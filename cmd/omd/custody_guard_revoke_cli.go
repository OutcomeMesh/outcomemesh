//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const custodyGuardRevokeCommand = "work-archive-custody-guard-revoke"

func runCustodyGuardRevokeCLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyGuardRevoke(ctx, args, os.Stdout)
}

func runCustodyGuardRevoke(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return wire.ErrGuard
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "", "sign, send or inspect permanent subject revocation")
	mode := f.String("mode", "review", "review or run")
	identity := f.String("identity", "", "independently retained public Identity JSON")
	config := f.String("config", "", "immutable public Config JSON with separate Revoker")
	subject := f.String("subject", "", "sign: revoked subject public key, hex")
	reason := f.String("reason-id", "", "sign: nonzero incident evidence ID")
	key := f.String("key", "", "sign: private offline revocation seed (32 raw bytes), unused by review")
	request := f.String("request", "", "send/inspect: exact signed revocation artifact")
	replacement := f.String("replacement", "", "public replacement receipt when revoking a successor")
	receipt := f.String("receipt", "", "inspect: signed guard receipt")
	url := f.String("guard-url", "", "send: guard base URL")
	output := f.String("out", "", "fresh request, receipt or inspection artifact")
	expected := f.String("expected-review-id", "", "exact public review")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || (*mode != "review" && *mode != "run") {
		return wire.ErrGuard
	}
	sign, send, inspect := *action == "sign", *action == "send", *action == "inspect"
	if !sign && !send && !inspect || (*subject != "") != sign || (*reason != "") != sign || (*key != "") != sign || (*request != "") == sign || (*receipt != "") != inspect || (*url != "") != send {
		return wire.ErrGuard
	}
	inputs := map[string]string{}
	var paths []string
	load := func(path *string, limit int) ([]byte, error) {
		var err error
		*path, err = custodyCommandFile(*path)
		if err != nil {
			return nil, err
		}
		b, err := readRegularArtifact(*path, limit)
		if err == nil {
			inputs[*path] = cutoverArtifactID(b).String()
			paths = append(paths, *path)
		}
		return b, err
	}
	var id guard.Identity
	var cfg guard.Config
	b, err := load(identity, 2048)
	if err != nil {
		return err
	}
	if err = cutoverJSON(b, &id); err != nil {
		return err
	}
	b, err = load(config, guard.MaximumConfigBytes)
	if err != nil {
		return err
	}
	if err = cutoverJSON(b, &cfg); err != nil {
		return err
	}
	if guard.ValidateIdentity(cfg, id) != nil || types.Hash(cfg.Revoker).IsZero() {
		return wire.ErrGuard
	}
	var successor *wire.ReplacementReceipt
	if *replacement != "" {
		b, err = load(replacement, wire.ReplacementReceiptBytes)
		if err != nil {
			return err
		}
		r, err := wire.DecodeReplacementReceipt(b)
		if err != nil || guard.ValidateReplacementDraft(cfg, id, r.Request) != nil || r.Verify(id.PublicKey, id.ID(), r.Request) != nil {
			return wire.ErrGuard
		}
		successor = &r
	}
	var q wire.Revocation
	var r wire.RevocationReceipt
	if sign {
		sub, err := witnessID("subject", *subject)
		if err != nil {
			return err
		}
		reasonID, err := witnessID("reason-id", *reason)
		if err != nil {
			return err
		}
		found := false
		for _, k := range cfg.Subjects {
			if k == [32]byte(sub) {
				found = true
			}
		}
		if successor != nil {
			found = successor.Request.Successor == [32]byte(sub)
		}
		if !found {
			return wire.ErrGuard
		}
		q = wire.Revocation{GuardID: id.ID(), Subject: [32]byte(sub), Authority: cfg.Revoker, ReasonID: reasonID}
		// Canonicalize only the placement; review never reads the private seed.
		*key, err = custodyCommandOutput(*key)
		if err != nil {
			return err
		}
		paths = append(paths, *key)
	} else {
		b, err = load(request, wire.RevocationBytes)
		if err != nil {
			return err
		}
		q, err = wire.DecodeRevocation(b)
		valid := guard.ValidateRevocation(cfg, id, q)
		if successor != nil {
			valid = guard.ValidateSuccessorRevocation(cfg, id, q, *successor)
		}
		if err != nil || valid != nil {
			return wire.ErrGuard
		}
	}
	if send && guard.ValidateURL(*url) != nil {
		return wire.ErrGuard
	}
	if inspect {
		b, err = load(receipt, wire.RevocationReceiptBytes)
		if err != nil {
			return err
		}
		r, err = wire.DecodeRevocationReceipt(b)
		if err != nil || r.Verify(id.PublicKey, id.ID(), q) != nil {
			return wire.ErrGuard
		}
	}
	*output, err = custodyCommandOutput(*output)
	if err != nil {
		return err
	}
	if err = rejectPruneLineageOutputAlias(*output, paths); err != nil {
		return err
	}
	public, err := json.Marshal(struct {
		Action, URL, Output, Key string
		Inputs                   map[string]string
		Identity                 guard.Identity
		Config                   guard.Config
		Request                  wire.Revocation
		Replacement              *wire.ReplacementReceipt `json:",omitzero"`
	}{*action, *url, *output, *key, inputs, id, cfg, q, successor})
	if err != nil {
		return err
	}
	review := types.DomainHash(wire.Domain+"cli/revoke/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_guard_revocation_review review_id=%s roots_opened=false keys_loaded=false network_called=false permanent=true\n%s\n", review, public))
	}
	want, err := witnessID("expected-review-id", *expected)
	if err != nil || want != review {
		return errors.New("revocation requires its exact public review")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		return wire.ErrGuard
	}
	switch {
	case sign:
		private, err := witnessKey(*key, cfg.Revoker)
		if err != nil {
			return err
		}
		defer clear(private)
		q, err = q.Sign(private)
		if err != nil {
			return err
		}
		b, err = q.CanonicalBytes()
		if err != nil {
			return err
		}
	case send:
		r, err = wire.ObtainRevocation(ctx, guard.Client{URL: *url}, id.PublicKey, id.ID(), q)
		if err != nil {
			return err
		}
		b, err = r.CanonicalBytes()
		if err != nil {
			return err
		}
	case inspect:
		after, err := r.After()
		if err != nil {
			return err
		}
		b, err = json.Marshal(struct {
			GuardID                   types.Hash
			Subject, Authority        [32]byte
			ReasonID                  types.Hash
			Before, After             guard.Position
			HistoricalOnly, Permanent bool
		}{q.GuardID, q.Subject, q.Authority, q.ReasonID, r.Before, after, true, true})
		if err != nil {
			return err
		}
	}
	if err = publishCustodyCommandArtifact(*output, b); err != nil {
		return err
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_guard_revocation action=%s subject=%x artifact_id=%s\n", *action, q.Subject, cutoverArtifactID(b)))
}
