//go:build linux || darwin

package main

import (
	"context"
	"crypto/ed25519"
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

const custodyGuardReplaceCommand = "work-archive-custody-guard-replace"

func runCustodyGuardReplaceCLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyGuardReplace(ctx, args, os.Stdout)
}

func runCustodyGuardReplace(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return wire.ErrGuard
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "", "propose, authorize, send or inspect")
	mode := f.String("mode", "review", "review or run")
	identity := f.String("identity", "", "independently retained guard Identity JSON")
	config := f.String("config", "", "immutable Config with explicit Replacer")
	revocation := f.String("revocation", "", "propose: permanent revocation receipt")
	position := f.String("position", "", "propose: independently retained exact current guard Position")
	successor := f.String("successor", "", "propose: fresh successor public key, hexadecimal")
	evidence := f.String("evidence-id", "", "propose: nonzero recovery inventory commitment")
	proposal := f.String("proposal", "", "authorize: exact successor-signed proposal")
	request := f.String("request", "", "send/inspect: fully authorized replacement")
	receipt := f.String("receipt", "", "inspect: guard replacement receipt")
	key := f.String("key", "", "propose/authorize: private 32-byte seed; review never reads it")
	url := f.String("guard-url", "", "send: guard base URL")
	output := f.String("out", "", "fresh public output")
	expected := f.String("expected-review-id", "", "exact public review ID")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	p, a, s, i := *action == "propose", *action == "authorize", *action == "send", *action == "inspect"
	if f.NArg() != 0 || *mode != "review" && *mode != "run" || !p && !a && !s && !i {
		return wire.ErrGuard
	}
	for _, v := range []struct {
		value    string
		required bool
	}{{*revocation, p}, {*position, p}, {*successor, p}, {*evidence, p}, {*proposal, a}, {*request, s || i}, {*receipt, i}, {*key, p || a}, {*url, s}} {
		if (v.value != "") != v.required {
			return wire.ErrGuard
		}
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
	if guard.ValidateIdentity(cfg, id) != nil || cfg.Replacer == ([32]byte{}) {
		return wire.ErrGuard
	}
	var q wire.Replacement
	var r wire.ReplacementReceipt
	if p {
		b, err = load(revocation, wire.RevocationReceiptBytes)
		if err != nil {
			return err
		}
		rev, err := wire.DecodeRevocationReceipt(b)
		if err != nil || rev.Verify(id.PublicKey, id.ID(), rev.Request) != nil || guard.ValidateRevocation(cfg, id, rev.Request) != nil {
			return wire.ErrGuard
		}
		b, err = load(position, 1024)
		if err != nil {
			return err
		}
		if err = cutoverJSON(b, &q.Before); err != nil {
			return err
		}
		after, err := rev.After()
		if err != nil || q.Before.Sequence < after.Sequence || q.Before.Sequence == after.Sequence && q.Before != after {
			return wire.ErrGuard
		}
		sub, err := witnessID("successor", *successor)
		if err != nil {
			return err
		}
		eid, err := witnessID("evidence-id", *evidence)
		if err != nil {
			return err
		}
		q.GuardID = id.ID()
		q.Subject = rev.Request.Subject
		q.Successor = [32]byte(sub)
		q.Authority = cfg.Replacer
		q.EvidenceID = eid
		q.RevocationID, err = rev.Request.ID()
		if err != nil {
			return err
		}
	} else if a {
		b, err = load(proposal, wire.ReplacementBytes)
		if err != nil {
			return err
		}
		q, err = wire.DecodeReplacementProposal(b)
		if err != nil {
			return err
		}
	} else {
		b, err = load(request, wire.ReplacementBytes)
		if err != nil {
			return err
		}
		q, err = wire.DecodeReplacement(b)
		if err != nil {
			return err
		}
	}
	if guard.ValidateReplacementDraft(cfg, id, q) != nil {
		return wire.ErrGuard
	}
	if i {
		b, err = load(receipt, wire.ReplacementReceiptBytes)
		if err != nil {
			return err
		}
		r, err = wire.DecodeReplacementReceipt(b)
		if err != nil || r.Verify(id.PublicKey, id.ID(), q) != nil {
			return wire.ErrGuard
		}
	}
	if s && guard.ValidateURL(*url) != nil {
		return wire.ErrGuard
	}
	if p || a {
		*key, err = custodyCommandOutput(*key)
		if err != nil {
			return err
		}
		paths = append(paths, *key)
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
		Request                  wire.Replacement
	}{*action, *url, *output, *key, inputs, id, cfg, q})
	if err != nil {
		return err
	}
	review := types.DomainHash(wire.Domain+"cli/replace/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_guard_replacement_review review_id=%s roots_opened=false keys_loaded=false network_called=false\n%s\n", review, public))
	}
	want, err := witnessID("expected-review-id", *expected)
	if err != nil || want != review {
		return errors.New("replacement requires its exact public review")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		return wire.ErrGuard
	}
	switch {
	case p || a:
		pub := q.Successor
		if a {
			pub = q.Authority
		}
		var private ed25519.PrivateKey
		private, err = witnessKey(*key, pub)
		if err != nil {
			return err
		}
		defer clear(private)
		if p {
			q, err = q.Accept(private)
		} else {
			q, err = q.Authorize(private)
		}
		if err != nil {
			return err
		}
		if p {
			b, err = q.ProposalBytes()
		} else {
			b, err = q.CanonicalBytes()
		}
	case s:
		r, err = wire.ObtainReplacement(ctx, guard.Client{URL: *url}, id.PublicKey, id.ID(), q)
		if err != nil {
			return err
		}
		b, err = r.CanonicalBytes()
	case i:
		after, e := r.After()
		if e != nil {
			return e
		}
		b, err = json.Marshal(struct {
			GuardID                                  types.Hash
			Subject, Successor                       [32]byte
			EvidenceID                               types.Hash
			Before, After                            guard.Position
			HistoricalOnly, OriginalIdentityRetained bool
		}{q.GuardID, q.Subject, q.Successor, q.EvidenceID, q.Before, after, true, true})
	}
	if err != nil {
		return err
	}
	if err = publishCustodyCommandArtifact(*output, b); err != nil {
		return err
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_guard_replacement action=%s subject=%x successor=%x artifact_id=%s\n", *action, q.Subject, q.Successor, cutoverArtifactID(b)))
}
