package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard"
	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const custodyGuardCommand = "work-archive-custody-guard"

func runCustodyGuardCLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyGuard(ctx, args, os.Stdout)
}
func runCustodyGuard(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return wire.ErrGuard
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "", "create or serve")
	mode := f.String("mode", "review", "review or run")
	root := f.String("root", "", "independent original guard root")
	config := f.String("config", "", "create: sorted Subjects, lifetime Limit and optional separate Revoker public key JSON")
	identity := f.String("identity", "", "serve: independently retained Identity JSON")
	position := f.String("position", "", "serve: independently retained exact Position JSON")
	attempt := f.String("attempt", "", "serve: one exact signed lost-response request")
	revokeAttempt := f.String("revoke-attempt", "", "serve: one exact signed lost-response revocation")
	listen := f.String("listen", "", "serve: explicit IP:port on the guard network")
	output := f.String("out", "", "create: fresh public Identity artifact outside guard root")
	expected := f.String("expected-review-id", "", "exact public review")
	if e := parsePruneFlags(f, args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 || (*mode != "review" && *mode != "run") || (*action != "create" && *action != "serve") || *root == "" {
		return wire.ErrGuard
	}
	create := *action == "create"
	if (*config != "") != create || (*output != "") != create || (*identity != "") == create || (*position != "") == create || (*listen != "") == create || create && (*attempt != "" || *revokeAttempt != "") || *attempt != "" && *revokeAttempt != "" {
		return wire.ErrGuard
	}
	abs, e := filepath.Abs(*root)
	if e != nil {
		return e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(abs))
	if e != nil {
		return e
	}
	*root = filepath.Join(parent, filepath.Base(abs))
	if !create {
		host, _, err := net.SplitHostPort(*listen)
		if err != nil || net.ParseIP(host) == nil {
			return wire.ErrGuard
		}
	}
	inputs := map[string]string{}
	load := func(path *string, max int) ([]byte, error) {
		file, e := custodyCommandFile(*path)
		if e != nil {
			return nil, e
		}
		*path = file
		if e = witnessOutside(*root, file); e != nil {
			return nil, e
		}
		raw, e := readRegularArtifact(file, max)
		if e == nil {
			inputs[file] = cutoverArtifactID(raw).String()
		}
		return raw, e
	}
	var cfg guard.Config
	var id guard.Identity
	var pos guard.Position
	var q *wire.Request
	var revocation *wire.Revocation
	if create {
		b, e := load(config, guard.MaximumConfigBytes)
		if e != nil {
			return e
		}
		if e = cutoverJSON(b, &cfg); e != nil {
			return e
		}
		// Public validation before any directory/key creation.
		if e = guard.ValidateConfig(cfg); e != nil {
			return e
		}
		*output, e = custodyCommandOutput(*output)
		if e != nil {
			return e
		}
		if e = witnessOutside(*root, *output); e != nil {
			return e
		}
		if e = rejectPruneLineageOutputAlias(*output, []string{*config}); e != nil {
			return e
		}
	} else {
		b, e := load(identity, 2048)
		if e != nil {
			return e
		}
		if e = cutoverJSON(b, &id); e != nil {
			return e
		}
		b, e = load(position, 1024)
		if e != nil {
			return e
		}
		if e = cutoverJSON(b, &pos); e != nil {
			return e
		}
		if *attempt != "" {
			b, e = load(attempt, wire.RequestBytes)
			if e != nil {
				return e
			}
			v, e := wire.DecodeRequest(b)
			if e != nil {
				return e
			}
			q = &v
		}
		if *revokeAttempt != "" {
			b, e = load(revokeAttempt, wire.RevocationBytes)
			if e != nil {
				return e
			}
			v, e := wire.DecodeRevocation(b)
			if e != nil || v.GuardID != id.ID() {
				return wire.ErrGuard
			}
			revocation = &v
		}

	}
	public, e := json.Marshal(struct {
		Action, Root, Listen, Output string
		Inputs                       map[string]string
		Config                       guard.Config
		Identity                     guard.Identity
		Position                     guard.Position
		Attempt                      *wire.Request
		Revocation                   *wire.Revocation `json:",omitzero"`
	}{*action, *root, *listen, *output, inputs, cfg, id, pos, q, revocation})
	if e != nil {
		return e
	}
	review := types.DomainHash(wire.Domain+"cli/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_guard_review review_id=%s roots_opened=false keys_loaded=false\n%s\n", review, public))
	}
	want, e := witnessID("expected-review-id", *expected)
	if e != nil || want != review {
		return errors.New("guard action requires its exact public review")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if create {
		if _, e = os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
			return wire.ErrGuard
		}
		s, e := guard.Create(*root, cfg)
		if e != nil {
			return e
		}
		defer s.Close()
		b, _ := json.Marshal(s.Identity())
		if e = publishCustodyCommandArtifact(*output, b); e != nil {
			return e
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_guard_created public_key=%x position_sequence=0\n", s.Identity().PublicKey))
	}
	var s *guard.Store
	if revocation != nil {
		s, e = guard.RecoverRevocation(*root, id, pos, *revocation)
	} else {
		s, e = guard.Open(*root, id, pos, q)
	}
	if e != nil {
		return e
	}
	defer s.Close()
	s.SetObserver(func(p guard.Position, q wire.Request) error {
		raw, e := json.Marshal(struct {
			Position guard.Position
			Request  wire.Request
		}{p, q})
		if e != nil {
			return e
		}
		return writePruneOutputLine(out, string(raw)+"\n")
	})
	s.SetRevocationObserver(func(p guard.Position, q wire.Revocation) error {
		raw, err := json.Marshal(struct {
			Position   guard.Position
			Revocation wire.Revocation
		}{p, q})
		if err != nil {
			return err
		}
		return writePruneOutputLine(out, string(raw)+"\n")
	})
	l, e := net.Listen("tcp", *listen)
	if e != nil {
		return e
	}
	defer l.Close()
	p, _ := s.Position()
	if e = writePruneOutputLine(out, fmt.Sprintf("custody_guard_ready address=%s sequence=%d head=%s\n", l.Addr(), p.Sequence, p.Head)); e != nil {
		return e
	}
	return guard.Serve(ctx, l, s)
}
