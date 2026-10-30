package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"sort"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const (
	pruneFencePolicyCommand = "work-prune-fence-policy"
	pruneFenceScopeCommand  = "work-prune-fence-scope"
)

type pruneFencePolicyJSON struct {
	Owner      string   `json:"owner"`
	Controller string   `json:"controller"`
	Guard      string   `json:"guard,omitempty"`
	Threshold  uint8    `json:"threshold"`
	Witnesses  []string `json:"witnesses"`
}

func parsePruneFencePolicy(raw []byte) (prunefence.Policy, error) {
	var in pruneFencePolicyJSON
	var p prunefence.Policy
	if len(raw) > 8192 {
		return p, prunefence.ErrFence
	}
	if err := cutoverJSON(raw, &in); err != nil {
		return p, err
	}
	a, err := pruneExternalID("owner", in.Owner)
	if err != nil {
		return p, err
	}
	b, err := pruneExternalID("controller", in.Controller)
	if err != nil {
		return p, err
	}
	p.Owner = [32]byte(a)
	p.Controller = [32]byte(b)
	p.Threshold = in.Threshold
	if in.Guard != "" {
		g, err := pruneExternalID("guard", in.Guard)
		if err != nil {
			return p, err
		}
		p.Guard = [32]byte(g)
	}
	if len(in.Witnesses) > custodyfence.MaximumWitnesses {
		return p, prunefence.ErrFence
	}
	for _, text := range in.Witnesses {
		key, err := pruneExternalID("witness", text)
		if err != nil {
			return p, err
		}
		p.Witnesses = append(p.Witnesses, [32]byte(key))
	}
	sort.Slice(p.Witnesses, func(i, j int) bool { return bytes.Compare(p.Witnesses[i][:], p.Witnesses[j][:]) < 0 })
	_, err = p.CanonicalBytes()
	return p, err
}
func runPruneFenceArtifactCLI(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || out == nil || len(args) == 0 {
		return prunefence.ErrFence
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review or publish")
	input := f.String("input", "", "policy JSON or existing canonical plan")
	planID := f.String("plan-id", "", "scope: independently reviewed plan ID")
	expected := f.String("expected-id", "", "publish: reviewed artifact ID")
	destination := f.String("out", "", "publish: immutable public artifact")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if *mode != "review" && *mode != "publish" {
		return prunefence.ErrFence
	}
	if *mode == "review" && (*expected != "" || *destination != "") {
		return prunefence.ErrFence
	}
	var raw []byte
	var id types.Hash
	switch args[0] {
	case pruneFencePolicyCommand:
		if *planID != "" {
			return prunefence.ErrFence
		}
		b, err := readRegularArtifact(*input, 8192)
		if err != nil {
			return err
		}
		p, err := parsePruneFencePolicy(b)
		if err != nil {
			return err
		}
		raw, _ = p.CanonicalBytes()
		id, _ = p.ID()
	case pruneFenceScopeCommand:
		pin, err := pruneExternalID("plan-id", *planID)
		if err != nil {
			return err
		}
		p, err := store.LoadScheduledPrunePlan(*input, pin)
		if err != nil {
			return err
		}
		s, err := p.FenceScope()
		if err != nil {
			return err
		}
		raw, _ = s.CanonicalBytes()
		id, _ = s.ID()
	default:
		return prunefence.ErrFence
	}
	if *mode == "publish" {
		want, err := pruneExternalID("expected-id", *expected)
		if err != nil || want != id {
			return prunefence.ErrFence
		}
		if err := scheduledOperatorOutput(*destination, []string{*input}, nil); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publishCustodyCommandArtifact(*destination, raw); err != nil {
			return err
		}
	}
	return scheduledOperatorReport(ctx, out, struct {
		ArtifactID          string `json:"artifact_id"`
		ExecutionAuthorized bool   `json:"execution_authorized"`
	}{id.String(), false})
}

type pruneFenceNetworkJSON struct {
	ClientTransport string `json:"client_transport"`
	Witnesses       []struct {
		Witness   string `json:"witness"`
		Transport string `json:"transport"`
		Address   string `json:"address"`
	} `json:"witnesses"`
}

func openPruneFenceCollector(ctx context.Context, v store.ScheduledPruneInventory, path, ownerPath, transportPath string, timeout time.Duration) (store.PruneClaimCollector, func() error, error) {
	if v.FencePolicy == nil || path == "" || ownerPath == "" || transportPath == "" {
		return nil, nil, prunefence.ErrFence
	}
	raw, err := readRegularArtifact(path, 64<<10)
	if err != nil {
		return nil, nil, err
	}
	var config pruneFenceNetworkJSON
	if err := cutoverJSON(raw, &config); err != nil {
		return nil, nil, err
	}
	local, err := pruneExternalID("client_transport", config.ClientTransport)
	if err != nil {
		return nil, nil, err
	}
	var endpoints []prunenet.Endpoint
	if len(config.Witnesses) > custodyfence.MaximumWitnesses {
		return nil, nil, prunefence.ErrFence
	}
	for _, e := range config.Witnesses {
		w, err := pruneExternalID("witness", e.Witness)
		if err != nil {
			return nil, nil, err
		}
		p, err := pruneExternalID("transport", e.Transport)
		if err != nil {
			return nil, nil, err
		}
		endpoints = append(endpoints, prunenet.Endpoint{Witness: [32]byte(w), Transport: [32]byte(p), Address: e.Address})
	}
	rid, _ := v.Request.ID()
	scope, err := v.FencePolicy.Scope(v.Request.AssignmentID, rid)
	if err != nil {
		return nil, nil, err
	}
	if err := prunenet.Validate(scope, [32]byte(local), endpoints, timeout); err != nil {
		return nil, nil, err
	}
	owner, err := witnessKey(ownerPath, v.FencePolicy.Owner)
	if err != nil {
		return nil, nil, err
	}
	key, err := witnessKey(transportPath, [32]byte(local))
	if err != nil {
		clear(owner)
		return nil, nil, err
	}
	c := libp2ptransport.DefaultConfig()
	c.Listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1"}
	host, err := libp2ptransport.New(ctx, key, c, nil)
	clear(key)
	if err != nil {
		clear(owner)
		return nil, nil, err
	}
	closeClient := func() error { defer clear(owner); return host.Close() }
	collect := func(ctx context.Context, s custodyfence.Scope, d custodyfence.Command) (custodyfence.Certificate, error) {
		id, _ := s.ID()
		want, _ := scope.ID()
		if id != want {
			return custodyfence.Certificate{}, prunefence.ErrFence
		}
		return prunenet.Collect(ctx, host, owner, [32]byte(local), endpoints, timeout, s, d)
	}
	return collect, closeClient, nil
}
