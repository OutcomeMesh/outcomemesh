//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	source "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	fence "github.com/outcomemesh/outcomemesh/node/custodyfence"
	gw "github.com/outcomemesh/outcomemesh/node/custodygateway"
	relay "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayrelay"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// Explicit acceptance-only driver. Public test keys are never deployment keys.
// Each invocation operates one local original root; only public files travel.
type profile5WANStep struct {
	Step, Role, Root, Fixture, Name, Input, Output, Family string
	Kind                                                   uint8
	Seed                                                   byte
	Votes                                                  []string
}

func TestProfile5WANStep(t *testing.T) {
	path := os.Getenv("OMESH_PROFILE5_WAN_STEP")
	if path == "" {
		t.Skip("explicit task-private distributed acceptance step")
	}
	raw, e := os.ReadFile(path)
	source.Require(t, e)
	var s profile5WANStep
	source.Require(t, cutoverJSON(raw, &s))
	profile5WANRun(t, s)
}
func profile5WANRun(t testing.TB, s profile5WANStep) {
	t.Helper()
	must := func(e error) { t.Helper(); source.Require(t, e) }
	if !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root || s.Role != "a" && s.Role != "b" {
		t.Fatal("invalid WAN placement")
	}
	pub := filepath.Join(s.Root, "public")
	private := filepath.Join(s.Root, "private")
	p := func(name string) string {
		if name == "" || filepath.Base(name) != name {
			t.Fatal("public filename", name)
		}
		return filepath.Join(pub, name)
	}
	read := func(name string) []byte { b, e := os.ReadFile(p(name)); must(e); return b }
	write := func(name string, b []byte) {
		f, e := os.OpenFile(p(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		must(e)
		_, e = f.Write(b)
		must(e)
		must(f.Sync())
		must(f.Close())
	}
	jout := func(name string, v any) {
		b, e := json.MarshalIndent(v, "", "  ")
		must(e)
		write(name, append(b, '\n'))
	}
	jin := func(name string, v any) { must(cutoverJSON(read(name), v)) }
	canonical := func(name string, v interface{ CanonicalBytes() ([]byte, error) }) {
		b, e := v.CanonicalBytes()
		must(e)
		write(name, b)
	}
	var d source.DistributedDraft
	if s.Step != "seed" {
		jin("draft.json", &d)
	}
	local := d.A
	if s.Role == "b" {
		local = d.B
	}
	load := func() (v2.AdmissionGenesis, v2.EnrollmentBinding) {
		g, e := v2.DecodeAdmissionGenesis(read("genesis"))
		must(e)
		b, e := v2.DecodeEnrollmentBinding(read("enrollment"))
		must(e)
		return g, b
	}
	descriptor := func(role string) wire.Descriptor {
		x, e := wire.DecodeDescriptor(read(role + ".descriptor"))
		must(e)
		return x
	}
	context := func() v2.Context { x, e := v2.DecodeContext(read("context")); must(e); return x }
	binding := func() v2.AdmissionBinding { x, e := v2.DecodeAdmissionBinding(read("binding")); must(e); return x }
	position := func(role string) wire.Position { var x wire.Position; jin(role+".position.json", &x); return x }
	savePosition := func(role string, x wire.Position) {
		b, e := json.Marshal(x)
		must(e)
		must(os.WriteFile(p(role+".position.json"), b, 0644))
	}
	request := func(role, name string, cmd v2.ProtectedCommand) {
		desc := descriptor(role)
		id, _ := desc.ID()
		payload, e := cmd.CanonicalBytes()
		must(e)
		q, e := (wire.Request{DescriptorID: id, Before: position(role), Nonce: f.Hash(s.Root + name), Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(payload)}).Sign(f.Key(14))
		must(e)
		raw, e := wire.EncodeRuntimeRequest(q, payload)
		must(e)
		write(name+".request", raw)
	}
	pins := func(g v2.AdmissionGenesis, b v2.EnrollmentBinding) cut.SourceHandoffPins {
		gid, _ := g.ID()
		did, _ := g.DescriptorID()
		bid, _ := b.ID()
		pl, _ := local.LocationID()
		return cut.SourceHandoffPins{GenesisID: gid, GenesisDescriptorID: did, EnrollmentID: bid, PlacementID: pl}
	}
	switch s.Step {
	case "seed":
		jout("draft.json", source.DistributedSeed(t, private, s.Fixture))
	case "source":
		jout(s.Role+".observation.json", source.DistributedSource(t, d, s.Role, filepath.Join(private, "objects"), s.Fixture))
	case "select":
		var a, b cut.Observation
		jin("a.observation.json", &a)
		jin("b.observation.json", &b)
		g, en := source.DistributedSelection(t, d, a, b)
		canonical("genesis", g)
		canonical("enrollment", en)
	case "install":
		g, b := load()
		pin := pins(g, b)
		h, _, e := cut.TransferSourceHandoff(t.Context(), g, b, pin, local)
		must(e)
		canonical(s.Role+".handoff", h)
		owner := filepath.Join(private, "gateway")
		_, e = gw.CreateIdentity(owner)
		must(e)
		gr, _ := g.CanonicalBytes()
		br, _ := b.CanonicalBytes()
		config := gw.Config{Genesis: gr, Enrollment: br, Pins: pin, Source: local}
		if s.Role == "b" {
			config.Objects = filepath.Join(private, "objects")
		}
		desc, e := gw.DraftDescriptor(owner, config, 65534, [][32]byte{f.Public(14)}, 32)
		must(e)
		desc, e = desc.Sign(f.Key(110))
		must(e)
		config.Descriptor, e = desc.CanonicalBytes()
		must(e)
		must(gw.Configure(t.Context(), owner, config))
		canonical(s.Role+".descriptor", desc)
		id, _ := desc.ID()
		jout(s.Role+".meta.json", map[string]any{"descriptor_id": id.String(), "owner": owner})
		jout(s.Role+".position.json", wire.Position{})
	case "deployment":
		a, e := workarchive.DecodeCustodySourceHandoff(read("a.handoff"))
		must(e)
		b, e := workarchive.DecodeCustodySourceHandoff(read("b.handoff"))
		must(e)
		pair := cut.SourceHandoffPair{A: a, B: b}
		canonical("pair", pair)
		pb, _ := pair.CanonicalBytes()
		dep, e := gw.PrepareDeployment(gw.DeploymentPreparation{Genesis: read("genesis"), Enrollment: read("enrollment"), Pair: pb, A: read("a.descriptor"), B: read("b.descriptor")})
		must(e)
		for _, r := range []struct {
			role string
			seed byte
		}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
			dep, e = dep.Sign(r.role, f.Key(r.seed))
			must(e)
		}
		canonical("deployment-draft", dep)
	case "endorse":
		desc := descriptor(s.Role)
		id, _ := desc.ID()
		o, e := gw.Open(filepath.Join(private, "gateway"), id, position(s.Role), nil)
		must(e)
		defer o.Close()
		dep, e := wire.DecodeDeployment(read(s.Input))
		must(e)
		pair, e := cut.DecodeSourceHandoffPair(read("pair"))
		must(e)
		data, e := gw.EncodeEndorsement(dep, pair)
		must(e)
		cmd := v2.ProtectedCommand{Kind: v2.ProtectedEndorse, Data: data, Now: uint64(time.Now().Unix())}
		payload, e := cmd.CanonicalBytes()
		must(e)
		q, e := (wire.Request{DescriptorID: id, Before: position(s.Role), Nonce: f.Hash(s.Role + "endorse"), Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(payload)}).Sign(f.Key(14))
		must(e)
		raw, e := o.ExecuteRuntime(t.Context(), q, payload)
		must(e)
		r, e := wire.DecodeResponse(raw)
		must(e)
		must(r.Verify(desc, q))
		write(s.Output, r.Data)
		pos, _ := r.Position()
		savePosition(s.Role, pos)
	case "configure":
		cfg := gw.ExecutionConfig{Deployment: read("deployment"), Pair: read("pair")}
		setup := gw.ExecutionSetup{ExecutionConfig: cfg}
		roles := map[string]byte{"authority": 101}
		if s.Role == "b" {
			roles = map[string]byte{"replica": 61, "control": 102}
		}
		for role, seed := range roles {
			path := filepath.Join(private, role+".seed")
			must(os.WriteFile(path, []byte(hex.EncodeToString(f.Key(seed).Seed())), 0600))
			switch role {
			case "authority":
				setup.AuthorityKeyPath = path
			case "replica":
				setup.ReplicaKeyPath = path
			case "control":
				setup.ControlKeyPath = path
			}
		}
		raw, e := json.Marshal(setup)
		must(e)
		must(os.WriteFile(filepath.Join(private, "setup.json"), raw, 0600))
		// Same reviewed CLI used by operators. The helper retains only its output.
		args := []string{custodyProfile5Command, "--action", "configure", "--root", filepath.Join(private, "gateway"), "--input", filepath.Join(private, "setup.json"), "--out", p(s.Role + ".configured")}
		profile5CLIAction(t, args)
	case "plan":
		g, _ := load()
		dep, e := wire.DecodeDeployment(read("deployment"))
		must(e)
		must(dep.Verify())
		aid, _ := g.Assignment.ID()
		rid, _ := g.Initial.ID()
		peer, e := transport.PeerIDFromPublicKey(g.Assignment.Base.RemoteTransportPublicKey[:])
		must(e)
		ch, e := workarchive.CreateCustodyChallenge(g.Manifest, g.Initial, f.Key(3), uint64(time.Now().Unix()), g.CustodyPolicy.MaximumChallengeLifetime, 1, g.Initial.RetainUntil+1)
		must(e)
		c := v2.Context{Assignment: g.Assignment, Manifest: g.Manifest, Initial: g.Initial, Previous: g.Initial, CustodyPolicy: g.CustodyPolicy}
		c.Plan = v2.Plan{Version: 5, AssignmentID: aid, Deployment: &dep, ServeConsumer: f.Public(4), ClientTransportPublicKey: f.Public(46), Challenge: ch, Intent: workarchive.CustodyAuditIntent{AssignmentID: aid, ConsumerPublicKey: f.Public(4), AuditorPublicKey: f.Public(3), ReplicaPeerID: peer, PriorReceiptID: rid, Nonce: ch.Nonce, IssuedAt: ch.IssuedAt, ExpiresAt: ch.ExpiresAt, RenewUntil: ch.RenewUntil, RequestedSamples: ch.RequestedSamples}}
		for _, r := range []struct {
			role string
			seed byte
		}{{"audit", 4}, {"serve", 4}, {"authority", 101}} {
			c.Plan, e = c.Plan.Sign(r.role, f.Key(r.seed))
			must(e)
		}
		must(c.Validate())
		canonical("context", c)
		gid, _ := g.ID()
		entry, e := (v2.AdmissionEntry{Version: 2, GenesisID: gid, ExpectedHead: gid, Kind: v2.AdmissionAdmit, Context: c}).Sign(g, f.Key(101))
		must(e)
		canonical("admit-entry", entry)
	case "witness-init", "witness-vote", "witness-commit", "witness-snapshot":
		if s.Seed < 70 || s.Seed > 73 || s.Role == "a" && s.Seed > 71 || s.Role == "b" && s.Seed < 72 {
			t.Fatal("wrong witness domain")
		}
		if s.Family != "admission" && s.Family != "job" && s.Family != "serve" {
			t.Fatal("witness family")
		}
		name := fmt.Sprintf("%s-%d", s.Family, s.Seed)
		root := filepath.Join(private, name)
		pinPath := filepath.Join(private, name+".pin")
		var pin fence.WitnessPin
		if s.Step != "witness-init" {
			b, e := os.ReadFile(pinPath)
			must(e)
			must(json.Unmarshal(b, &pin))
		}
		if s.Family == "admission" {
			g, b := load()
			gid, _ := g.ID()
			var w *v2.AdmissionWitness
			var e error
			if s.Step == "witness-init" {
				w, e = v2.CreateAdmissionWitness(root, g, gid, f.Key(s.Seed), b)
			} else {
				w, e = v2.OpenAdmissionWitness(root, g, gid, f.Key(s.Seed), pin, b)
			}
			must(e)
			defer w.Close()
			if s.Step == "witness-vote" {
				entry, e := v2.DecodeAdmissionEntry(read(s.Input))
				must(e)
				vote, e := w.VoteAt(pin, entry)
				must(e)
				canonical(s.Output, vote)
			}
			if s.Step == "witness-commit" {
				cert, e := v2.DecodeAdmissionCertificate(read(s.Input))
				must(e)
				must(w.CommitAt(pin, cert))
			}
			snap, next, e := w.Snapshot()
			must(e)
			pin = next
			if s.Step == "witness-snapshot" {
				jout(s.Output, snap)
			}
		} else {
			c := context()
			scope, e := c.Scope()
			if s.Family == "serve" {
				scope, e = c.ServeScope()
			}
			must(e)
			sid, _ := scope.ID()
			var w *fence.Witness
			if s.Step == "witness-init" {
				w, e = fence.Create(root, scope, sid, f.Key(s.Seed))
			} else {
				w, e = fence.Open(root, scope, sid, f.Key(s.Seed), pin)
			}
			must(e)
			defer w.Close()
			if s.Step == "witness-vote" {
				cmd, e := fence.DecodeCommand(read(s.Input))
				must(e)
				vote, e := w.Vote(cmd)
				must(e)
				canonical(s.Output, vote)
			}
			if s.Step == "witness-commit" {
				cert, e := fence.DecodeCertificate(read(s.Input))
				must(e)
				must(w.Commit(cert))
			}
			snap, next, e := w.Snapshot()
			must(e)
			pin = next
			if s.Step == "witness-snapshot" {
				jout(s.Output, snap)
			}
		}
		raw, e := json.Marshal(pin)
		must(e)
		must(os.WriteFile(pinPath, raw, 0600))
	case "quorum":
		if s.Family == "admission" {
			g, _ := load()
			entry, e := v2.DecodeAdmissionEntry(read(s.Input))
			must(e)
			q := v2.AdmissionCertificate{Version: 2, Entry: entry}
			for _, name := range s.Votes {
				v, e := v2.DecodeAdmissionVote(read(name))
				must(e)
				q.Votes = append(q.Votes, v)
			}
			sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
			must(q.Verify(g))
			canonical(s.Output, q)
			if entry.Kind == v2.AdmissionAdmit {
				canonical("binding", v2.AdmissionBinding{Version: 2, Genesis: g, Chain: []v2.AdmissionCertificate{q}})
			}
		} else {
			cmd, e := fence.DecodeCommand(read(s.Input))
			must(e)
			q := fence.Certificate{Version: cmd.Version, Command: cmd}
			for _, name := range s.Votes {
				v, e := fence.DecodeVote(read(name))
				must(e)
				q.Votes = append(q.Votes, v)
			}
			sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
			c := context()
			scope, e := c.Scope()
			if s.Family == "serve" {
				scope, e = c.ServeScope()
			}
			must(e)
			must(q.Verify(scope))
			canonical(s.Output, q)
		}
	case "request":
		cmd := v2.ProtectedCommand{Kind: s.Kind, Admission: binding(), Now: 1}
		if s.Input != "" {
			cmd.Data = read(s.Input)
		}
		request(s.Role, s.Name, cmd)
	case "advance":
		raw := read(s.Input)
		q, _, e := wire.DecodeRuntimeRequest(read(s.Name + ".request"))
		must(e)
		r, e := wire.DecodeResponse(raw)
		must(e)
		must(r.Verify(descriptor(s.Role), q))
		if position(s.Role) != q.Before {
			t.Fatal("controller cursor changed")
		}
		next, e := r.Position()
		must(e)
		savePosition(s.Role, next)
		write(s.Name+".data", r.Data)
	case "claim":
		candidate, e := v2.DecodeCandidate(read(s.Input))
		must(e)
		must(candidate.Verify(context()))
		canonical("claim-command", candidate.Claim)
	case "prefix":
		q, e := fence.DecodeCertificate(read("claim"))
		must(e)
		chain := []fence.Certificate{q}
		if s.Input != "" {
			u, e := fence.DecodeCertificate(read(s.Input))
			must(e)
			chain = append(chain, u)
		}
		raw, e := v2.EncodeProtectedPrefix(chain)
		must(e)
		write("prefix", raw)
	case "bundle":
		result, e := v2.DecodeResult(read("execute.data"))
		must(e)
		claim, e := fence.DecodeCertificate(read("claim"))
		must(e)
		record, e := fence.DecodeCertificate(read("record"))
		must(e)
		chain := []fence.Certificate{claim}
		if s.Input != "" {
			u, e := fence.DecodeCertificate(read(s.Input))
			must(e)
			chain = append(chain, u)
		}
		chain = append(chain, record)
		bundle := v2.Bundle{Version: 2, Result: result, Chain: chain}
		must(bundle.Verify(context()))
		canonical("bundle", bundle)
	case "serve-proposal":
		c := context()
		bundle, e := v2.DecodeBundle(read("bundle"))
		must(e)
		ack, e := v2.DecodeReceipt(read("accept.data"))
		must(e)
		must(ack.Verify(c, bundle))
		proposal, e := v2.NewServeFulfilled(c, bundle, ack)
		must(e)
		for _, r := range []struct {
			role string
			seed byte
		}{{"authority", 101}, {"consumer", 4}} {
			proposal, e = proposal.Sign(c, r.role, f.Key(r.seed))
			must(e)
		}
		canonical("serve-proposal", proposal)
		cmd, e := proposal.Decision(c, f.Key(101))
		must(e)
		canonical("serve-command", cmd)
	case "serve-data":
		proposal, e := v2.DecodeServeProposal(read("serve-proposal"))
		must(e)
		q, e := fence.DecodeCertificate(read("serve-quorum"))
		must(e)
		cert := v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: q}
		must(cert.Verify(context()))
		var parent *v2.ServeReceipt
		if s.Role == "b" {
			a, e := v2.DecodeServeReceipt(read("serve-a.data"))
			must(e)
			parent = &a
		}
		data, e := gw.EncodeExecutionServe(cert, parent)
		must(e)
		write(s.Output, data)
	case "closure":
		proposal, e := v2.DecodeServeProposal(read("serve-proposal"))
		must(e)
		q, e := fence.DecodeCertificate(read("serve-quorum"))
		must(e)
		a, e := v2.DecodeServeReceipt(read("serve-a.data"))
		must(e)
		b, e := v2.DecodeServeReceipt(read("serve-b.data"))
		must(e)
		closure := v2.AdmissionClosure{Serve: v2.ServeCertificate{Version: 2, Proposal: proposal, Decision: q}, A: a, B: b}
		must(closure.Verify(context()))
		canonical("closure", closure)
		binding := binding()
		gid, _ := binding.Genesis.ID()
		state, e := v2.NewAdmissionState(binding.Genesis, gid)
		must(e)
		for _, q := range binding.Chain {
			must(state.Apply(q))
		}
		snap := state.Snapshot()
		entry, e := (v2.AdmissionEntry{Version: 2, GenesisID: gid, ExpectedSequence: snap.Position.Sequence, ExpectedHead: snap.Position.HeadID, Kind: v2.AdmissionClose, Context: context(), Closure: &closure}).Sign(binding.Genesis, f.Key(101))
		must(e)
		canonical("close-entry", entry)
	case "unknown":
		c := context()
		scope, e := c.Scope()
		must(e)
		sid, _ := scope.ID()
		q, e := fence.DecodeCertificate(read("claim"))
		must(e)
		cid, _ := q.Command.ID()
		cmd, e := (fence.Command{Version: 1, ScopeID: sid, ExpectedSequence: 1, ExpectedHead: cid, Kind: fence.MarkUnknown, ClaimID: cid, EvidenceID: f.Hash(s.Root + "lost-reply")}).Sign(f.Key(101))
		must(e)
		canonical("unknown-command", cmd)
	case "verify-source":
		g, b := load()
		h, e := cut.InspectSourceHandoff(t.Context(), g, b, pins(g, b), local)
		must(e)
		canonical(s.Output, h)
	default:
		t.Fatal("unknown WAN step", s.Step)
	}
}

// A separate process establishes authenticated QUIC before the controller drops
// packets. The barrier never changes production code or edits private service
// state. Only the exact request crosses the already pinned stream afterwards.
func TestProfile5WANBarrierClient(t *testing.T) {
	path := os.Getenv("OMESH_PROFILE5_WAN_CLIENT")
	if path == "" {
		t.Skip("explicit WAN packet-fault client")
	}
	var cfg struct{ Descriptor, Request, Address, Peer, Listen, Ready, Send, Output string }
	raw, e := os.ReadFile(path)
	source.Require(t, e)
	source.Require(t, cutoverJSON(raw, &cfg))
	dRaw, e := os.ReadFile(cfg.Descriptor)
	source.Require(t, e)
	d, e := wire.DecodeDescriptor(dRaw)
	source.Require(t, e)
	attempt, e := os.ReadFile(cfg.Request)
	source.Require(t, e)
	peer, e := witnessID("peer", cfg.Peer)
	source.Require(t, e)
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{cfg.Listen}
	h, e := libp2ptransport.New(t.Context(), f.Key(46), config, nil)
	source.Require(t, e)
	defer h.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	st, _, e := h.OpenCustodyGatewayStream(ctx, cfg.Address, peer)
	source.Require(t, e)
	defer st.Close()
	source.Require(t, os.WriteFile(cfg.Ready, []byte("authenticated\n"), 0644))
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, e = os.Stat(cfg.Send); e == nil {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("missing send barrier")
		}
	}
	r, e := relay.Exchange(ctx, st, d, attempt, 10*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = r.CanonicalBytes()
	source.Require(t, e)
	source.Require(t, os.WriteFile(cfg.Output, raw, 0644))
}

func TestProtected5DistributedSetupCreatesOnlySelectedOriginal(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	source.Require(t, e)
	source.Require(t, os.Mkdir(filepath.Join(root, "public"), 0755))
	source.Require(t, os.Mkdir(filepath.Join(root, "private"), 0700))
	repo, e := os.Getwd()
	source.Require(t, e)
	fixture := filepath.Join(repo, "../../node/custodyv2/testdata/public-fixture")
	run := func(step, role string) {
		profile5WANRun(t, profile5WANStep{Step: step, Role: role, Root: root, Fixture: fixture})
	}
	run("seed", "a")
	run("source", "a")
	if _, e := os.Stat(filepath.Join(root, "private/b-source")); !os.IsNotExist(e) {
		t.Fatal("A created B source")
	}
	run("source", "b")
	run("select", "a")
	run("install", "a")
	// B installation belongs to its own host; it is exercised by the WAN suite.
}
