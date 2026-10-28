package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type custodyV2Fixture struct {
	legacy           *remoteCLIFixture
	context          v2.Context
	pin              types.Hash
	target, acceptor string
	sources          v2.Sources
}

func newCustodyV2Fixture(t testing.TB, lifetimes ...uint64) *custodyV2Fixture {
	t.Helper()
	f := newRemoteCLIFixture(t, lifetimes...)
	a := v2.Assignment{Version: v2.Version2, Base: f.scope.Worker.Assignment, Policy: v2.Policy{Version: v2.Version2, Threshold: 3, Witnesses: fencetest.Scope().Witnesses}}
	aid, e := a.ID()
	if e != nil {
		t.Fatal(e)
	}
	intent := f.intent
	intent.AssignmentID = aid
	p := v2.Plan{Version: v2.Version2, AssignmentID: aid, Intent: intent, Challenge: f.scope.Challenge, ServeConsumer: pruneCLIPublic(4), ClientTransportPublicKey: pruneCLIPublic(46)}
	for _, role := range []string{"audit", "serve", "authority"} {
		seed := byte(4)
		if role == "authority" {
			seed = 1
		}
		p, e = p.Sign(role, pruneCLIKey(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	c := v2.Context{Assignment: a, Plan: p, Manifest: f.scope.Manifest, Initial: f.scope.InitialReceipt, Previous: f.scope.PreviousReceipt, CustodyPolicy: f.scope.CustodyPolicy}
	s, e := c.Scope()
	if e != nil {
		t.Fatal(e)
	}
	pin, _ := s.ID()
	result := &custodyV2Fixture{legacy: f, context: c, pin: pin, target: filepath.Join(t.TempDir(), "target"), acceptor: filepath.Join(t.TempDir(), "acceptor"), sources: v2.Sources{Journal: f.base.serve.config.Session.JournalPath, Objects: f.base.serve.config.ObjectPath}}
	if e := v2.CreateTarget(result.target, c, pin, result.sources); e != nil {
		t.Fatal(e)
	}
	if e := v2.CreateAcceptor(result.acceptor, c, pin, f.base.config.Audit.JournalPath); e != nil {
		t.Fatal(e)
	}
	return result
}
func (f *custodyV2Fixture) open(t testing.TB) *v2.Target {
	t.Helper()
	target, e := v2.OpenTarget(f.target, f.context, f.pin, f.sources, pruneCLIKey(61), pruneCLIKey(14))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}
func (f *custodyV2Fixture) bundle(t testing.TB, target *v2.Target) (v2.Bundle, custodyfence.Certificate) {
	t.Helper()
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	claim := fencetest.Certificate(candidate.Claim, 70, 71, 72)
	result, e := target.Execute(t.Context(), claim, f.context.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	same, command, e := target.ResultCommand([]custodyfence.Certificate{claim})
	if e != nil {
		t.Fatal(e)
	}
	a, _ := same.ID()
	b, _ := result.ID()
	if a != b {
		t.Fatal("recovery changed result")
	}
	bundle := v2.Bundle{Version: v2.Version2, Result: result, Chain: []custodyfence.Certificate{claim, fencetest.Certificate(command, 70, 71, 72)}}
	if e := bundle.Verify(f.context); e != nil {
		t.Fatal(e)
	}
	return bundle, claim
}
func TestCustodyV2RequiresWitnessesAtExecutionAndSourceAcceptance(t *testing.T) {
	f := newCustodyV2Fixture(t)
	target := f.open(t)
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	weak := fencetest.Certificate(candidate.Claim, 70, 71)
	if _, e := target.Execute(t.Context(), weak, f.context.Plan.Challenge.IssuedAt); e == nil {
		t.Fatal("two witnesses executed")
	}
	if _, e := os.Stat(filepath.Join(f.target, "consumed")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("invalid quorum consumed execution", e)
	}
	bundle, claim := f.bundle(t, target)
	if _, e := target.Execute(t.Context(), claim, f.context.Plan.Challenge.IssuedAt); !errors.Is(e, v2.ErrConsumed) {
		t.Fatal("replayed grant", e)
	}
	if e := target.Close(); e != nil {
		t.Fatal(e)
	}
	target = f.open(t)
	if _, e := target.Prepare(); !errors.Is(e, v2.ErrConsumed) {
		t.Fatal("restart enabled effect", e)
	}
	if _, e := target.Execute(t.Context(), claim, f.context.Plan.Challenge.IssuedAt); !errors.Is(e, v2.ErrConsumed) {
		t.Fatal("restart replayed grant", e)
	}
	retained, e := target.ReadResult()
	if e != nil {
		t.Fatal(e)
	}
	one, _ := retained.CanonicalBytes()
	two, _ := bundle.Result.CanonicalBytes()
	if !bytes.Equal(one, two) {
		t.Fatal("proof refreshed on restart")
	}
	a, e := v2.OpenAcceptor(f.acceptor, f.context, f.pin, f.legacy.base.config.Audit.JournalPath, pruneCLIKey(1))
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	bad := bundle
	bad.Chain = append([]custodyfence.Certificate(nil), bundle.Chain...)
	bad.Chain[1].Votes = bad.Chain[1].Votes[:2]
	if _, e := a.Accept(t.Context(), bad, f.context.Plan.Challenge.IssuedAt); e == nil {
		t.Fatal("accepted without result quorum")
	}
	ack, e := a.Accept(t.Context(), bundle, f.context.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	if e := ack.Verify(f.context, bundle); e != nil {
		t.Fatal(e)
	}
	retry, e := a.Accept(t.Context(), bundle, f.context.Plan.Challenge.ExpiresAt+10_000)
	if e != nil || retry != ack {
		t.Fatal("historical receipt changed", e)
	}
	if e := a.Close(); e != nil {
		t.Fatal(e)
	}
	if e := target.Close(); e != nil {
		t.Fatal(e)
	}
	state, e := f.legacy.base.serve.journal.State()
	if e != nil || state.Sequence != 1 {
		t.Fatal("B effect count", state, e)
	}
	j, _, e := workarchive.OpenExistingCustodyJournalWithLimits(context.Background(), f.legacy.base.config.Audit.JournalPath, f.context.Manifest, f.context.Initial, f.context.CustodyPolicy, workarchive.DefaultCustodyJournalLimits())
	if e != nil {
		t.Fatal(e)
	}
	state, e = j.State()
	if e != nil || state.Sequence != 1 {
		t.Fatal("A effect count", state, e)
	}
}
func TestCustodyV2CanonicalPolicyAndLegacySeparation(t *testing.T) {
	f := newCustodyV2Fixture(t)
	c := f.context
	raw, e := c.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := v2.DecodeContext(raw)
	if e != nil {
		t.Fatal(e)
	}
	pin, _ := decoded.Scope()
	id, _ := pin.ID()
	if id != f.pin {
		t.Fatal("scope changed")
	}
	a, _ := c.Assignment.CanonicalBytes()
	if _, e := custodyauthority.DecodeAssignment(a); e == nil {
		t.Fatal("V1 decoded V2 assignment")
	}
	changed := c.Assignment
	changed.Policy.Threshold = 4
	before, _ := c.Assignment.ID()
	after, _ := changed.ID()
	if before == after {
		t.Fatal("policy omitted from assignment")
	}
	if c.Plan.Verify(changed) == nil {
		t.Fatal("plan reused new policy")
	}
	c.Assignment.Policy.Witnesses = append([][32]byte(nil), c.Assignment.Policy.Witnesses...)
	c.Assignment.Policy.Witnesses[0] = c.Assignment.Base.ReplicaPublicKey
	if c.Validate() == nil {
		t.Fatal("role reuse")
	}
	for _, b := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
		if _, e := v2.DecodeContext(b); e == nil {
			t.Fatal("accepted noncanonical context")
		}
	}
}
func TestExportCustodyV2PublicGolden(t *testing.T) {
	destination := os.Getenv("OMESH_V2_PUBLIC_GOLDEN")
	if destination == "" {
		t.Skip("explicit public fixture export only")
	}
	f := newCustodyV2Fixture(t)
	b, e := f.context.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(destination, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(destination, "context"), b, 0600); e != nil {
		t.Fatal(e)
	}
	objects, e := workarchive.OpenExistingObjectStore(f.sources.Objects, workarchive.DefaultObjectStorePolicy())
	if e != nil {
		t.Fatal(e)
	}
	for _, chunk := range f.context.Manifest.Chunks {
		b, e := objects.Get(chunk.ID)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(destination, chunk.ID.String()), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
