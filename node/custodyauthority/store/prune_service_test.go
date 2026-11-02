package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type pruneServiceGuard struct {
	calls int
	fail  bool
}

func (g *pruneServiceGuard) Choose(ctx context.Context, q guardwire.Request) ([64]byte, error) {
	g.calls++
	if ctx.Err() != nil {
		return [64]byte{}, ctx.Err()
	}
	if _, err := q.CanonicalBytes(); err != nil || g.fail {
		return [64]byte{}, guardwire.ErrGuard
	}
	h, _ := q.SealDigest()
	var seal [64]byte
	copy(seal[:], ed25519.Sign(testKey(92), h[:]))
	return seal, nil
}
func enrolledPrunePolicy(t testing.TB, v ScheduledPruneInventory) prunefence.Policy {
	t.Helper()
	e, err := (prunefence.ServiceEnrollment{AssignmentID: v.Request.AssignmentID, ScheduleID: v.Request.ScheduleID, StorageID: v.Request.StorageID, StoragePairID: v.StoragePairID, Service: testPublic(90), Issuer: testPublic(91), Guard: testPublic(92)}).Sign(testKey(91))
	if err != nil {
		t.Fatal(err)
	}
	p := pruneFencePolicy()
	p.Service = &e
	return p
}
func newServicePruneFixture(t testing.TB) *scheduledPruneFixture {
	t.Helper()
	return newScheduledPruneFixtureConfigured(t, func(v *ScheduledPruneInventory) { p := enrolledPrunePolicy(t, *v); v.FencePolicy = &p })
}

func TestPruneServiceActualStorageAndColdRecovery(t *testing.T) {
	f := newServicePruneFixture(t)
	w := newPruneWitnessFixture(t, f.inventory)
	before := pruneFenceObligations(t, f)
	for _, run := range []func() error{
		func() error { _, e := f.execute(t.Context()); return e },
		func() error { _, e := f.executeFenced(t.Context(), w.collect); return e },
		func() error {
			op, _ := pruneFenceOperation(pruneSnapshot(t, f.executor))
			_, e := f.archive.f.chain.PruneCanonicalPrefixOnce(op, func() (uint64, error) { t.Fatal("legacy storage authorized"); return 0, nil })
			return e
		},
	} {
		if err := run(); err == nil {
			t.Fatal("legacy path bypassed service")
		}
	}
	if pruneSnapshot(t, f.executor).Stage != PruneAdmitted || !reflect.DeepEqual(before, pruneFenceObligations(t, f)) {
		t.Fatal("rejected bypass mutated obligations")
	}
	g := new(pruneServiceGuard)
	i, err := prunefence.NewServiceIdentity(*f.inventory.FencePolicy.Service, testKey(90), g)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	c := f.runtimeConfig(t)
	c.CollectPruneClaim, c.ServiceIdentity = w.collect, i
	s := openScheduledEffect(t, c)
	review := scheduledEffectReview(t, s)
	r, err := s.Execute(t.Context(), review.ReviewID)
	if err != nil || r.Commit == nil || !r.Commit.Applied || g.calls != 1 || r.FenceResult == nil || r.FenceResult.ServiceConsumption == nil {
		t.Fatal("service deletion", err, g.calls)
	}
	if r.Commit.Effect.Operation.ServiceEnrollmentID != f.inventory.Request.ServiceEnrollmentID {
		t.Fatal("effect lost enrollment")
	}
	raw, _ := r.Commit.Effect.CanonicalBytes()
	if raw[9] != 3 {
		t.Fatal("wrong effect version")
	}
	decoded, err := workchain.DecodeCanonicalPruneEffect(raw)
	if err != nil || !reflect.DeepEqual(decoded, r.Commit.Effect) {
		t.Fatal("effect roundtrip", err)
	}
	if _, err := RetainedScheduledPruneOutcome(f.inventory, scheduledEffectReview(t, s).Executor); err != nil {
		t.Fatal("retained outcome", err)
	}
	after := scheduledEffectReview(t, s)
	if !reflect.DeepEqual(review.Authorities, after.Authorities) || !reflect.DeepEqual(review.Journals, after.Journals) {
		t.Fatal("effect discharged obligations")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	i.Close()
	c.ServiceIdentity, c.CollectPruneClaim = nil, nil
	cold := openScheduledEffect(t, c)
	recovered, err := cold.Recover(t.Context(), scheduledEffectReview(t, cold).ReviewID)
	if err != nil || recovered.Commit.Applied || !reflect.DeepEqual(recovered.Commit.Effect, r.Commit.Effect) || g.calls != 1 {
		t.Fatal("cold recovery replayed live permission", err)
	}
}

func TestPruneServiceGuardRefusalRetainsUnknownWork(t *testing.T) {
	f := newServicePruneFixture(t)
	w := newPruneWitnessFixture(t, f.inventory)
	g := &pruneServiceGuard{fail: true}
	i, err := prunefence.NewServiceIdentity(*f.inventory.FencePolicy.Service, testKey(90), g)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	c := f.runtimeConfig(t)
	c.CollectPruneClaim, c.ServiceIdentity = w.collect, i
	s := openScheduledEffect(t, c)
	before := scheduledEffectReview(t, s)
	if _, err := s.Execute(t.Context(), before.ReviewID); err == nil || g.calls != 1 {
		t.Fatal("guard refusal accepted", err)
	}
	after := scheduledEffectReview(t, s)
	if after.Executor.Stage != PruneStarted || after.Executor.FenceClaim == nil || after.Executor.FenceResult != nil || !reflect.DeepEqual(before.Storage, after.Storage) || !reflect.DeepEqual(before.Authorities, after.Authorities) || !reflect.DeepEqual(before.Journals, after.Journals) {
		t.Fatal("refusal lost held obligations")
	}
	g.fail = false
	if _, err := s.Execute(t.Context(), after.ReviewID); err == nil {
		t.Fatal("unknown work reexecuted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cold := openScheduledEffect(t, c)
	if _, err := cold.Recover(t.Context(), scheduledEffectReview(t, cold).ReviewID); err == nil || g.calls != 1 {
		t.Fatal("absence manufactured a result", err)
	}
}

func fixedServicePrunePlan(t testing.TB) ScheduledPrunePlan {
	t.Helper()
	old, err := DecodeScheduledPrunePlan(fixedScheduledPrunePlan(t).Plan)
	if err != nil {
		t.Fatal(err)
	}
	p, err := old.WithFence(enrolledPrunePolicy(t, ScheduledPruneInventory(old)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPruneServicePlanVersionsAndSubstitution(t *testing.T) {
	p := fixedServicePrunePlan(t)
	raw, _ := p.CanonicalBytes()
	req, _ := p.Request.CanonicalBytes()
	if raw[9] != 2 || req[9] != 4 {
		t.Fatal("wrong versions")
	}
	for _, mode := range []string{"missing", "id", "storage", "pair", "schedule", "assignment", "service-role", "issuer-role", "guard-role", "signature"} {
		bad, _ := DecodeScheduledPrunePlan(raw)
		e := bad.FencePolicy.Service
		switch mode {
		case "missing":
			bad.FencePolicy.Service = nil
		case "id":
			bad.Request.ServiceEnrollmentID[0] ^= 1
		case "storage":
			e.StorageID[0] ^= 1
		case "pair":
			e.StoragePairID[0] ^= 1
		case "schedule":
			e.ScheduleID[0] ^= 1
		case "assignment":
			e.AssignmentID[0] ^= 1
		case "service-role":
			e.Service = p.Replicas[0].Assignment.ReplicaPublicKey
		case "issuer-role":
			e.Issuer = testPublic(4)
		case "guard-role":
			e.Guard = p.OriginalPolicy.TrustedAttestors[0]
		case "signature":
			e.Signature[0] ^= 1
		}
		if mode != "id" && mode != "signature" && mode != "missing" {
			key := testKey(91)
			if mode == "issuer-role" {
				key = testKey(4)
			}
			signed, err := e.Sign(key)
			if err != nil {
				t.Fatal(err)
			}
			*e = signed
			bad.Request.ServiceEnrollmentID, _ = e.ID()
			bad.Request.FencePolicyID, _ = bad.FencePolicy.ID()
		}
		if _, err := bad.ID(); err == nil {
			t.Fatal("substitution", mode)
		}
	}
	for version := byte(0); version < 4; version++ {
		b := bytes.Clone(req)
		b[9] = version
		if _, err := DecodePruneRequest(b); err == nil {
			t.Fatal("request downgrade")
		}
	}
	for version := byte(0); version < 2; version++ {
		b := bytes.Clone(raw)
		b[9] = version
		if _, err := DecodeScheduledPrunePlan(b); err == nil {
			t.Fatal("plan downgrade")
		}
	}
	for i, b := range [][]byte{req, raw} {
		got := fmt.Sprintf("%d:%x", len(b), sha256.Sum256(b))
		if got != []string{"546:8662592f87b52be102e421e0936c11a02bb426a4a4a53a07e438c5252924eac2", "8614:9ee7119a244b7d65513c8d2801cf9928bd8a31d3cff3cf05b42e0181cb243859"}[i] {
			t.Errorf("vector %d: %s", i, got)
		}
	}
}
func FuzzPruneServicePlan(f *testing.F) {
	p := fixedServicePrunePlan(f)
	raw, _ := p.CanonicalBytes()
	req, _ := p.Request.CanonicalBytes()
	f.Add(false, raw)
	f.Add(true, req)
	f.Fuzz(func(t *testing.T, request bool, raw []byte) {
		var b []byte
		var err error
		if request {
			p, e := DecodePruneRequest(raw)
			if e != nil {
				return
			}
			b, err = p.CanonicalBytes()
		} else {
			p, e := DecodeScheduledPrunePlan(raw)
			if e != nil {
				return
			}
			b, err = p.CanonicalBytes()
		}
		if err != nil || !bytes.Equal(b, raw) {
			t.Fatal("noncanonical service plan")
		}
	})
}

func fixedServiceEffect(t testing.TB) workchain.CanonicalPruneEffect {
	t.Helper()
	e, err := workchain.DecodeCanonicalPruneEffect(fixedScheduledPrune(t).Effect)
	if err != nil {
		t.Fatal(err)
	}
	e.Operation.ServiceEnrollmentID = fixedServicePrunePlan(t).Request.ServiceEnrollmentID
	return e
}
func TestPruneServiceEffectVersionAndVector(t *testing.T) {
	e := fixedServiceEffect(t)
	raw, err := e.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []byte{0, 1, 2, 4} {
		bad := bytes.Clone(raw)
		bad[9] = version
		if _, err := workchain.DecodeCanonicalPruneEffect(bad); err == nil {
			t.Fatal("effect version substitution")
		}
	}
	id, _ := e.ID()
	op, _ := e.Operation.FenceOperationID()
	got := fmt.Sprintf("%d:%x:%s:%s", len(raw), sha256.Sum256(raw), id, op)
	if got != "626:097b12f2367417936600897fe168b35602204cf284366b1d27ada8b5c30f28aa:3651f3135dee7acf3b8be2fabc731e97c31f4f2a796a0950ae7f2811b792b9df:6aa3761664a68e3af96eecd613e86e16a59e60b745b4ea97d1dab50bdc6be06c" {
		t.Errorf("effect vector: %s", got)
	}
}
func FuzzPruneServiceEffect(f *testing.F) {
	b, _ := fixedServiceEffect(f).CanonicalBytes()
	f.Add(b)
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := workchain.DecodeCanonicalPruneEffect(raw)
		if err != nil {
			return
		}
		b, err := e.CanonicalBytes()
		if err != nil || !bytes.Equal(b, raw) {
			t.Fatal("noncanonical storage effect")
		}
	})
}
