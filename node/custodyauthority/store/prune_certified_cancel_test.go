package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	fencetest "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

func pruneClosureIntent(v ScheduledPruneInventory) prunefence.ClosureIntent {
	id, _ := v.Request.ID()
	return prunefence.ClosureIntent{Policy: *v.FencePolicy, AssignmentID: v.Request.AssignmentID, RequestID: id}
}

func (w *pruneWitnessFixture) closeSlot(t testing.TB, i prunefence.ClosureIntent) prunefence.Closure {
	t.Helper()
	_, draft, err := i.Draft()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := draft.Sign(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	c := prunefence.Closure{Intent: i, Certificate: custodyfence.Certificate{Version: 1, Command: signed}}
	for _, m := range w.members {
		v, err := m.Vote(signed)
		if err == nil {
			c.Certificate.Votes = append(c.Certificate.Votes, v)
		}
	}
	sort.Slice(c.Certificate.Votes, func(i, j int) bool {
		return bytes.Compare(c.Certificate.Votes[i].Witness[:], c.Certificate.Votes[j].Witness[:]) < 0
	})
	if err := c.Verify(); err != nil {
		t.Fatal(err)
	}
	return c
}

func signedPruneClosure(t testing.TB, i prunefence.ClosureIntent) prunefence.Closure {
	t.Helper()
	_, draft, err := i.Draft()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := draft.Sign(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	c := prunefence.Closure{Intent: i, Certificate: fencetest.Certificate(signed, 70, 71, 72)}
	if err := c.Verify(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPruneCertifiedCancellationOriginalCompletion(t *testing.T) {
	f := newScheduledPruneFixture(t, pruneFencePolicy())
	w := newPruneWitnessFixture(t, f.inventory)
	before := pruneFenceObligations(t, f)
	storage, _ := f.archive.f.chain.StorageProtection()
	closure := w.closeSlot(t, pruneClosureIntent(f.inventory))
	// All four votes exist. Retain one exact quorum; another valid subset must
	// not rewrite the cancellation once its ID is used for completion.
	other := closure
	other.Certificate.Votes = append([]custodyfence.Vote(nil), closure.Certificate.Votes[1:]...)
	closure.Certificate.Votes = closure.Certificate.Votes[:3]
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.operations[0].Coordinator); err == nil {
		t.Fatal("local bypass")
	}
	c, err := f.executor.CancelWithClosure(t.Context(), f.operations[0].Coordinator, closure)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := c.CanonicalBytes()
	if !reflect.DeepEqual(before, pruneFenceObligations(t, f)) {
		t.Fatal("cancellation changed accounting")
	}
	afterStorage, _ := f.archive.f.chain.StorageProtection()
	if !reflect.DeepEqual(storage, afterStorage) {
		t.Fatal("cancellation changed storage")
	}
	// Input and result are detached from retained state.
	closure.Certificate.Votes[0].Signature[0] ^= 1
	c.Closure.Intent.Policy.Witnesses[0][0] ^= 1
	s, err := f.executor.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	retained, _ := s.Cancellation.CanonicalBytes()
	if !bytes.Equal(raw, retained) {
		t.Fatal("caller mutated retained quorum")
	}
	if _, err := f.executor.CancelWithClosure(t.Context(), nil, other); err == nil {
		t.Fatal("different valid quorum replaced evidence")
	}
	copy, _ := DecodePruneCancellation(raw)
	reopenPruneFence(t, f)
	retry, err := f.executor.CancelWithClosure(t.Context(), nil, *copy.Closure)
	again, _ := retry.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("cold retry changed evidence", err)
	}
	if _, err := f.executeFenced(t.Context(), w.collect); err == nil {
		t.Fatal("cancelled executor restarted")
	}
	s, _ = f.executor.Snapshot()
	o, err := RetainedScheduledPruneOutcome(f.inventory, s)
	if err != nil {
		t.Fatal(err)
	}
	for i, op := range f.operations {
		draft, err := BuildScheduledPruneOutcomeCompletion(planFromInventory(f.inventory), f.inventory, o, op.Binding.AssignmentID, testCoordination(t, op.Coordinator).Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		entry := managedCommandApplyTestSign(t, draft)
		commit, err := f.executor.CompleteScheduledArchiveReplica(t.Context(), op.Coordinator, f.path, f.id, entry)
		if err != nil {
			t.Fatal(err)
		}
		if commit.Snapshot.Pending != before[i].Pending-1 || len(commit.Snapshot.Operations) != len(before[i].Operations) {
			t.Fatal("accounting reset")
		}
		for _, old := range before[i].Operations {
			if old.TicketID == op.Binding.TicketID {
				continue
			}
			found := false
			for _, now := range commit.Snapshot.Operations {
				if reflect.DeepEqual(old, now) {
					found = true
				}
			}
			if !found {
				t.Fatal("unrelated obligation changed")
			}
		}
		if i == 0 && testCoordination(t, f.operations[1].Coordinator).Authority.Pending != before[1].Pending {
			t.Fatal("released other replica")
		}
		again, err := f.executor.CompleteScheduledArchiveReplica(t.Context(), op.Coordinator, f.path, f.id, entry)
		if err != nil || again.Appended || !reflect.DeepEqual(commit.Snapshot, again.Snapshot) {
			t.Fatal("completion not idempotent", err)
		}
	}
}

func TestPruneCertifiedCancellationFaultRecovery(t *testing.T) {
	for _, stage := range []string{"pins-cancel-intent-before-publish", "pins-cancel-intent-after-publish", "prune-cancel-before-write", "prune-cancel-after-publish", "prune-cancel-after-apply", "pins-cancel-confirm-before-publish", "pins-cancel-confirm-after-publish"} {
		t.Run(stage, func(t *testing.T) {
			f := newScheduledPruneFixture(t, pruneFencePolicy())
			w := newPruneWitnessFixture(t, f.inventory)
			before := pruneFenceObligations(t, f)
			// A cold candidate with no granted claim can be closed; the candidate
			// remains present after cancellation and across all recovery points.
			fault := errors.New("interrupt certified cancellation")
			f.executor.hooks.at = func(at string) error {
				if at == "prune-fence-candidate-synced" {
					return fault
				}
				return nil
			}
			if _, err := f.executeFenced(t.Context(), w.collect); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			reopenPruneFence(t, f)
			candidate, _ := f.executor.fenceCandidate.CanonicalBytes()
			closure := w.closeSlot(t, pruneClosureIntent(f.inventory))
			hit := false
			hook := storeHooks{at: func(at string) error {
				if at == stage {
					hit = true
					return fault
				}
				return nil
			}}
			f.executor.hooks, f.executor.pins.hooks = hook, hook
			if _, err := f.executor.CancelWithClosure(t.Context(), f.operations[0].Coordinator, closure); !errors.Is(err, fault) || !hit {
				t.Fatal("missed fault", err)
			}
			reopenPruneFence(t, f)
			s, _ := f.executor.Snapshot()
			if s.Protection.Pending != nil {
				if _, err := f.executor.CancelWithClosure(t.Context(), f.operations[0].Coordinator, closure); !errors.Is(err, ErrPrunePinPending) {
					t.Fatal("implicit resume", err)
				}
				if err := f.executor.ResumePinnedTransition(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			c, err := f.executor.CancelWithClosure(t.Context(), f.operations[0].Coordinator, closure)
			if err != nil || c.Closure == nil {
				t.Fatal(err)
			}
			reopenPruneFence(t, f)
			s, _ = f.executor.Snapshot()
			got, _ := s.FenceCandidate.CanonicalBytes()
			if s.Stage != PruneCancelled || s.Protection.Pending != nil || !bytes.Equal(candidate, got) {
				t.Fatal("lost terminal/candidate")
			}
			if !reflect.DeepEqual(before, pruneFenceObligations(t, f)) {
				t.Fatal("recovery changed obligations")
			}
			if _, err := RetainedScheduledPruneOutcome(f.inventory, s); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPruneCertifiedCancellationRejectsStartedAndSubstitution(t *testing.T) {
	f := newScheduledPruneFixture(t, pruneFencePolicy())
	i := pruneClosureIntent(f.inventory)
	closure := signedPruneClosure(t, i)
	before, _ := f.executor.Snapshot()
	for _, name := range []string{"request", "assignment", "policy", "minority", "signature", "nil-owner", "wrong-owner", "context"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := closure.CanonicalBytes()
			bad, _ := prunefence.DecodeClosure(raw)
			owner, ctx := f.operations[0].Coordinator, t.Context()
			switch name {
			case "request":
				bad.Intent.RequestID = testHash(238)
				bad = signedPruneClosure(t, bad.Intent)
			case "assignment":
				bad.Intent.AssignmentID = testHash(238)
				bad = signedPruneClosure(t, bad.Intent)
			case "policy":
				bad.Intent.Policy.Owner = testPublic(238)
				bad = signedPruneClosure(t, bad.Intent)
			case "minority":
				bad.Certificate.Votes = bad.Certificate.Votes[:2]
			case "signature":
				bad.Certificate.Command.Signature[0] ^= 1
			case "nil-owner":
				owner = nil
			case "wrong-owner":
				owner = f.operations[1].Coordinator
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := f.executor.CancelWithClosure(ctx, owner, bad); err == nil {
				t.Fatal("accepted", name)
			}
			after, _ := f.executor.Snapshot()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejection changed executor")
			}
		})
	}
	// Even syntactically valid closure evidence cannot override any retained
	// start. This deliberately supplies inconsistent signer choices as defense
	// in depth; real original witnesses cannot grant both quorums.
	f.executor.hooks.at = func(at string) error {
		if at == "prune-before-effect" {
			return errors.New("hold start")
		}
		return nil
	}
	w := newPruneWitnessFixture(t, f.inventory)
	if _, err := f.executeFenced(t.Context(), w.collect); err == nil {
		t.Fatal("expected held start")
	}
	reopenPruneFence(t, f)
	if _, err := f.executor.CancelWithClosure(t.Context(), f.operations[0].Coordinator, closure); !errors.Is(err, ErrPruneOutcome) {
		t.Fatal("started cancelled", err)
	}
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.operations[0].Coordinator); err == nil {
		t.Fatal("legacy bypass")
	}
}

func TestPruneCertifiedCancellationRejectsRollback(t *testing.T) {
	for _, mode := range []string{"missing-record", "wrong-binding", "different-quorum", "legacy-downgrade"} {
		t.Run(mode, func(t *testing.T) {
			f := newScheduledPruneFixture(t, pruneFencePolicy())
			w := newPruneWitnessFixture(t, f.inventory)
			closure := w.closeSlot(t, pruneClosureIntent(f.inventory))
			c, err := f.executor.CancelWithClosure(t.Context(), f.operations[0].Coordinator, closure)
			if err != nil {
				t.Fatal(err)
			}
			e := f.executor
			pinsPath := e.pins.path
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.path, pruneRecordsName, pruneRecordName(1, PruneCancelled))
			if mode == "missing-record" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				switch mode {
				case "wrong-binding":
					c.BindingID = testHash(239)
				case "different-quorum":
					c.Closure.Certificate.Votes = c.Closure.Certificate.Votes[:3]
				case "legacy-downgrade":
					c.Closure = nil
				}
				raw, err := c.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := OpenPinnedPruneExecutor(e.path, pinsPath, e.assignment, e.id)
			if opened != nil {
				opened.Close()
			}
			if err == nil {
				t.Fatal("accepted rolled-back or substituted record")
			}
		})
	}
}

func TestPruneCertifiedCancellationRacesExecution(t *testing.T) {
	f := newScheduledPruneFixture(t, pruneFencePolicy())
	w := newPruneWitnessFixture(t, f.inventory)
	closure := w.closeSlot(t, pruneClosureIntent(f.inventory))
	var wg sync.WaitGroup
	wg.Add(2)
	var cancelErr, executeErr error
	go func() {
		defer wg.Done()
		_, cancelErr = f.executor.CancelWithClosure(t.Context(), f.operations[0].Coordinator, closure)
	}()
	go func() { defer wg.Done(); _, executeErr = f.executeFenced(t.Context(), w.collect) }()
	wg.Wait()
	if cancelErr != nil || executeErr == nil {
		t.Fatal("race did not retain only cancellation", cancelErr, executeErr)
	}
	s, _ := f.executor.Snapshot()
	if s.Stage != PruneCancelled || s.Effect != nil || s.FenceClaim != nil {
		t.Fatal("conflicting branches")
	}
}

func certifiedCancellationVector(t testing.TB) PruneCancellation {
	i := prunefence.ClosureIntent{Policy: pruneFencePolicy(), AssignmentID: testHash(1), RequestID: testHash(2)}
	c := signedPruneClosure(t, i)
	return PruneCancellation{AssignmentID: i.AssignmentID, RequestID: i.RequestID, TicketID: testHash(3), BindingID: testHash(4), Closure: &c}
}

func TestPruneCertifiedCancellationCodec(t *testing.T) {
	c := certifiedCancellationVector(t)
	raw, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Fixed header/fields and the length prefix are assembled independently.
	want := []byte("OMCPCNCL\x00\x01")
	for _, h := range []types.Hash{testHash(1), testHash(2), testHash(3), testHash(4)} {
		want = append(want, h[:]...)
	}
	proof, _ := c.Closure.CanonicalBytes()
	want = binary.AppendUvarint(want, uint64(len(proof)))
	want = append(want, proof...)
	if !bytes.Equal(want, raw) {
		t.Fatal("v1 layout")
	}
	if len(raw) != 1102 || fmt.Sprintf("%x", sha256.Sum256(want)) != "7cac32414918c942caf018c56b5e2a8ecf03537a3fc343f7592586c184d550d3" {
		t.Fatal("v1 fixed vector")
	}
	id, _ := c.ID()
	if id != types.DomainHash("OMESH/custody-prune/cancellation/id/v1", want) {
		t.Fatal("v1 domain")
	}
	if id.String() != "cfd1d0a6500084a72927975f22519ae2f3e3022570cc8b2ed67ec1654df2ca6a" {
		t.Fatal("v1 fixed ID")
	}
	decoded, err := DecodePruneCancellation(raw)
	if err != nil || !reflect.DeepEqual(decoded, c) {
		t.Fatal("round trip", err)
	}
	for n := 0; n < len(raw); n++ {
		if _, err := DecodePruneCancellation(raw[:n]); err == nil {
			t.Fatal("truncated", n)
		}
	}
	badVersion := bytes.Clone(raw)
	badVersion[9] = 2
	overlong := append([]byte(nil), raw[:138]...)
	n, size := binary.Uvarint(raw[138:])
	prefix := binary.AppendUvarint(nil, n)
	prefix[len(prefix)-1] |= 0x80
	prefix = append(prefix, 0)
	overlong = append(overlong, prefix...)
	overlong = append(overlong, raw[138+size:]...)
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), badVersion, overlong, make([]byte, MaximumCertifiedPruneCancellationBytes+1)} {
		if _, err := DecodePruneCancellation(bad); err == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	for _, mutate := range []func(*PruneCancellation){func(c *PruneCancellation) { c.RequestID = testHash(7) }, func(c *PruneCancellation) { c.AssignmentID = testHash(7) }, func(c *PruneCancellation) { c.TicketID = types.Hash{} }, func(c *PruneCancellation) { c.Closure.Certificate.Votes[0].Signature[0] ^= 1 }} {
		bad, _ := DecodePruneCancellation(raw)
		mutate(&bad)
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("invalid certificate accepted")
		}
	}
	// A v1 outcome can never be used to upgrade an unfenced request.
	legacy := PruneExecution{RequestID: c.RequestID, Request: PruneRequest{AssignmentID: c.AssignmentID}, Admission: &custodyauthority.Entry{}}
	if cancellationMatches(legacy, c) {
		t.Fatal("legacy upgrade")
	}
}
