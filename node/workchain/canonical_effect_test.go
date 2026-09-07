package workchain

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func pruneOperation(boundary CanonicalFloor, label string) CanonicalPruneOperation {
	return CanonicalPruneOperation{
		AssignmentID: types.DomainHash("test/prune-effect/assignment"),
		TicketID:     types.DomainHash("test/prune-effect/ticket/" + label), Boundary: cloneCanonicalFloor(boundary),
	}
}

func equalPruneEffect(left, right CanonicalPruneEffect) bool {
	l, le := left.CanonicalBytes()
	r, re := right.CanonicalBytes()
	return le == nil && re == nil && bytes.Equal(l, r)
}

func TestCanonicalPruneEffectRetainsExactResultAcrossLaterMaintenance(t *testing.T) {
	for _, ticketedSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-second", true: "ticketed-second"}[ticketedSecond], func(t *testing.T) {
			store, path, base, parameters, policy, boundary := canonicalAuthorizationFixture(t)
			op := pruneOperation(boundary, "first")
			before, _, _ := store.HistoryUsage()
			calls := 0
			commit, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { calls++; return 200, nil })
			if err != nil || !commit.Applied || calls != 1 || commit.Effect.VerifiedAt != 200 {
				t.Fatalf("commit=%+v calls=%d err=%v", commit, calls, err)
			}
			after, _, _ := store.HistoryUsage()
			if after != before-commit.Effect.Report.ReleasedHistoryBytes+commit.Effect.Report.AddedHistoryBytes {
				t.Fatal("result bytes not included in atomic accounting")
			}
			floor, _ := store.CanonicalFloor()
			if floor.PruneTicketID != op.TicketID || floor.VerifiedAt != 200 {
				t.Fatal("floor lost result linkage")
			}
			// Caller-owned and returned slice mutations cannot change retained data.
			op.Boundary.Anchor.CumulativeWork[0] ^= 1
			op = pruneOperation(boundary, "first")
			detached, found, err := store.CanonicalPruneEffect(op.TicketID)
			if err != nil || !found || !equalPruneEffect(detached, commit.Effect) {
				t.Fatal("lookup lost result", err)
			}
			detached.Operation.Boundary.Anchor.CumulativeWork[0] ^= 1
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenWithPolicy(path, base, parameters, policy)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			secondAnchor := store.nodes[store.tipID].block.Header.Seal.AnchorParent
			tip, _ := store.TipByID(secondAnchor)
			root, count, _ := store.SelectedAncestryCommitment(secondAnchor)
			second := canonicalTestFloor(base.Tip.ID, tip, root, count, "second")
			if ticketedSecond {
				if _, err := store.PruneCanonicalPrefixOnce(pruneOperation(second, "second"), func() (uint64, error) { return 250, nil }); err != nil {
					t.Fatal(err)
				}
			} else if _, err := store.PruneCanonicalPrefix(second); err != nil {
				t.Fatal(err)
			}
			if _, err := store.PruneStaleForks(); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateReplayCheckpoint(); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = OpenWithPolicy(path, base, parameters, policy)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			usage, _, _ := store.HistoryUsage()
			store.persistence.policy.CanonicalRetention = 0 // historical lookup is not a new authorization
			store.persistence.pruneEffects = MaximumCanonicalPruneEffects
			store.persistence.commitHook = func() error { t.Error("retry prepared a write"); return context.Canceled }
			retry, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { t.Error("retry reauthorized"); return 0, context.Canceled })
			if err != nil || retry.Applied || !equalPruneEffect(commit.Effect, retry.Effect) {
				t.Fatal("retry changed old result", err)
			}
			current, _ := store.CanonicalFloor()
			if current.Anchor.ID != secondAnchor {
				t.Fatal("retry moved floor backwards")
			}
			if got, _, _ := store.HistoryUsage(); got != usage {
				t.Fatal("retry changed accounting")
			}
			lookup, found, err := store.CanonicalPruneEffect(op.TicketID)
			if err != nil || !found || !equalPruneEffect(commit.Effect, lookup) {
				t.Fatal("later maintenance lost old evidence", err)
			}
		})
	}
}

func TestCanonicalPruneEffectRejectsTicketSubstitution(t *testing.T) {
	store, _, _, _, _, boundary := canonicalAuthorizationFixture(t)
	op := pruneOperation(boundary, "conflict")
	if _, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil }); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CanonicalPruneOperation){
		"assignment":   func(o *CanonicalPruneOperation) { o.AssignmentID[0] ^= 1 },
		"manifest":     func(o *CanonicalPruneOperation) { o.Boundary.ManifestID[0] ^= 1 },
		"statement":    func(o *CanonicalPruneOperation) { o.Boundary.StatementID[0] ^= 1 },
		"availability": func(o *CanonicalPruneOperation) { o.Boundary.AvailabilityID[0] ^= 1 },
		"ancestry":     func(o *CanonicalPruneOperation) { o.Boundary.AncestryRoot[0] ^= 1 },
		"count":        func(o *CanonicalPruneOperation) { o.Boundary.AncestryNodes++ },
		"initial-time": func(o *CanonicalPruneOperation) { o.Boundary.VerifiedAt++ },
		"expiry":       func(o *CanonicalPruneOperation) { o.Boundary.RetainUntil++ },
		"anchor":       func(o *CanonicalPruneOperation) { o.Boundary.Anchor.ID[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := pruneOperation(boundary, "conflict")
			mutate(&changed)
			result, err := store.PruneCanonicalPrefixOnce(changed, func() (uint64, error) { t.Error("conflict reached authorization"); return 200, nil })
			if !errors.Is(err, ErrPruneTicketConflict) || result.Applied || !result.Effect.Operation.TicketID.IsZero() {
				t.Fatal("accepted substitution", err)
			}
		})
	}
}

func TestCanonicalPruneEffectDenialPublishesNothing(t *testing.T) {
	for _, mode := range []string{"nil", "cancel", "expired", "rollback", "preparation", "bytes", "count", "ticket-in-boundary", "assignment", "ticket"} {
		t.Run(mode, func(t *testing.T) {
			store, path, base, parameters, policy, boundary := canonicalAuthorizationFixture(t)
			op := pruneOperation(boundary, mode)
			before, _, _ := store.HistoryUsage()
			called, prepared := false, false
			store.persistence.commitHook = func() error {
				prepared = true
				if mode == "preparation" {
					return context.Canceled
				}
				return nil
			}
			authorize := func() (uint64, error) {
				called = true
				if !prepared {
					t.Error("authorization preceded batch preparation")
				}
				switch mode {
				case "cancel":
					return 0, context.Canceled
				case "expired":
					return boundary.RetainUntil, nil
				case "rollback":
					return 99, nil
				}
				return 200, nil
			}
			switch mode {
			case "nil":
				authorize = nil
			case "bytes":
				store.persistence.policy.MaxHistoryBytes = 1
			case "count":
				store.persistence.pruneEffects = MaximumCanonicalPruneEffects
			case "ticket-in-boundary":
				op.Boundary.PruneTicketID = op.TicketID
			case "assignment":
				op.AssignmentID = types.Hash{}
			case "ticket":
				op.TicketID = types.Hash{}
			}
			commit, err := store.PruneCanonicalPrefixOnce(op, authorize)
			if (mode == "bytes" || mode == "count") && !errors.Is(err, storage.ErrHistoryLimit) {
				t.Fatal("wrong retention budget error", err)
			}
			if err == nil || commit.Applied || !commit.Effect.Operation.TicketID.IsZero() {
				t.Fatal("denial returned result", err)
			}
			if called != (mode == "cancel" || mode == "expired" || mode == "rollback") {
				t.Fatal("unexpected authorization call")
			}
			if floor, _ := store.CanonicalFloor(); floor.Pruned {
				t.Fatal("denial pruned")
			}
			if usage, _, _ := store.HistoryUsage(); usage != before {
				t.Fatal("denial changed accounting")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenWithPolicy(path, base, parameters, policy)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if reopened.persistence.effectSchema || reopened.persistence.pruneEffects != 0 {
				t.Fatal("denial published schema or effect")
			}
			if _, found, err := reopened.CanonicalPruneEffect(pruneOperation(boundary, mode).TicketID); err != nil || found {
				t.Fatal("denial recorded result", err)
			}
		})
	}
}

func TestCanonicalPruneEffectSerializesSameTicket(t *testing.T) {
	store, _, _, _, _, boundary := canonicalAuthorizationFixture(t)
	op := pruneOperation(boundary, "concurrent")
	var calls, applied atomic.Int32
	var wg sync.WaitGroup
	results := make(chan CanonicalPruneEffect, 16)
	for range 16 {
		wg.Go(func() {
			commit, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { calls.Add(1); return 200, nil })
			if err != nil {
				t.Error(err)
				return
			}
			if commit.Applied {
				applied.Add(1)
			}
			results <- commit.Effect
		})
	}
	wg.Wait()
	close(results)
	if calls.Load() != 1 || applied.Load() != 1 {
		t.Fatal("duplicate effect", calls.Load(), applied.Load())
	}
	var first CanonicalPruneEffect
	for effect := range results {
		if first.Operation.TicketID.IsZero() {
			first = effect
		}
		if !equalPruneEffect(first, effect) {
			t.Fatal("different concurrent results")
		}
	}
}

func TestCanonicalPruneEffectAmbiguousCommitRequiresReopen(t *testing.T) {
	for _, persisted := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-write", true: "written-with-lost-sync-result"}[persisted], func(t *testing.T) {
			store, path, base, parameters, policy, boundary := canonicalAuthorizationFixture(t)
			op := pruneOperation(boundary, "uncertain")
			tip, _ := store.Tip()
			candidate, _ := mineChild(t, store, tip.ID, tip.Timestamp+parameters.TargetSpacing, "uncertain-extension")
			injected := errors.New("lost commit result")
			store.persistence.pruneCommitHook = func(batch *pebble.Batch) error {
				if persisted {
					if err := batch.Commit(pebble.NoSync); err != nil {
						return err
					}
				}
				return injected
			}
			commit, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil })
			if !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) || commit.Applied || !commit.Effect.Operation.TicketID.IsZero() {
				t.Fatal("uncertain success", err)
			}
			for name, check := range map[string]func() error{
				"tip":          func() error { _, e := store.Tip(); return e },
				"base":         func() error { _, e := store.BaseID(); return e },
				"nodes":        func() error { _, e := store.NodeIDs(); return e },
				"tip-by-id":    func() error { _, e := store.TipByID(tip.ID); return e },
				"floor":        func() error { _, e := store.CanonicalFloor(); return e },
				"ancestor":     func() error { _, e := store.IsAncestor(base.Tip.ID, tip.ID); return e },
				"commitment":   func() error { _, _, e := store.SelectedAncestryCommitment(tip.ID); return e },
				"history":      func() error { _, e := store.SelectedHistorySnapshot(tip.ID, 100); return e },
				"state":        func() error { _, e := store.Snapshot(); return e },
				"block":        func() error { _, e := store.BlockByID(tip.ID); return e },
				"prepare":      func() error { _, _, e := store.Prepare(tip.ID, tip.Timestamp+60, nil); return e },
				"commit":       func() error { _, _, e := store.Commit(candidate, candidate.Header.Seal.Timestamp); return e },
				"usage":        func() error { _, _, e := store.HistoryUsage(); return e },
				"fork-prune":   func() error { _, e := store.PruneStaleForks(); return e },
				"checkpoint":   func() error { _, e := store.CreateReplayCheckpoint(); return e },
				"legacy-prune": func() error { _, e := store.PruneCanonicalPrefix(boundary); return e },
				"authorized-prune": func() error {
					_, e := store.PruneCanonicalPrefixAuthorized(boundary, func() (uint64, error) { t.Error("poisoned callback"); return 200, nil })
					return e
				},
				"once": func() error {
					_, e := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { t.Error("poisoned callback"); return 200, nil })
					return e
				},
				"lookup": func() error { _, _, e := store.CanonicalPruneEffect(op.TicketID); return e },
			} {
				if err := check(); !errors.Is(err, ErrUncertain) {
					t.Errorf("%s escaped poisoned handle: %v", name, err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenWithPolicy(path, base, parameters, policy)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			effect, found, err := reopened.CanonicalPruneEffect(op.TicketID)
			if err != nil || found != persisted {
				t.Fatal("wrong recovered result", found, err)
			}
			calls := 0
			retry, err := reopened.PruneCanonicalPrefixOnce(op, func() (uint64, error) { calls++; return 200, nil })
			if err != nil || retry.Applied == persisted || calls != map[bool]int{false: 1, true: 0}[persisted] {
				t.Fatal("wrong explicit retry", retry, err)
			}
			if persisted && !equalPruneEffect(effect, retry.Effect) {
				t.Fatal("retry changed committed result")
			}
		})
	}
}

func TestCanonicalPruneEffectCodecs(t *testing.T) {
	store, _, _, _, _, boundary := canonicalAuthorizationFixture(t)
	commit, err := store.PruneCanonicalPrefixOnce(pruneOperation(boundary, "codec"), func() (uint64, error) { return 200, nil })
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := commit.Effect.CanonicalBytes()
	id, _ := commit.Effect.ID()
	if len(encoded) != 490 || id.String() != "31be0ab8508b95f9f49708ad5c18d2c28300354873e778ad9a1a8e85f044bd99" {
		t.Fatalf("effect vector changed: bytes=%d id=%s", len(encoded), id)
	}
	decoded, err := DecodeCanonicalPruneEffect(encoded)
	if err != nil || !equalPruneEffect(commit.Effect, decoded) {
		t.Fatal("roundtrip", err)
	}
	for length := 0; length < len(encoded); length++ {
		if _, err := DecodeCanonicalPruneEffect(encoded[:length]); err == nil {
			t.Fatal("accepted truncation", length)
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), encoded...), 0), make([]byte, MaximumCanonicalPruneEffectBytes+1), {}} {
		if _, err := DecodeCanonicalPruneEffect(bad); err == nil {
			t.Fatal("accepted invalid effect size")
		}
	}
	for _, offset := range []int{0, 8, 9} {
		bad := append([]byte(nil), encoded...)
		bad[offset] ^= 1
		if _, err := DecodeCanonicalPruneEffect(bad); err == nil {
			t.Fatal("accepted bad envelope", offset)
		}
	}
	for name, mutate := range map[string]func(*CanonicalPruneEffect){
		"assignment":          func(e *CanonicalPruneEffect) { e.Operation.AssignmentID = types.Hash{} },
		"ticket":              func(e *CanonicalPruneEffect) { e.Operation.TicketID = types.Hash{} },
		"pre-tagged-boundary": func(e *CanonicalPruneEffect) { e.Operation.Boundary.PruneTicketID = e.Operation.TicketID },
		"time-backwards":      func(e *CanonicalPruneEffect) { e.VerifiedAt = 99 },
		"time-expired":        func(e *CanonicalPruneEffect) { e.VerifiedAt = 1000 },
		"report-floor":        func(e *CanonicalPruneEffect) { e.Report.FloorID[0] ^= 1 },
		"previous-zero":       func(e *CanonicalPruneEffect) { e.Report.PreviousFloorID = types.Hash{} },
		"previous-same":       func(e *CanonicalPruneEffect) { e.Report.PreviousFloorID = e.Report.FloorID },
		"removed":             func(e *CanonicalPruneEffect) { e.Report.RemovedNodes = 0 },
		"retained":            func(e *CanonicalPruneEffect) { e.Report.RetainedNodes = 0 },
		"headers":             func(e *CanonicalPruneEffect) { e.Report.ArchivedHeaders++ },
		"added":               func(e *CanonicalPruneEffect) { e.Report.AddedHistoryBytes = 0 },
		"released":            func(e *CanonicalPruneEffect) { e.Report.ReleasedHistoryBytes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := commit.Effect
			mutate(&bad)
			if _, err := bad.CanonicalBytes(); err == nil {
				t.Fatal("encoded invalid effect")
			}
			if _, err := bad.ID(); err == nil {
				t.Fatal("hashed invalid effect")
			}
		})
	}
	legacy, _ := encodeCanonicalFloor(boundary)
	if binary.BigEndian.Uint16(legacy[:2]) != 0 {
		t.Fatal("legacy floor version changed")
	}
	boundary.PruneTicketID = commit.Effect.Operation.TicketID
	tagged, _ := encodeCanonicalFloor(boundary)
	if binary.BigEndian.Uint16(tagged[:2]) != 1 || len(tagged) != len(legacy)+32 {
		t.Fatal("bad ticketed floor format")
	}
	for _, bad := range [][]byte{tagged[:len(tagged)-1], append(tagged, 0), append(append([]byte(nil), tagged[:len(tagged)-32]...), make([]byte, 32)...)} {
		if _, err := decodeCanonicalFloor(bad); err == nil {
			t.Fatal("accepted malformed ticketed floor")
		}
	}
}

func FuzzCanonicalPruneEffect(f *testing.F) {
	// This target checks formats, not persistence. Keep worker setup entirely
	// in memory; the transaction-derived golden record is tested above.
	base := testBase(f, testParameters())
	anchor := cloneTip(base.Tip)
	anchor.ID = types.DomainHash("test/prune-effect/fuzz-anchor")
	anchor.Height++
	anchor.CumulativeWork = []byte{1}
	boundary := canonicalTestFloor(base.Tip.ID, anchor, types.DomainHash("test/prune-effect/fuzz-ancestry"), 2, "fuzz")
	effect := CanonicalPruneEffect{
		Operation: pruneOperation(boundary, "fuzz"), VerifiedAt: 200,
		Report: CanonicalPruneReport{PreviousFloorID: base.Tip.ID, FloorID: anchor.ID,
			RemovedNodes: 1, RetainedNodes: 1, AddedHistoryBytes: 1, ReleasedHistoryBytes: 1},
	}
	encoded, err := effect.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	legacy, _ := encodeCanonicalFloor(boundary)
	f.Add(legacy)
	boundary.PruneTicketID = effect.Operation.TicketID
	tagged, _ := encodeCanonicalFloor(boundary)
	f.Add(tagged)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		effect, err := DecodeCanonicalPruneEffect(input)
		if err == nil {
			encoded, err := effect.CanonicalBytes()
			if err != nil || !bytes.Equal(input, encoded) {
				t.Fatal("noncanonical accepted effect")
			}
			id, err := effect.ID()
			if err != nil || id.IsZero() {
				t.Fatal("valid effect has no commitment")
			}
		}
		floor, err := decodeCanonicalFloor(input)
		if err == nil {
			encoded, err := encodeCanonicalFloor(floor)
			if err != nil || !bytes.Equal(input, encoded) {
				t.Fatal("noncanonical accepted floor")
			}
		}
	})
}

func TestCanonicalPruneEffectResultWaitsForStoreTransition(t *testing.T) {
	store, _, _, _, _, boundary := canonicalAuthorizationFixture(t)
	op := pruneOperation(boundary, "drain")
	committed, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	store.persistence.afterCommitHook = func() { close(committed); <-release }
	type result struct {
		commit CanonicalPruneCommit
		err    error
	}
	returned := make(chan result, 1)
	go func() {
		commit, err := store.PruneCanonicalPrefixOnce(op, func() (uint64, error) { return 200, nil })
		returned <- result{commit, err}
	}()
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("commit not reached")
	}
	select {
	case <-returned:
		t.Fatal("result escaped before memory transition drained")
	default:
	}
	if store.mu.TryRLock() {
		store.mu.RUnlock()
		t.Fatal("commit released guard before memory transition")
	}
	unblock.Do(func() { close(release) })
	select {
	case result := <-returned:
		if result.err != nil || !result.commit.Applied {
			t.Fatal("missing drained result", result.err)
		}
		floor, err := store.CanonicalFloor()
		if err != nil || floor.PruneTicketID != op.TicketID {
			t.Fatal("success preceded coherent floor", err)
		}
		persisted, found, err := store.CanonicalPruneEffect(op.TicketID)
		if err != nil || !found || !equalPruneEffect(persisted, result.commit.Effect) {
			t.Fatal("success preceded coherent result", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("result did not drain")
	}
}
