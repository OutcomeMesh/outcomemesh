package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestCoordinatorOperationGuardDrainsBeforeStop(t *testing.T) {
	c, _, _ := newTestCoordinator(t)
	entry := testEntry(t, testCoordination(t, c).Authority, custodyauthority.Admit, testHash(10), types.Hash{}, types.Hash{})
	commit := appendCoordinated(t, c, entry)
	binding := OperationBinding{AssignmentID: testAssignmentID(t), TicketID: commit.EntryID, ConsumerPublicKey: testPublic(4), OperationID: testHash(10), Purpose: custodyauthority.Audit}
	stop := testEntry(t, commit.Snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(20))
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	injected := errors.New("effect failed after draining")
	go func() {
		returned <- c.WithOperation(t.Context(), binding, func() error { close(entered); <-release; return injected })
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("guard not entered")
	}
	if c.mu.TryLock() {
		c.mu.Unlock()
		t.Fatal("guard released coordinator early")
	}
	stopped := make(chan error, 1)
	go func() { _, err := c.Append(t.Context(), stop); stopped <- err }()
	select {
	case <-stopped:
		t.Fatal("stop crossed live effect")
	default:
	}
	close(release)
	if err := <-returned; !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	snapshot := testCoordination(t, c).Authority
	if snapshot.Phase != custodyauthority.Stopping || snapshot.Pending != 1 {
		t.Fatal("effect error closed ticket")
	}
	if err := c.WithOperation(t.Context(), binding, func() error { return nil }); err != nil {
		t.Fatal("stopping prevented admitted drain", err)
	}
	completion := testEntry(t, snapshot, custodyauthority.Complete, types.Hash{}, commit.EntryID, testHash(30))
	appendCoordinated(t, c, completion)
	if err := c.WithOperation(t.Context(), binding, func() error { t.Error("completed work ran"); return nil }); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal(err)
	}
	retire := testEntry(t, testCoordination(t, c).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, snapshot.StopID)
	appendCoordinated(t, c, retire)
	if err := c.WithOperation(t.Context(), binding, func() error { t.Error("retired work ran"); return nil }); !errors.Is(err, custodyauthority.ErrPhase) {
		t.Fatal(err)
	}
}

func TestCoordinatorOperationGuardRejectsUnconfirmedAndWrongBindings(t *testing.T) {
	c, _, _ := newTestCoordinator(t)
	entry := testEntry(t, testCoordination(t, c).Authority, custodyauthority.Admit, testHash(10), types.Hash{}, types.Hash{})
	commit := appendCoordinated(t, c, entry)
	binding := OperationBinding{AssignmentID: testAssignmentID(t), TicketID: commit.EntryID, ConsumerPublicKey: testPublic(4), OperationID: testHash(10), Purpose: custodyauthority.Audit}
	for name, mutate := range map[string]func(*OperationBinding){
		"assignment": func(b *OperationBinding) { b.AssignmentID[0] ^= 1 }, "ticket": func(b *OperationBinding) { b.TicketID[0] ^= 1 },
		"consumer": func(b *OperationBinding) { b.ConsumerPublicKey = testPublic(2) }, "request": func(b *OperationBinding) { b.OperationID[0] ^= 1 },
		"purpose": func(b *OperationBinding) { b.Purpose = custodyauthority.Prune }, "mask": func(b *OperationBinding) { b.Purpose = custodyauthority.AllPurposes },
	} {
		t.Run(name, func(t *testing.T) {
			bad := binding
			mutate(&bad)
			if err := c.WithOperation(t.Context(), bad, func() error { t.Error("invalid binding ran"); return nil }); err == nil {
				t.Fatal("bad binding accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	c.journal.hooks.at = func(stage string) error {
		if stage == "intent-after-apply" {
			cancel()
		}
		return nil
	}
	stop := testEntry(t, commit.Snapshot, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(20))
	if _, err := c.Append(ctx, stop); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal(err)
	}
	if err := c.WithOperation(t.Context(), binding, func() error { t.Error("uncertain authority ran effect"); return nil }); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal(err)
	}
	c.journal.hooks = storeHooks{}
	if _, err := c.Resume(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := c.WithOperation(ctx, binding, func() error { t.Error("cancelled action ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := c.WithOperation(nil, binding, func() error { return nil }); err == nil {
		t.Fatal("nil context")
	}
	if err := c.WithOperation(t.Context(), binding, nil); err == nil {
		t.Fatal("nil action")
	}
	if err := (*Coordinator)(nil).WithOperation(t.Context(), binding, func() error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	_ = c.Close()
	if err := c.WithOperation(t.Context(), binding, func() error { t.Error("closed guard ran"); return nil }); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
