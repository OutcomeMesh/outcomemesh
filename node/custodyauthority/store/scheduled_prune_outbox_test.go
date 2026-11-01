package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
)

func scheduledOutboxVector(t testing.TB) (custodyauthority.Assignment, scheduledwire.Intent) {
	t.Helper()
	v := fixedScheduledPrunePlan(t)
	p, err := DecodeScheduledPrunePlan(v.Plan)
	if err != nil {
		t.Fatal(err)
	}
	e, err := custodyauthority.DecodeEntry(v.Completion)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Replica(e.Command.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := p.Request.ID()
	return a.Assignment, scheduledwire.Intent{ClientPeerID: testHash(1), ServerPeerID: testHash(2), PlanID: v.PlanID, RequestID: rid, ExecutorBindingID: testHash(4), InventoryID: testHash(5), ReviewID: testHash(6), Entry: e}
}

func TestPruneScheduledOutboxFaultsAndOriginalPins(t *testing.T) {
	a, intent := scheduledOutboxVector(t)
	id, _ := intent.ID()
	ack := scheduledwire.Acknowledgement{Nonce: testHash(7), IntentID: id}
	raw, err := scheduledPruneReceipt(id, ack)
	if err != nil || len(raw) != 148 {
		t.Fatal("receipt framing", err)
	}
	if h := types.DomainHash("OMESH/test/scheduled-prune-receipt/v0", raw); h.String() != "b0108451166efcde18c970a6901d90d640f6304609db078e6e9b0ef584784fc3" {
		t.Fatal("receipt vector changed", h)
	}
	for _, stage := range []string{"before-write", "before-file-sync", "file-synced", "before-publish", "after-publish", "directory-synced", "after-apply"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outbox")
			o, err := CreateScheduledPruneOutbox(path, a, intent, id)
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("receipt write interrupted")
			o.hooks.at = func(at string) error {
				if at == "scheduled-outbox-"+stage {
					return fault
				}
				return nil
			}
			if err := o.record(ack); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			if _, err := o.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatal("failed writer stayed usable")
			}
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				o, err = OpenScheduledPruneOutbox(path, a, id)
				if err != nil {
					t.Fatal(err)
				}
				s, err := o.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				published := stage == "after-publish" || stage == "directory-synced" || stage == "after-apply"
				if s.Intent != intent || (s.Acknowledgement != nil) != published {
					t.Fatal("cold open changed evidence")
				}
				if err := o.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := CreateScheduledPruneOutbox(path, a, intent, id); !errors.Is(err, os.ErrExist) {
				t.Fatal("root recreated", err)
			}
			if o, err := OpenScheduledPruneOutbox(path, a, testHash(99)); err == nil {
				o.Close()
				t.Fatal("wrong external intent pin accepted")
			}
		})
	}
	for _, stage := range []string{"before-ready", "ready-file-synced", "ready-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outbox")
			fault := errors.New("initialization interrupted")
			_, err := createScheduledPruneOutbox(path, a, intent, id, storeHooks{at: func(at string) error {
				if at == "scheduled-outbox-"+stage {
					return fault
				}
				return nil
			}})
			if !errors.Is(err, fault) {
				t.Fatal(err)
			}
			o, err := OpenScheduledPruneOutbox(path, a, id)
			if o != nil {
				defer o.Close()
			}
			if (err != nil) != (stage == "before-ready") {
				t.Fatal("partial initialization misclassified", err)
			}
		})
	}
}

func FuzzPruneScheduledDeliveryReceipt(f *testing.F) {
	_, intent := scheduledOutboxVector(f)
	id, _ := intent.ID()
	raw, err := scheduledPruneReceipt(id, scheduledwire.Acknowledgement{Nonce: testHash(7), IntentID: id})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		if ack, err := decodeScheduledPruneReceipt(input, intent); err == nil {
			raw, err := scheduledPruneReceipt(id, ack)
			if err != nil || !bytes.Equal(raw, input) {
				t.Fatal("noncanonical receipt")
			}
		}
	})
}
