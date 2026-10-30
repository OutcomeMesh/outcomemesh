package workchain

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestPruneInspectionReadsOnePositionWithoutMutation(t *testing.T) {
	f := newPositionFixture(t, 7)
	op := f.operation()
	before, err := f.chain.InspectCanonicalPrune(op.TicketID)
	if err != nil || before.Effect != nil {
		t.Fatal("initial observation", err)
	}
	db := positionDatabaseSummary(t, f.chain)
	again, err := f.chain.InspectCanonicalPrune(op.TicketID)
	if err != nil || !reflect.DeepEqual(before, again) || db != positionDatabaseSummary(t, f.chain) {
		t.Fatal("inspection changed database", err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	commit := make(chan error, 1)
	go func() {
		_, err := f.chain.PruneCanonicalPrefixOnce(op, func() (uint64, error) {
			close(entered)
			<-release
			return 200, nil
		})
		commit <- err
	}()
	<-entered
	type inspected struct {
		value CanonicalPruneInspection
		err   error
	}
	read := make(chan inspected, 1)
	go func() { v, err := f.chain.InspectCanonicalPrune(op.TicketID); read <- inspected{v, err} }()
	select {
	case <-read:
		t.Fatal("inspection escaped a running commit")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-commit; err != nil {
		t.Fatal(err)
	}
	after := <-read
	if after.err != nil || after.value.Effect == nil || after.value.Storage.Confirmed.Sequence != before.Storage.Confirmed.Sequence+1 || after.value.Storage.Database != after.value.Storage.Confirmed {
		t.Fatal("mixed result and position", after.err)
	}
	retained := *after.value.Effect
	after.value.Effect.Report.RemovedNodes++
	f.reopen(t)
	cold, err := f.chain.InspectCanonicalPrune(op.TicketID)
	if err != nil || cold.Effect == nil || !equalPruneEffect(*cold.Effect, retained) || cold.Storage != after.value.Storage {
		t.Fatal("detached result or cold observation changed", err)
	}
}

func TestPruneInspectionErrorsNeverMeanAbsence(t *testing.T) {
	for _, kind := range []string{"pending", "corrupt-effect", "replaced-pins", "closed", "memory", "nil", "zero-ticket"} {
		t.Run(kind, func(t *testing.T) {
			f := newPositionFixture(t, 7)
			ticket := f.operation().TicketID
			chain := f.chain
			switch kind {
			case "pending":
				chain.persistence.pins.hook = func(stage string) error {
					if stage == "confirmation-before-temp" {
						return errors.New("lost storage confirmation")
					}
					return nil
				}
				if _, err := chain.PruneCanonicalPrefixOnce(f.operation(), func() (uint64, error) { return 200, nil }); err == nil {
					t.Fatal("missed storage confirmation")
				}
				f.reopen(t)
				chain = f.chain
			case "corrupt-effect":
				if err := chain.persistence.db.Set(workPruneEffectKey(ticket), []byte("damaged"), pebble.Sync); err != nil {
					t.Fatal(err)
				}
			case "replaced-pins":
				if err := os.Rename(filepath.Join(f.pins, "confirmed"), filepath.Join(f.pins, "old-confirmed")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(f.pins, "confirmed"), 0700); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := chain.Close(); err != nil {
					t.Fatal(err)
				}
			case "memory":
				var err error
				chain, err = New(f.base, f.parameters)
				if err != nil {
					t.Fatal(err)
				}
				defer chain.Close()
			case "nil":
				chain = nil
			case "zero-ticket":
				ticket = types.Hash{}
			}
			value, err := chain.InspectCanonicalPrune(ticket)
			if err == nil || !reflect.DeepEqual(value, CanonicalPruneInspection{}) {
				t.Fatal("failed read became an observation", err)
			}
		})
	}
}
