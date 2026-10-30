package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type pruneObservationCLIReport struct {
	ID          string                         `json:"observation_id"`
	Review      string                         `json:"review_id"`
	Status      string                         `json:"record_status"`
	Published   bool                           `json:"published"`
	Observation store.MigratedPruneObservation `json:"observation"`
}

func runPruneObservationCLI(t testing.TB, args []string) pruneObservationCLIReport {
	t.Helper()
	var out bytes.Buffer
	if err := runMigratedPruneCLIContext(t.Context(), args, &out); err != nil {
		t.Fatal(err)
	}
	var r pruneObservationCLIReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// Construct a confirmed version-1 start using the documented on-disk encoding.
// This tests CLI ownership/decoding, not the original publication sequence;
// interrupted real execution and process kills are exercised in store tests.
func retainPruneCLIStart(t testing.TB, f *pruneEffectCLIFixture) {
	t.Helper()
	e := f.executor(t)
	s, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	ticket, err := s.Admission.ID()
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte("OMCPSTRT\x00\x01"), s.RequestID[:]...)
	raw = append(raw, ticket[:]...)
	raw = append(raw, f.config.InventoryID[:]...)
	head := types.DomainHash("OMESH/custody-prune/position/id/v0", s.Protection.Confirmed.HeadID[:], []byte{byte(store.PruneStarted)}, raw)
	confirmation := append([]byte("OMCPPOSN\x00\x00"), s.RequestID[:]...)
	confirmation = append(confirmation, byte(store.PruneStarted))
	confirmation = append(confirmation, head[:]...)
	writePruneCLIFile(t, filepath.Join(f.config.ExecutorPinsPath, "intents", "02-started.omcps"), raw)
	writePruneCLIFile(t, filepath.Join(f.config.ExecutorPath, "records", "02-started.omcps"), raw)
	writePruneCLIFile(t, filepath.Join(f.config.ExecutorPinsPath, "confirmed", "02.omcpp"), confirmation)
	e = f.executor(t)
	s, err = e.Snapshot()
	if err != nil || s.Stage != store.PruneStarted || s.Protection.Pending != nil {
		t.Fatal("invalid start fixture", err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPruneMigratedObservationCLI(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(strconv.FormatBool(present), func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, false)
			retainPruneCLIStart(t, f)
			if present {
				chain := f.chain(t)
				ticket, _ := f.admissions[0].ID()
				r := f.inventory.Request
				if _, err := chain.PruneCanonicalPrefixOnce(workchain.CanonicalPruneOperation{AssignmentID: r.AssignmentID, TicketID: ticket, StorageID: r.StorageID, Boundary: r.Boundary}, func() (uint64, error) { return r.Boundary.VerifiedAt, nil }); err != nil {
					t.Fatal(err)
				}
				if err := chain.Close(); err != nil {
					t.Fatal(err)
				}
			}
			_, cp, _, sources := migratePruneCLIFixtureOwners(t, f)
			chain := f.chain(t)
			migration, err := chain.ReviewRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := chain.MigrateRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight, migration.ID()); err != nil {
				t.Fatal(err)
			}
			if err := chain.Close(); err != nil {
				t.Fatal(err)
			}
			s := sources[0]
			common := []string{migratedPruneObservationCommand, "--inventory", f.config.InventoryPath, "--inventory-id", f.config.InventoryID.String(), "--policy-id", f.config.PolicyID.String(), "--schedule-proof", s.Proof, "--schedule-id", s.ScheduleID, "--storage-migration-id", migration.ID().String()}
			args := append(append([]string(nil), common...), "--authority", s.Authority, "--authority-pins", s.Pins, "--executor", f.config.ExecutorPath, "--executor-pins", f.config.ExecutorPinsPath, "--data", f.data, "--chain", f.config.ChainPath, "--chain-pins", f.config.ChainPinsPath, "--max-history-bytes", strconv.FormatUint(f.config.StoragePolicy.MaxHistoryBytes, 10), "--canonical-retention", strconv.FormatUint(f.config.StoragePolicy.CanonicalRetention, 10))
			r := runPruneObservationCLI(t, args)
			if r.ID == "" || r.Review == "" || (r.Status == "matching-effect-retained") != present || r.Published {
				t.Fatal("wrong report", r.Status)
			}
			path := filepath.Join(t.TempDir(), "observation")
			publish := append(append([]string(nil), args...), "--mode", "publish", "--expected-review-id", r.Review, "--out", path)
			lost := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
			if err := runMigratedPruneCLIContext(t.Context(), publish, lost); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			p := runPruneObservationCLI(t, publish)
			if !p.Published || p.ID != r.ID {
				t.Fatal("lost output changed evidence")
			}
			if after := runPruneObservationCLI(t, args); !reflect.DeepEqual(r, after) {
				t.Fatal("publication changed owners")
			}
			offline := append(append([]string(nil), common...), "--mode", "verify", "--observation", path, "--observation-id", r.ID)
			if err := os.Rename(f.config.ExecutorPath, f.config.ExecutorPath+"-offline"); err != nil {
				t.Fatal(err)
			}
			v := runPruneObservationCLI(t, offline)
			if v.ID != r.ID || v.Review != "" || v.Published {
				t.Fatal("offline verification implied live inspection")
			}
			if err := runMigratedPruneCLIContext(t.Context(), args, io.Discard); err == nil {
				t.Fatal("missing owner accepted")
			}
			if err := os.Rename(f.config.ExecutorPath+"-offline", f.config.ExecutorPath); err != nil {
				t.Fatal(err)
			}
			wrong := append(append([]string(nil), args...), "--mode", "publish", "--expected-review-id", (types.Hash{1}).String(), "--out", filepath.Join(t.TempDir(), "wrong"))
			if err := runMigratedPruneCLIContext(t.Context(), wrong, io.Discard); !errors.Is(err, store.ErrPruneRecoveryReview) {
				t.Fatal("stale review accepted", err)
			}
			for _, extra := range [][]string{{"--mode", "execute"}, {"--mode", "recover-effect"}, {"--consumer-key", ""}, {"--outcome-kind", "effect"}, {"--observation", path}, {"--mode", "review", "--mode", "review"}} {
				if err := runMigratedPruneCLIContext(t.Context(), append(append([]string(nil), args...), extra...), io.Discard); err == nil {
					t.Fatal("ignored flag accepted", extra)
				}
			}
			if err := runMigratedPruneCLIContext(t.Context(), append(append([]string(nil), offline...), "--chain", ""), io.Discard); err == nil {
				t.Fatal("offline verifier accepted owner argument")
			}
			for _, dest := range []string{filepath.Join(f.data, "observation"), filepath.Join(f.config.ChainPath, "observation"), f.config.InventoryPath} {
				bad := append(append([]string(nil), args...), "--mode", "publish", "--expected-review-id", r.Review, "--out", dest)
				if err := runMigratedPruneCLIContext(t.Context(), bad, io.Discard); err == nil {
					t.Fatal("output overlapped original input")
				}
			}
		})
	}
}
