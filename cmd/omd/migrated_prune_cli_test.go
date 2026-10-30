package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type migratedPruneCLIReport struct {
	Result    store.MigratedPruneResult `json:"result"`
	ReviewID  string                    `json:"review_id"`
	Head      string                    `json:"confirmed_head"`
	Sequence  uint64                    `json:"confirmed_sequence"`
	OutcomeID string                    `json:"outcome_id"`
	Kind      string                    `json:"outcome_kind"`
	EntryID   string                    `json:"entry_id"`
}

func migratedCLIRun(t testing.TB, args []string) migratedPruneCLIReport {
	t.Helper()
	var out bytes.Buffer
	if err := runMigratedPruneCLIContext(t.Context(), args, &out); err != nil {
		t.Fatal(args[0], err)
	}
	var r migratedPruneCLIReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestPruneMigratedCLIOriginalOutcomesAndLostOutput(t *testing.T) {
	for _, outcome := range []string{"success", "cancelled", "recover-effect", "cancel-after-migration"} {
		t.Run(outcome, func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, false)
			if outcome == "cancelled" {
				owner, err := store.OpenCoordinator(f.config.Authorities[0].AuthorityPath, f.config.Authorities[0].AuthorityPinsPath, f.assignments[0], f.inventory.Request.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				e, err := store.OpenPinnedPruneExecutor(f.config.ExecutorPath, f.config.ExecutorPinsPath, f.assignments[0], f.inventory.Policy.RequestID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := e.CancelBeforeStart(t.Context(), owner); err != nil {
					t.Fatal(err)
				}
				if err := e.Close(); err != nil {
					t.Fatal(err)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			} else if outcome != "cancel-after-migration" {
				service, err := store.OpenPruneArchiveEffectService(f.config)
				if err != nil {
					t.Fatal(err)
				}
				review, err := service.Review(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				id, _ := review.ID()
				if _, err := service.Execute(t.Context(), id); err != nil {
					t.Fatal(err)
				}
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
			}
			_, cp, _, sources := migratePruneCLIFixtureOwners(t, f)
			chain, err := workchain.OpenPositionPinnedWithPolicy(f.config.ChainPath, f.config.ChainPinsPath, f.config.Base, f.config.Parameters, f.config.StoragePolicy, f.inventory.Request.StorageID)
			if err != nil {
				t.Fatal(err)
			}
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
			common := func(s custodyScheduleQuorumSource) []string {
				return []string{"--inventory", f.config.InventoryPath, "--inventory-id", f.config.InventoryID.String(), "--policy-id", f.config.PolicyID.String(), "--schedule-proof", s.Proof, "--schedule-id", s.ScheduleID}
			}
			owners := func(s custodyScheduleQuorumSource) []string {
				return []string{"--authority", s.Authority, "--authority-pins", s.Pins, "--executor", f.config.ExecutorPath, "--executor-pins", f.config.ExecutorPinsPath}
			}
			if outcome == "cancel-after-migration" {
				args := append(append([]string{migratedPruneOutcomeCommand}, common(sources[0])...), owners(sources[0])...)
				r := migratedCLIRun(t, args)
				if r.OutcomeID != "" {
					t.Fatal("admitted work already has outcome")
				}
				result := migratedCLIRun(t, append(args, "--mode", "cancel-before-start", "--expected-review-id", r.ReviewID))
				if result.Result.Executor.Stage != store.PruneCancelled {
					t.Fatal("cancellation not retained")
				}
			}
			if outcome == "recover-effect" {
				// The owned CLI also verifies a historical retry against the migrated pair;
				// fault-injected Started->Succeeded recovery is covered at the storage layer.
				args := append(append([]string{migratedPruneOutcomeCommand}, common(sources[0])...), owners(sources[0])...)
				args = append(args, "--data", f.data, "--chain", f.config.ChainPath, "--chain-pins", f.config.ChainPinsPath, "--storage-migration-id", migration.ID().String(), "--max-history-bytes", strconv.FormatUint(f.config.StoragePolicy.MaxHistoryBytes, 10), "--canonical-retention", strconv.FormatUint(f.config.StoragePolicy.CanonicalRetention, 10))
				r := migratedCLIRun(t, args)
				after := migratedCLIRun(t, append(args, "--mode", "recover-effect", "--expected-review-id", r.ReviewID))
				if after.Result.Recovered == nil || after.Result.Recovered.Applied {
					t.Fatal("CLI repeated deletion")
				}
			}
			for _, s := range sources {
				args := append(append([]string{migratedPruneOutcomeCommand}, common(s)...), owners(s)...)
				r := migratedCLIRun(t, args)
				before := r.Result.Review.Authority.Authority
				if before.Pending != 1 || r.OutcomeID == "" {
					t.Fatal("missing original outcome or ticket")
				}
				file := filepath.Join(t.TempDir(), "outcome")
				publish := append(append([]string(nil), args...), "--mode", "publish", "--expected-review-id", r.ReviewID, "--out", file)
				lost := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
				if err := runMigratedPruneCLIContext(t.Context(), publish, lost); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
				migratedCLIRun(t, publish)
				evidence := []string{"--outcome", file, "--outcome-id", r.OutcomeID, "--outcome-kind", r.Kind}
				sign := append(append([]string{migratedPruneSignCommand}, common(s)...), evidence...)
				sign = append(sign, "--expected-sequence", strconv.FormatUint(r.Sequence, 10), "--expected-head", r.Head)
				sr := migratedCLIRun(t, sign)
				root := t.TempDir()
				consumer, authority := filepath.Join(root, "consumer"), filepath.Join(root, "authority")
				writePruneCLIFile(t, consumer, pruneCLIKey(4).Seed())
				writePruneCLIFile(t, authority, pruneCLIKey(1).Seed())
				command, entry := filepath.Join(root, "command"), filepath.Join(root, "entry")
				wrong := append(append([]string(nil), sign...), "--mode", "sign", "--expected-review-id", (types.Hash{1}).String(), "--consumer-key", filepath.Join(root, "absent"), "--out", command)
				if err := runMigratedPruneCLIContext(t.Context(), wrong, io.Discard); !errors.Is(err, custodyauthority.ErrPruneReview) {
					t.Fatal("wrong review reached key", err)
				}
				migratedCLIRun(t, append(append([]string(nil), sign...), "--mode", "sign", "--expected-review-id", sr.ReviewID, "--consumer-key", consumer, "--out", command))
				cosign := append([]string(nil), sign...)
				cosign[0] = migratedPruneCosignCommand
				cosign = append(cosign, "--command", command)
				cr := migratedCLIRun(t, cosign)
				cr = migratedCLIRun(t, append(cosign, "--mode", "sign", "--expected-review-id", cr.ReviewID, "--authority-key", authority, "--out", entry))
				apply := append(append([]string{migratedPruneApplyCommand}, common(s)...), owners(s)...)
				apply = append(apply, evidence...)
				apply = append(apply, "--entry", entry, "--entry-id", cr.EntryID)
				ar := migratedCLIRun(t, apply)
				if err := runMigratedPruneCLIContext(t.Context(), append(append([]string(nil), apply...), "--mode", "apply", "--expected-review-id", ar.ReviewID), lost); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
				ar = migratedCLIRun(t, apply)
				after := ar.Result.Review.Authority.Authority
				if !ar.Result.Review.AlreadyApplied || after.Pending != 0 || len(after.Operations) != 1 || after.Operations[0].TicketID != before.Operations[0].TicketID || after.Operations[0].OperationID != before.Operations[0].OperationID {
					t.Fatal("CLI reset old accounting")
				}
				done := migratedCLIRun(t, append(apply, "--mode", "apply", "--expected-review-id", ar.ReviewID))
				if done.Result.Commit.Appended || !reflect.DeepEqual(done.Result.Commit.Snapshot, after) {
					t.Fatal("historical retry changed accounting")
				}
				for _, extra := range [][]string{{"--consumer-key", ""}, {"--out", ""}, {"--mode", "execute"}, {"--mode", "review", "--mode", "review"}} {
					if err := runMigratedPruneCLIContext(t.Context(), append(append([]string(nil), args...), extra...), io.Discard); err == nil {
						t.Fatal("ambiguous flags accepted", extra)
					}
				}
			}
		})
	}
}
