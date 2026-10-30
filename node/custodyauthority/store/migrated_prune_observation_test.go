package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestPruneMigratedObservationRequiresCurrentOpenOwner(t *testing.T) {
	for _, pending := range []bool{false, true} {
		_, configs := migratedPruneFixture(t, "prune-before-effect")
		c := configs[0]
		before, err := InspectMigratedPrune(t.Context(), c)
		if err != nil {
			t.Fatal(err)
		}
		v, err := LoadMigratedPruneContext(c)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := v.bindings()
		owner, err := OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, b.primary, v.Proof.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		p := before.Observation.Authority
		draft := custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, AssignmentID: v.Proof.AssignmentID, ScheduleID: v.ScheduleID, ExpectedSequence: p.Sequence, ExpectedHead: p.HeadID, Kind: custodyauthority.Stop, EvidenceID: testHash(91), ActorPublicKey: b.primary.AuthorityPublicKey}
		cmd, err := draft.Sign(testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(cmd, testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		fault := errors.New("stop intent interrupted")
		if pending {
			setCoordinatorRuntimeHooks(owner, storeHooks{at: func(stage string) error {
				if stage == "intent-after-publish" {
					return fault
				}
				return nil
			}})
		}
		_, err = owner.Append(t.Context(), entry)
		if (pending && !errors.Is(err, fault)) || (!pending && err != nil) {
			t.Fatal("stop", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		after, err := InspectMigratedPrune(t.Context(), c)
		if pending {
			if err == nil || after.Observation != nil {
				t.Fatal("pending authority accepted")
			}
		} else if err != nil || after.Observation.AuthorityPhase != custodyauthority.Stopping || after.Review.ReviewID == before.Review.ReviewID || after.Observation.ExecutorHeadID != before.Observation.ExecutorHeadID {
			t.Fatal("stopping observation reused old review or reset start", err)
		}
	}
	_, configs := migratedPruneFixture(t, "prune-after-effect")
	c := configs[0]
	r, err := InspectMigratedPrune(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := LoadMigratedPruneContext(c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := v.bindings()
	o := MigratedPruneOutcome{Effect: r.Observation.Effect}
	draft, err := BuildMigratedPruneCompletion(v, o, r.Observation.Authority)
	if err != nil {
		t.Fatal(err)
	}
	entry := managedCommandApplyTestSign(t, draft)
	completion := c
	completion.Storage = nil
	completion.EntryID, _ = entry.ID()
	completion.OutcomeID, _ = o.EvidenceID(v)
	completion.OutcomeKind = "effect"
	completion.EntryPath = filepath.Join(t.TempDir(), "entry")
	completion.OutcomePath = filepath.Join(t.TempDir(), "effect")
	raw, _ := entry.CanonicalBytes()
	writeTestFile(t, completion.EntryPath, raw)
	raw, _ = o.Artifact()
	writeTestFile(t, completion.OutcomePath, raw)
	if _, err := RunMigratedPrune(t.Context(), completion, "review", types.Hash{}); err == nil {
		t.Fatal("observation bypassed executor result confirmation")
	}
	// A raw trusted owner can accept a co-signed entry. Inspection must still
	// reject the now-closed ticket instead of describing it as held work.
	owner, err := OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, b.primary, v.Proof.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Append(t.Context(), entry); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := InspectMigratedPrune(t.Context(), c); err == nil || result.Observation != nil {
		t.Fatal("completed ticket observed as unresolved")
	}
}

func TestPruneMigratedObservationKeepsUnknownWorkHeld(t *testing.T) {
	for _, stage := range []string{"prune-before-effect", "prune-after-effect"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := migratedPruneFixture(t, stage)
			c := configs[0]
			before := migratedPruneReview(t, c)
			observed, err := InspectMigratedPrune(t.Context(), c)
			if err != nil || observed.Observation == nil {
				t.Fatal("capture", err)
			}
			o := *observed.Observation
			if (o.Effect != nil) != (stage == "prune-after-effect") || observed.Executor.Stage != PruneStarted || observed.Review.Authority.Authority.Pending != 1 || observed.Commit != nil || observed.Recovered != nil {
				t.Fatal("observation resolved work")
			}
			if observed.Review.ReviewID == before.Review.ReviewID {
				t.Fatal("ordinary review reused as observation review")
			}
			if after := migratedPruneReview(t, c); !reflect.DeepEqual(before, after) {
				t.Fatal("observation changed originals")
			}
			again, err := InspectMigratedPrune(t.Context(), c)
			if err != nil || !reflect.DeepEqual(observed, again) {
				t.Fatal("cold observation changed", err)
			}
			raw, err := o.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePruneCancellation(raw); err == nil {
				t.Fatal("observation became cancellation")
			}
			if _, err := workchain.DecodeCanonicalPruneEffect(raw); err == nil {
				t.Fatal("observation became storage effect")
			}
			v, err := LoadMigratedPruneContext(c)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := o.ID()
			path := filepath.Join(t.TempDir(), "observation")
			writeTestFile(t, path, raw)
			loaded, err := LoadMigratedPruneObservation(path, id, v, c.Storage.MigrationID)
			if err != nil || !reflect.DeepEqual(o, loaded) {
				t.Fatal("offline verification", err)
			}
			if _, err := LoadMigratedPruneObservation(path, types.Hash{1}, v, c.Storage.MigrationID); err == nil {
				t.Fatal("wrong content pin accepted")
			}
			if _, err := LoadMigratedPruneObservation(path, id, v, types.Hash{1}); err == nil {
				t.Fatal("wrong migration accepted")
			}
			if _, err := BuildMigratedPruneCompletion(v, MigratedPruneOutcome{}, o.Authority); err == nil {
				t.Fatal("empty observation used as terminal evidence")
			}
			_, err = RunMigratedPrune(t.Context(), c, "recover-effect", before.Review.ReviewID)
			if stage == "prune-before-effect" {
				if !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("missing effect resolved", err)
				}
				if after := migratedPruneReview(t, c); !reflect.DeepEqual(before, after) {
					t.Fatal("unknown work changed")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := InspectMigratedPrune(t.Context(), c); err == nil {
					t.Fatal("terminal executor accepted as unknown")
				}
				if _, err := LoadMigratedPruneObservation(path, id, v, c.Storage.MigrationID); err != nil {
					t.Fatal("historical observation stopped verifying", err)
				}
			}
		})
	}
}

func TestPruneMigratedObservationRefusesIneligibleOrSubstitutedState(t *testing.T) {
	for _, stage := range []string{"admitted", "success", "cancelled", "pins-start-intent-after-publish", "pins-result-confirm-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			_, configs := migratedPruneFixture(t, stage)
			c := configs[0]
			before := migratedPruneReview(t, c)
			result, err := InspectMigratedPrune(t.Context(), c)
			if err == nil || result.Observation != nil {
				t.Fatal("ineligible state observed", err)
			}
			if after := migratedPruneReview(t, c); !reflect.DeepEqual(before, after) {
				t.Fatal("rejection changed owners")
			}
		})
	}
	_, configs := migratedPruneFixture(t, "prune-before-effect")
	c := configs[0]
	before := migratedPruneReview(t, c)
	for _, kind := range []string{"secondary", "no-storage", "migration", "inventory", "scope", "missing-storage", "overlap"} {
		t.Run(kind, func(t *testing.T) {
			bad := c
			s := *c.Storage
			bad.Storage = &s
			switch kind {
			case "secondary":
				bad = configs[1]
			case "no-storage":
				bad.Storage = nil
			case "migration":
				bad.Storage.MigrationID[0] ^= 1
			case "inventory":
				bad.InventoryID[0] ^= 1
			case "scope":
				bad.ScheduleID[0] ^= 1
			case "missing-storage":
				bad.Storage.ChainPath = filepath.Join(t.TempDir(), "absent")
			case "overlap":
				bad.Storage.ChainPinsPath = bad.ExecutorPinsPath
			}
			result, err := InspectMigratedPrune(t.Context(), bad)
			if err == nil || result.Observation != nil {
				t.Fatal("substitution accepted", err)
			}
			if after := migratedPruneReview(t, c); !reflect.DeepEqual(before, after) {
				t.Fatal("rejection changed originals")
			}
		})
	}
}

func TestPruneMigratedObservationInterruptedReadPublishesNothing(t *testing.T) {
	for _, boundary := range []string{"prune-observation-before-read", "prune-observation-after-read"} {
		for _, kind := range []string{"cancel", "replace-owner", "fail"} {
			t.Run(boundary+"/"+kind, func(t *testing.T) {
				_, configs := migratedPruneFixture(t, "prune-before-effect")
				c := configs[0]
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				hit := false
				result, err := runMigratedPruneOwned(ctx, c, "review", types.Hash{}, storeHooks{at: func(stage string) error {
					if stage != boundary {
						return nil
					}
					hit = true
					switch kind {
					case "cancel":
						cancel()
					case "replace-owner":
						if err := os.Rename(c.ExecutorPath, c.ExecutorPath+"-moved"); err != nil {
							return err
						}
						return os.Mkdir(c.ExecutorPath, 0700)
					case "fail":
						return errors.New("read interrupted")
					}
					return nil
				}}, true)
				if !hit || err == nil || result.Observation != nil {
					t.Fatal("interrupted observation escaped", hit, err)
				}
			})
		}
	}
}

func TestPruneMigratedObservationContextRejectsChangedFields(t *testing.T) {
	_, configs := migratedPruneFixture(t, "prune-after-effect")
	c := configs[0]
	r, err := InspectMigratedPrune(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := LoadMigratedPruneContext(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*MigratedPruneObservation){
		func(o *MigratedPruneObservation) { o.InventoryID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.PolicyID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.ScheduleID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.TicketID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.RequestID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.ExecutorHeadID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.ExecutorBindingID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.StorageID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.StoragePairID[0] ^= 1 },
		func(o *MigratedPruneObservation) { o.RadixActivationHeight++ },
		func(o *MigratedPruneObservation) { o.Authority.Sequence = 1 },
		func(o *MigratedPruneObservation) { o.Authority.HeadID = o.TicketID },
		func(o *MigratedPruneObservation) { o.Effect.Operation.Boundary.AvailabilityID[0] ^= 1 },
	} {
		o := *r.Observation
		e := *o.Effect
		o.Effect = &e
		mutate(&o)
		if err := o.Verify(v, c.Storage.MigrationID); err == nil {
			t.Fatal("changed context accepted")
		}
	}
	raw, _ := r.Observation.CanonicalBytes()
	for n := range len(raw) {
		if _, err := DecodeMigratedPruneObservation(raw[:n]); err == nil {
			t.Fatal("truncated observation accepted", n)
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), bytes.Repeat([]byte{1}, MaximumMigratedPruneObservationBytes+1)} {
		if _, err := DecodeMigratedPruneObservation(bad); err == nil {
			t.Fatal("invalid length accepted")
		}
	}
}
