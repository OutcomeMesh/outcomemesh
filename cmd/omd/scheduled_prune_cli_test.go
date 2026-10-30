package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestScheduledPruneCLIOwnedExecutionLostOutputAndRecovery(t *testing.T) {
	f, cp, _, sources := prepareCustodyScheduleQuorumCLI(t)
	policy := f.inventory.Policy
	v := store.ScheduledPruneInventory{Checkpoint: cp, OriginalPolicy: policy.CheckpointPolicy, ReplicaPolicy: policy.ReplicaPolicy}
	for _, source := range sources {
		aid, _ := pruneExternalID("assignment", source.AssignmentID)
		a, err := loadPruneOfflineAssignment(source.Assignment, aid)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := readRegularArtifact(source.Proof, workarchive.MaximumCustodyScheduleBytes)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := workarchive.DecodeCustodyScheduleProof(raw)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = readRegularArtifact(source.Receipt, workarchive.MaximumScheduledReceiptBytes)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := workarchive.DecodeScheduledReplicaReceipt(raw)
		if err != nil {
			t.Fatal(err)
		}
		v.Replicas = append(v.Replicas, store.ScheduledPruneReplica{Assignment: a, Proof: proof, Receipt: receipt})
	}
	bundle, err := v.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	bid, _ := bundle.ID()
	sid, _ := cp.Statement.ID()
	primaryID, _ := v.Replicas[0].Assignment.ID()
	scopeID, _ := v.Replicas[0].Proof.ID()
	v.Request = store.PruneRequest{AssignmentID: primaryID, ScheduleID: scopeID, ConsumerPublicKey: f.inventory.Request.ConsumerPublicKey, StorageID: f.inventory.Request.StorageID, Boundary: workchain.CanonicalFloor{Pruned: true, RadixActivationHeight: cp.Statement.RadixActivationHeight, BaseID: cp.Statement.BaseID, Anchor: cp.Statement.Anchor, AncestryNodes: cp.Statement.AncestryNodes, AncestryRoot: cp.Statement.AncestryRoot, ManifestID: cp.Statement.ArchiveManifestID, StatementID: sid, AvailabilityID: bid, VerifiedAt: f.inventory.Request.Boundary.VerifiedAt, RetainUntil: f.inventory.Request.Boundary.RetainUntil}}
	rid, err := v.Request.ID()
	if err != nil {
		t.Fatal(err)
	}
	executorPath, executorPins := filepath.Join(t.TempDir(), "executor"), filepath.Join(t.TempDir(), "pins")
	executor, err := store.CreatePinnedPruneExecutor(executorPath, executorPins, v.Replicas[0].Assignment, v.Request, rid)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close()
	snap, err := executor.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v.ExecutorBindingID = snap.Protection.BindingID
	chain, err := workchain.OpenPositionPinnedWithPolicy(f.config.ChainPath, f.config.ChainPinsPath, f.config.Base, f.config.Parameters, f.config.StoragePolicy, v.Request.StorageID)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	review, err := chain.ReviewRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.MigrateRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight, review.ID()); err != nil {
		t.Fatal(err)
	}
	protection, err := chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	v.StoragePairID = protection.PairID
	var roots []scheduledPruneCLISource
	for i, s := range v.Replicas {
		source := sources[i]
		aid, _ := s.Assignment.ID()
		owner, err := store.OpenCoordinator(source.Authority, source.Pins, s.Assignment, aid)
		if err != nil {
			t.Fatal(err)
		}
		current, err := owner.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		draft, err := store.BuildScheduledPruneAdmission(s.Assignment, s.Proof, v.OriginalPolicy, v.Request, current.Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		command, err := draft.Sign(pruneCLIKey(4))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(command, pruneCLIKey(1))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			_, err = executor.Admit(t.Context(), owner, entry)
		} else {
			_, err = owner.Append(t.Context(), entry)
		}
		if err := errors.Join(err, owner.Close()); err != nil {
			t.Fatal(err)
		}
		v.Replicas[i].Admission = entry
		directory := filepath.Join(t.TempDir(), "migrated")
		if _, _, err := workarchive.MigrateRadixArchiveDirectory(f.config.Replicas[i].Directory, directory, policy.Checkpoint, cp, policy.CheckpointPolicy, f.config.Base, f.config.Parameters, workarchive.DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, scheduledPruneCLISource{AssignmentID: aid.String(), Authority: source.Authority, Pins: source.Pins, Journal: source.Journal, Directory: directory})
	}
	if err := errors.Join(executor.Close(), chain.Close()); err != nil {
		t.Fatal(err)
	}
	vid, err := v.ID()
	if err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(t.TempDir(), "inventory")
	if err := store.SaveScheduledPruneInventory(t.Context(), inventoryPath, v, vid); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "sources.json")
	raw, _ := json.Marshal(roots)
	writePruneCLIFile(t, rootPath, raw)
	p := f.config.StoragePolicy
	args := []string{"--inventory", inventoryPath, "--inventory-id", vid.String(), "--data", f.data, "--sources", rootPath, "--executor", executorPath, "--executor-pins", executorPins, "--chain", f.config.ChainPath, "--chain-pins", f.config.ChainPinsPath, "--storage-migration-id", review.ID().String(), "--canonical-retention", strconv.FormatUint(p.CanonicalRetention, 10), "--max-history-bytes", strconv.FormatUint(p.MaxHistoryBytes, 10), "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000"}
	inspect := func() store.ScheduledPruneRuntimeResult {
		t.Helper()
		var out bytes.Buffer
		if err := runScheduledPrune(t.Context(), args, &out); err != nil {
			t.Fatal(err)
		}
		var r store.ScheduledPruneRuntimeResult
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := inspect()
	for _, bad := range [][]byte{[]byte(`null`), []byte(`[]`), append(bytes.Clone(raw), []byte(` {}`)...), bytes.Replace(raw, []byte(`"assignment_id":`), []byte(`"assignment_id":"bad","assignment_id":`), 1)} {
		writePruneCLIFile(t, rootPath, bad)
		if err := runScheduledPrune(t.Context(), args, io.Discard); err == nil {
			t.Fatal("malformed sources accepted")
		}
	}
	writePruneCLIFile(t, rootPath, raw)
	failedOutput := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	execute := append(append([]string(nil), args...), "--mode", "execute", "--expected-review-id", before.Review.ReviewID.String())
	if err := runScheduledPrune(t.Context(), execute, failedOutput); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost output", err)
	}
	after := inspect()
	if after.Review.Executor.Stage != store.PruneSucceeded || after.Review.Executor.Effect == nil {
		t.Fatal("lost output rolled back effect")
	}
	for _, owner := range after.Review.Authorities {
		if owner.Authority.Pending != 2 {
			t.Fatal("CLI reset obligations")
		}
	}
	if err := runScheduledPrune(t.Context(), execute, io.Discard); err == nil {
		t.Fatal("stale reviewed action repeated")
	}
	recover := append(append([]string(nil), args...), "--mode", "recover", "--expected-review-id", after.Review.ReviewID.String())
	var out bytes.Buffer
	if err := runScheduledPrune(t.Context(), recover, &out); err != nil {
		t.Fatal(err)
	}
	var recovered store.ScheduledPruneRuntimeResult
	if err := json.Unmarshal(out.Bytes(), &recovered); err != nil || recovered.Commit == nil || recovered.Commit.Applied {
		t.Fatal("CLI recovery repeated effect", err)
	}
}
