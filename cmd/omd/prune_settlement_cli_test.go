package main

import (
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestPruneSettlementCLIEntireObservedLifecycle(t *testing.T) {
	scheduledPruneCLILifecycle(t, false, true, false, true)
}

// Assemble the documented confirmed start as a CLI decoding fixture, obtain a
// real witness claim, and commit the real storage effect without sealing it.
// The actual owner publication/kill sequence is covered by store process tests.
func retainScheduledCLIObservedEffect(t testing.TB, f *pruneEffectCLIFixture, v store.ScheduledPruneInventory, executor, pins string, migration types.Hash, fenceArgs []string) {
	t.Helper()
	rid, _ := v.Request.ID()
	primary := v.Replicas[0]
	for _, s := range v.Replicas {
		id, _ := s.Assignment.ID()
		if id == v.Request.AssignmentID {
			primary = s
		}
	}
	e, err := store.OpenPinnedPruneExecutor(executor, pins, primary.Assignment, rid)
	if err != nil {
		t.Fatal(err)
	}
	state, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	ticket, _ := primary.Admission.ID()
	iid, _ := v.ID()
	op := workchain.CanonicalPruneOperation{AssignmentID: v.Request.AssignmentID, TicketID: ticket, StorageID: v.Request.StorageID, ScheduleID: v.Request.ScheduleID, Boundary: v.Request.Boundary}
	operation, _ := op.FenceOperationID()
	session, err := prunefence.NewSession(*v.FencePolicy, prunefence.Binding{RequestID: rid, AssignmentID: v.Request.AssignmentID, OperationID: operation, InventoryID: iid, ExecutorBindingID: v.ExecutorBindingID, StoragePairID: v.StoragePairID})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	candidate, _ := session.Candidate()
	scope, draft, _ := candidate.Draft()
	collect, closeNetwork, err := openPruneFenceCollector(t.Context(), v, fenceArgs[1], fenceArgs[3], fenceArgs[5], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNetwork()
	q, err := collect(t.Context(), scope, draft)
	if err != nil {
		t.Fatal(err)
	}
	permit, claim, err := session.Authorize(q)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := candidate.CanonicalBytes()
	writePruneCLIFile(t, filepath.Join(executor, "fence", "candidate"), cb)
	proof, _ := claim.CanonicalBytes()
	raw := append([]byte("OMCPSTRT\x00\x02"), proof...)
	head := types.DomainHash("OMESH/custody-prune/position/id/v0", state.Protection.Confirmed.HeadID[:], []byte{byte(store.PruneStarted)}, raw)
	confirmation := append([]byte("OMCPPOSN\x00\x00"), rid[:]...)
	confirmation = append(confirmation, byte(store.PruneStarted))
	confirmation = append(confirmation, head[:]...)
	writePruneCLIFile(t, filepath.Join(pins, "intents", "02-started.omcps"), raw)
	writePruneCLIFile(t, filepath.Join(executor, "records", "02-started.omcps"), raw)
	writePruneCLIFile(t, filepath.Join(pins, "confirmed", "02.omcpp"), confirmation)
	parameters := f.config.Parameters
	parameters.RadixActivationHeight = v.Request.Boundary.RadixActivationHeight
	chain, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(f.config.ChainPath, f.config.ChainPinsPath, f.config.Base, parameters, f.config.StoragePolicy, v.Request.StorageID, migration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.PruneCanonicalPrefixFenced(op, func() (uint64, error) { return v.Request.Boundary.VerifiedAt, nil }, permit); err != nil {
		t.Fatal(err)
	}
	if err := chain.Close(); err != nil {
		t.Fatal(err)
	}
	// Deliberately no Permit.Seal: neither memory nor disk holds a signed result.
}
func settlePruneCLI(t testing.TB, outcomeArgs, storageArgs []string, planPath string, planID types.Hash, inventoryPath string, inventoryID types.Hash) {
	t.Helper()
	base := append(append([]string(nil), outcomeArgs...), storageArgs...)
	var prepared struct {
		store.ScheduledPruneCommandResult
		ProposalID string `json:"proposal_id"`
	}
	scheduledCLIRun(t, append(base, "--mode", "review-settlement"), &prepared)
	if prepared.Executor.Stage != store.PruneStarted || prepared.Proposal == nil {
		t.Fatal("missing observed proposal")
	}
	proposalPath := filepath.Join(t.TempDir(), "proposal")
	args := append(append([]string(nil), base...), "--mode", "prepare-settlement", "--expected-review-id", prepared.Review.ReviewID.String(), "--out", proposalPath)
	scheduledCLIRun(t, args, &prepared)
	pid := prepared.ProposalID
	for _, v := range []struct {
		role string
		seed byte
	}{{"owner", 4}, {"controller", 1}} {
		signArgs := []string{pruneSettlementCommand, "--plan", planPath, "--plan-id", planID.String(), "--inventory", inventoryPath, "--inventory-id", inventoryID.String(), "--proposal", proposalPath, "--proposal-id", pid, "--role", v.role}
		var report struct {
			Review   string `json:"review_id"`
			Proposal string `json:"proposal_id"`
		}
		scheduledCLIRun(t, signArgs, &report)
		reviewID := report.Review
		key, out := filepath.Join(t.TempDir(), "seed"), filepath.Join(t.TempDir(), "signed")
		writePruneCLIFile(t, key, pruneCLIKey(v.seed).Seed())
		scheduledCLIRun(t, append(signArgs, "--mode", "sign", "--key", key, "--expected-review-id", reviewID, "--out", out), &report)
		proposalPath, pid = out, report.Proposal
	}
	network := preparePruneFenceCLINetwork(t, planPath, planID, pruneSettlementScopeCommand)
	network[2] = "--controller-key"
	writePruneCLIFile(t, network[3], pruneCLIKey(1).Seed())
	certPath := filepath.Join(t.TempDir(), "certificate")
	collect := []string{pruneSettlementCommand, "--mode", "collect", "--plan", planPath, "--plan-id", planID.String(), "--inventory", inventoryPath, "--inventory-id", inventoryID.String(), "--proposal", proposalPath, "--proposal-id", pid, "--out", certPath}
	collect = append(collect, network...)
	var certificate struct {
		ID string `json:"certificate_id"`
	}
	fail := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runScheduledPruneOperator(t.Context(), collect, fail); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost certificate output", err)
	}
	scheduledCLIRun(t, collect, &certificate)
	verify := []string{pruneSettlementCommand, "--mode", "verify", "--plan", planPath, "--plan-id", planID.String(), "--inventory", inventoryPath, "--inventory-id", inventoryID.String(), "--proposal", proposalPath, "--proposal-id", pid, "--certificate", certPath, "--certificate-id", certificate.ID}
	scheduledCLIRun(t, verify, nil)
	apply := append(append([]string(nil), base...), "--settlement-certificate", certPath, "--certificate-id", certificate.ID)
	var review store.ScheduledPruneCommandResult
	scheduledCLIRun(t, apply, &review)
	if err := runScheduledPruneOperator(t.Context(), append(apply, "--mode", "settle-effect", "--expected-review-id", review.Review.ReviewID.String()), fail); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost settlement output", err)
	}
	var after store.ScheduledPruneCommandResult
	scheduledCLIRun(t, apply, &after)
	if after.Executor.FenceResult != nil || after.Executor.FenceSettlement == nil || after.Executor.Stage != store.PruneSucceeded || after.Review.Authority.Authority.Pending != review.Review.Authority.Authority.Pending {
		t.Fatal("settlement manufactured signature or released ticket")
	}
	scheduledCLIRun(t, append(apply, "--mode", "settle-effect", "--expected-review-id", after.Review.ReviewID.String()), nil)
}
