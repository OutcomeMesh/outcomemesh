//go:build linux || darwin

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func TestPruneServiceSettlementAfterLostFinalSignature(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("filesystem denial requires an unprivileged owner; Linux UID campaign exercises this path")
	}
	f := preparePruneServiceOwnerCLI(t)
	before := pruneFailureAuthorities(t, f)
	owner, pos := pruneFailureExecute(t, f, "result-write")
	state := pruneFailureSnapshot(t, f)
	if state.Stage != store.PruneStarted || state.FenceClaim == nil || state.FenceResult != nil || state.FenceSettlement != nil || state.Protection.Pending != nil {
		t.Fatal("unexpected original state after result write failure")
	}
	if _, ok := pruneFailureEffect(t, f); !ok {
		t.Fatal("fault happened before deletion")
	}
	if _, err := owner.Recover(t.Context(), f.request); err == nil {
		t.Fatal("bare effect recreated final signature")
	}
	owner.Close()
	response := settlePruneServiceFixture(t, f, pos)
	if response.Result != nil || response.Settlement == nil {
		t.Fatal("settlement confused with live result")
	}
	if !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) {
		t.Fatal("settlement changed pending or spent accounting")
	}
	completePruneServiceSettlement(t, f, response, before)
}

func preparePruneServiceSettlementCLI(t testing.TB, f *pruneServiceOwnerCLIFixture, pos wire.Position) (apply, certified []string, out string) {
	t.Helper()
	did, _ := f.descriptor.ID()
	in := pruneFailureInput(t, f)
	cursor := filepath.Join(f.public, "settlement.position")
	pruneServiceCLIJSON(t, cursor, pos)
	base := []string{pruneServiceCommand, "--root", f.root, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", cursor, "--request", f.requestPath, "--plan", in.PlanPath, "--plan-id", in.PlanID.String()}
	proposalPath, reviewOut := filepath.Join(f.public, "settlement.proposal"), filepath.Join(f.public, "settlement.review")
	args := append(append([]string(nil), base...), "--action", "settlement-review", "--out", reviewOut, "--proposal-out", proposalPath)
	pruneServiceCLIRun(t, args)
	prepared := pruneReadSettlementReview(t, reviewOut)
	if prepared.Proposal == nil {
		t.Fatal("no actual effect proposal")
	}
	proposalID, _ := prepared.Proposal.ID()
	pid := proposalID.String()
	inventoryPath, iid := f.config.Runtime.InventoryPath, f.config.Runtime.InventoryID
	// Existing offline CLI signs each role separately; the owner loads neither seed.
	for _, v := range []struct {
		role string
		seed byte
	}{{"owner", 4}, {"controller", 1}} {
		signArgs := []string{pruneSettlementCommand, "--plan", in.PlanPath, "--plan-id", in.PlanID.String(), "--inventory", inventoryPath, "--inventory-id", iid.String(), "--proposal", proposalPath, "--proposal-id", pid, "--role", v.role}
		var r struct {
			Review   string `json:"review_id"`
			Proposal string `json:"proposal_id"`
		}
		scheduledCLIRun(t, signArgs, &r)
		key, out := filepath.Join(f.public, "settlement-"+v.role+".seed"), filepath.Join(f.public, "settlement-"+v.role+".proposal")
		writePruneCLIFile(t, key, pruneCLIKey(v.seed).Seed())
		scheduledCLIRun(t, append(signArgs, "--mode", "sign", "--key", key, "--expected-review-id", r.Review, "--out", out), &r)
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		proposalPath, pid = out, r.Proposal
	}
	network := preparePruneFenceCLINetwork(t, in.PlanPath, in.PlanID, pruneSettlementScopeCommand)
	network[2] = "--controller-key"
	writePruneCLIFile(t, network[3], pruneCLIKey(1).Seed())
	cert := filepath.Join(f.public, "settlement.decision")
	collect := []string{pruneSettlementCommand, "--mode", "collect", "--plan", in.PlanPath, "--plan-id", in.PlanID.String(), "--inventory", inventoryPath, "--inventory-id", iid.String(), "--proposal", proposalPath, "--proposal-id", pid, "--out", cert}
	collect = append(collect, network...)
	var decision struct {
		ID string `json:"certificate_id"`
	}
	scheduledCLIRun(t, collect, &decision)
	certified = append(append([]string(nil), base...), "--settlement", cert, "--settlement-id", decision.ID)
	reviewedPath := filepath.Join(f.public, "certified.review")
	pruneServiceCLIRun(t, append(append([]string(nil), certified...), "--action", "settlement-review", "--out", reviewedPath))
	reviewed := pruneReadSettlementReview(t, reviewedPath)
	out = filepath.Join(f.public, "settled.response")
	apply = append(append([]string(nil), certified...), "--action", "settle", "--settlement-review-id", reviewed.Review.ReviewID.String(), "--out", out)
	return apply, certified, out
}

func settlePruneServiceFixture(t testing.TB, f *pruneServiceOwnerCLIFixture, pos wire.Position) wire.Response {
	t.Helper()
	apply, certified, out := preparePruneServiceSettlementCLI(t, f, pos)
	checkPruneServiceSettlementRejections(t, f, pos)
	generic := pruneServiceCLIReview(t, apply)
	fail := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runPruneServiceCLIContext(t.Context(), append(append([]string(nil), apply...), "--mode", "run", "--expected-review-id", generic), fail); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost final output", err)
	}
	raw := pruneServiceCLIRead(t, out)
	response, err := wire.DecodeResponse(raw)
	if err != nil || response.Verify(f.descriptor, f.request) != nil || response.Settlement == nil || response.Result != nil {
		t.Fatal("settlement response", err)
	}
	// A consumed review cannot be silently refreshed after the executor advances.
	if err = runPruneServiceCLIContext(t.Context(), append(append([]string(nil), apply...), "--mode", "run", "--expected-review-id", generic), io.Discard); err == nil {
		t.Fatal("stale original-state review reused")
	}
	retryOut := filepath.Join(f.public, "certified-retry.review")
	pruneServiceCLIRun(t, append(append([]string(nil), certified...), "--action", "settlement-review", "--out", retryOut))
	cold := pruneReadSettlementReview(t, retryOut)
	apply = replaceRemoteCLIFlag(apply, "--settlement-review-id", cold.Review.ReviewID.String())
	pruneServiceCLIRun(t, apply)
	if !bytes.Equal(raw, pruneServiceCLIRead(t, out)) {
		t.Fatal("retry changed response")
	}
	return response
}

func checkPruneServiceSettlementRejections(t testing.TB, f *pruneServiceOwnerCLIFixture, pos wire.Position) {
	t.Helper()
	before := pruneFailureSnapshot(t, f)
	accounts := pruneFailureAuthorities(t, f)
	did, _ := f.descriptor.ID()
	o, err := service.Open(t.Context(), f.root, did, pos, &f.request)
	if err != nil {
		t.Fatal(err)
	}
	in := pruneFailureInput(t, f)
	wrong := types.DomainHash("test/wrong-settlement", nil)
	if _, err = o.Settle(t.Context(), f.request, in, wrong); err == nil {
		t.Fatal("unsigned proposal granted settlement")
	}
	in.PlanID = wrong
	if _, err = o.ReviewSettlement(t.Context(), f.request, in); err == nil {
		t.Fatal("foreign plan accepted")
	}
	in = pruneFailureInput(t, f)
	in.DecisionPath, err = filepath.EvalSymlinks(filepath.Join(f.public, "settlement.decision"))
	if err != nil {
		t.Fatal(err)
	}
	review := pruneReadSettlementReview(t, filepath.Join(f.public, "certified.review"))
	in.DecisionID = review.Review.SettlementID
	if _, err = o.Settle(t.Context(), f.request, in, wrong); err == nil {
		t.Fatal("stale review granted settlement")
	}
	q := f.request
	q.Signature[0] ^= 1
	if _, err = o.ReviewSettlement(t.Context(), q, in); err == nil {
		t.Fatal("foreign request accepted")
	}
	in.DecisionID = wrong
	if _, err = o.ReviewSettlement(t.Context(), f.request, in); err == nil {
		t.Fatal("foreign decision ID accepted")
	}
	in.DecisionID = review.Review.SettlementID
	in.DecisionPath, err = filepath.EvalSymlinks(filepath.Join(f.public, "settlement.proposal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.ReviewSettlement(t.Context(), f.request, in); err == nil {
		t.Fatal("proposal substituted for full quorum decision")
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, pruneFailureSnapshot(t, f)) || !reflect.DeepEqual(accounts, pruneFailureAuthorities(t, f)) {
		t.Fatal("refused settlement changed original accounting")
	}
}

func completePruneServiceSettlement(t testing.TB, f *pruneServiceOwnerCLIFixture, r wire.Response, before []store.Coordination) {
	t.Helper()
	in := pruneFailureInput(t, f)
	proof := store.PruneSettlement{Effect: r.Effect, Decision: *r.Settlement}
	proofID, err := proof.ID()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := proof.CanonicalBytes()
	proofPath := filepath.Join(f.public, "complete-settlement")
	writePruneCLIFile(t, proofPath, raw)
	for i, replica := range f.inventory.Replicas {
		aid, _ := replica.Assignment.ID()
		var roots store.PruneArchiveAuthorityRoots
		for _, p := range f.config.Runtime.Authorities {
			if p.AssignmentID == aid {
				roots = p
			}
		}
		common := []string{"--plan", in.PlanPath, "--plan-id", in.PlanID.String(), "--assignment-id", aid.String(), "--authority", roots.AuthorityPath, "--authority-pins", roots.AuthorityPinsPath, "--executor", f.config.Runtime.ExecutorPath, "--executor-pins", f.config.Runtime.ExecutorPinsPath, "--inventory", f.config.Runtime.InventoryPath, "--inventory-id", f.config.Runtime.InventoryID.String()}
		var review store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append([]string{scheduledApplyCommand}, common...), &review)
		entry, eid := scheduledCLISign(t, []string{"--plan", in.PlanPath, "--plan-id", in.PlanID.String(), "--assignment-id", aid.String(), "--kind", "complete", "--inventory", f.config.Runtime.InventoryPath, "--inventory-id", f.config.Runtime.InventoryID.String(), "--settlement", proofPath, "--settlement-id", proofID.String(), "--expected-sequence", strconv.FormatUint(review.Review.Authority.Confirmed.Sequence, 10), "--expected-head", review.Review.Authority.Confirmed.HeadID.String()})
		apply := append(append([]string{scheduledApplyCommand}, common...), "--entry", entry, "--entry-id", eid.String())
		scheduledCLIRun(t, apply, &review)
		scheduledCLIRun(t, append(apply, "--mode", "apply", "--expected-review-id", review.Review.ReviewID.String()), &review)
		if review.Commit == nil || review.Commit.Snapshot.Pending != before[i].Authority.Pending-1 || len(review.Commit.Snapshot.Operations) != len(before[i].Authority.Operations) {
			t.Fatal("replica completion lost original accounting")
		}
		want := before[i].Authority
		want.Operations = append(want.Operations[:0:0], want.Operations...)
		want.Pending--
		want.Sequence++
		want.HeadID = eid
		ticket, _ := replica.Admission.ID()
		found := false
		for j := range want.Operations {
			if want.Operations[j].TicketID == ticket {
				if !want.Operations[j].CompletionID.IsZero() {
					t.Fatal("ticket already completed")
				}
				want.Operations[j].CompletionID = eid
				want.Operations[j].EvidenceID = proofID
				found = true
			}
		}
		if !found || !reflect.DeepEqual(want, review.Commit.Snapshot) {
			t.Fatal("completion changed unrelated operations or used different evidence")
		}
		all := pruneFailureAuthorities(t, f)
		if all[i].Pending != nil || all[i].Confirmed.Sequence != want.Sequence || all[i].Confirmed.HeadID != eid || !reflect.DeepEqual(all[i].Authority, want) {
			t.Fatal("completion not retained by original authority and pins")
		}
		for j := i + 1; j < len(all); j++ {
			if !reflect.DeepEqual(before[j], all[j]) {
				t.Fatal("completion changed another replica")
			}
		}
	}
}
