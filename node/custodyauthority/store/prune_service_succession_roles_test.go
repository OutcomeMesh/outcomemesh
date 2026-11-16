package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

func TestPruneServiceSuccessionArchiveRoles(t *testing.T) {
	var v ScheduledPruneInventory
	v.OriginalPolicy.TrustedAttestors = [][32]byte{testPublic(10), testPublic(11)}
	v.ReplicaPolicy.TrustedReplicas = [][32]byte{testPublic(12), testPublic(13)}
	for _, base := range []byte{20, 30} {
		v.Replicas = append(v.Replicas, ScheduledPruneReplica{Assignment: custodyauthority.Assignment{
			AuthorityPublicKey: testPublic(base), ReplicaPublicKey: testPublic(base + 1),
			RemoteControlPublicKey: testPublic(base + 2), RemoteTransportPublicKey: testPublic(base + 3),
			Auditors:  [][32]byte{testPublic(base + 4), testPublic(base + 5)},
			Consumers: []custodyauthority.Consumer{{PublicKey: testPublic(base + 6)}, {PublicKey: testPublic(base + 7)}},
		}})
	}
	check := func(successor, authority byte) error {
		var s prunefence.ServiceSuccession
		s.Replacement.Request.Successor = testPublic(successor)
		s.Replacement.Request.Authority = testPublic(authority)
		return v.CheckSuccessorRoles(s)
	}
	for _, seed := range []byte{10, 11, 12, 13, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37} {
		if !errors.Is(check(seed, 94), prunefence.ErrFence) || !errors.Is(check(95, seed), prunefence.ErrFence) {
			t.Errorf("archive participant %d escaped the successor or replacement authority check", seed)
		}
	}
	if err := check(95, 94); err != nil {
		t.Fatalf("unrelated keys: %v", err)
	}
}

func archiveSuccessorIdentity(t testing.TB, p prunefence.Policy, b prunefence.Binding, g *pruneServiceGuard, successor, authority byte) *prunefence.ServiceIdentity {
	t.Helper()
	q := guardwire.Replacement{
		GuardID: testHash(141), Subject: p.Service.Service, Successor: testPublic(successor), Authority: testPublic(authority),
		RevocationID: testHash(142), EvidenceID: testHash(143), Before: guardwire.Position{Sequence: 1, Head: testHash(144)},
	}
	q, err := q.Accept(testKey(successor))
	if err != nil {
		t.Fatal(err)
	}
	q, err = q.Authorize(testKey(authority))
	if err != nil {
		t.Fatal(err)
	}
	r, err := (guardwire.ReplacementReceipt{Request: q, Guard: p.Service.Guard}).Sign(testKey(92))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := (prunefence.ServiceSuccession{Replacement: r}).Sign(p, b, testKey(91))
	if err != nil {
		t.Fatal(err)
	}
	id, err := prunefence.NewSuccessorServiceIdentity(*p.Service, testKey(successor), g, proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	return id
}

func archiveSuccessorClaim(t testing.TB, v ScheduledPruneInventory, b prunefence.Binding, id *prunefence.ServiceIdentity) prunefence.Claim {
	t.Helper()
	session, err := id.NewSession(t.Context(), *v.FencePolicy, b)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	candidate, err := session.Candidate()
	if err != nil {
		t.Fatal(err)
	}
	scope, command, err := candidate.Draft()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := newPruneWitnessFixture(t, v).collect(t.Context(), scope, command)
	if err != nil {
		t.Fatal(err)
	}
	_, claim, err := session.Authorize(cert)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func TestPruneServiceSuccessionArchiveExecutionAndSettlement(t *testing.T) {
	f := newServicePruneFixture(t)
	v := f.inventory
	admitted := pruneSnapshot(t, f.executor)
	op, err := pruneFenceOperation(admitted)
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := op.FenceOperationID()
	if err != nil {
		t.Fatal(err)
	}
	b := prunefence.Binding{RequestID: admitted.RequestID, AssignmentID: v.Request.AssignmentID, OperationID: operationID,
		InventoryID: f.id, ExecutorBindingID: v.ExecutorBindingID, StoragePairID: v.StoragePairID}
	g := new(pruneServiceGuard)
	// 51 and 52 signed the original archived checkpoint. Neither is a fence witness.
	alias := archiveSuccessorIdentity(t, *v.FencePolicy, b, g, 51, 94)
	aliasAuthority := archiveSuccessorIdentity(t, *v.FencePolicy, b, g, 95, 52)
	valid := archiveSuccessorIdentity(t, *v.FencePolicy, b, g, 95, 94)
	config := f.runtimeConfig(t)
	config.CollectPruneCandidate = func(context.Context, prunefence.Candidate) (custodyfence.Certificate, error) {
		t.Fatal("requested witness votes for an archive participant")
		return custodyfence.Certificate{}, nil
	}
	for _, id := range []*prunefence.ServiceIdentity{alias, aliasAuthority} {
		config.ServiceIdentity = id
		service := openScheduledEffect(t, config)
		before := scheduledEffectReview(t, service)
		if _, err := service.Execute(t.Context(), before.ReviewID); !errors.Is(err, prunefence.ErrFence) {
			t.Fatalf("guarded execution accepted conflicting roles: %v", err)
		}
		after := scheduledEffectReview(t, service)
		if g.calls != 0 || after.Executor.Stage != PruneAdmitted || after.Executor.FenceCandidate != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("archive role reached guard, retained a candidate, or changed obligations")
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
	}

	config.ServiceIdentity = valid
	config.CollectPruneCandidate = nil
	config.CollectPruneClaim = newPruneWitnessFixture(t, v).collect
	service := openScheduledEffect(t, config)
	result, err := service.Execute(t.Context(), scheduledEffectReview(t, service).ReviewID)
	if err != nil || result.Commit == nil || !result.Commit.Applied || result.FenceResult == nil || g.calls != 1 {
		t.Fatalf("unrelated successor could not execute: %v", err)
	}
	effect := result.Commit.Effect
	effectID, err := effect.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		id      *prunefence.ServiceIdentity
		allowed bool
	}{{"independent", valid, true}, {"successor-attestor", alias, false}, {"replacement-authority-attestor", aliasAuthority, false}} {
		t.Run(tc.name, func(t *testing.T) {
			claim := result.FenceResult.Claim
			if !tc.allowed {
				claim = archiveSuccessorClaim(t, v, b, tc.id)
			}
			proposal := prunefence.SettlementProposal{Claim: claim, EffectID: effectID}
			decision := certifyObservedProposal(t, proposal)
			settlement := PruneSettlement{Effect: effect, Decision: decision}
			if _, err := settlement.CanonicalBytes(); err != nil {
				t.Fatalf("invalid test settlement: %v", err)
			}
			held := admitted
			held.Stage, held.FenceClaim, held.ArchiveInventoryID = PruneStarted, &claim, f.id
			_, _, observedErr := observedPruneSettlement(v, held, service.chain)
			offlineErr := VerifyScheduledPruneSettlementProposal(planFromInventory(v), v, decision.Proposal)
			outcome := ScheduledPruneOutcome{Settlement: &settlement}
			_, exportErr := outcome.EvidenceID(v)
			held.Stage, held.Effect, held.FenceSettlement = PruneSucceeded, &effect, &settlement
			_, retainedErr := RetainedScheduledPruneOutcome(v, held)
			for name, err := range map[string]error{"observed": observedErr, "offline": offlineErr, "export": exportErr, "retained": retainedErr} {
				if (err == nil) != tc.allowed {
					t.Errorf("%s verdict: %v", name, err)
				}
			}
		})
	}
	if g.calls != 1 {
		t.Fatal("settlement contacted the live guard")
	}
}
