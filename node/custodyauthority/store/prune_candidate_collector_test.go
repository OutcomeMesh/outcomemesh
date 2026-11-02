package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

func TestPruneCandidateCollectorRetainsDetachedCandidateAndOriginalOwners(t *testing.T) {
	f := newServicePruneFixture(t)
	w := newPruneWitnessFixture(t, f.inventory)
	g := new(pruneServiceGuard)
	identity, err := prunefence.NewServiceIdentity(*f.inventory.FencePolicy.Service, testKey(90), g)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	c := f.runtimeConfig(t)
	c.ServiceIdentity = identity
	rid, _ := f.inventory.Request.ID()
	calls := 0
	c.CollectPruneCandidate = func(ctx context.Context, candidate prunefence.Candidate) (custodyfence.Certificate, error) {
		calls++
		raw, err := candidate.CanonicalBytes()
		if err != nil {
			return custodyfence.Certificate{}, err
		}
		retained, err := os.ReadFile(filepath.Join(c.ExecutorPath, "fence", "candidate"))
		if err != nil || !bytes.Equal(raw, retained) {
			t.Fatal("candidate not retained before external approval", err)
		}
		if candidate.Binding.RequestID != rid || candidate.Binding.InventoryID != f.id || candidate.Binding.ExecutorBindingID != f.inventory.ExecutorBindingID || candidate.Binding.StoragePairID != f.inventory.StoragePairID || candidate.Policy.Service == nil || *candidate.Policy.Service != *f.inventory.FencePolicy.Service {
			t.Fatal("incomplete service candidate")
		}
		assertScheduledEffectBusy(t, f, c)
		scope, draft, err := candidate.Draft()
		if err != nil {
			return custodyfence.Certificate{}, err
		}
		certificate, err := w.collect(ctx, scope, draft)
		// The callback has only public, detached data. Even mutations after it
		// obtains the exact certificate must not alter the retained session.
		candidate.Policy.Service.StorageID[0] ^= 1
		candidate.Policy.Witnesses[0][0] ^= 1
		candidate.Binding.InventoryID[0] ^= 1
		return certificate, err
	}
	encoded, err := json.Marshal(c)
	if err != nil || bytes.Contains(encoded, []byte("CollectPruneCandidate")) {
		t.Fatal("collector leaked into transport configuration", err)
	}
	s := openScheduledEffect(t, c)
	before := scheduledEffectReview(t, s)
	r, err := s.Execute(t.Context(), before.ReviewID)
	if err != nil || r.Commit == nil || !r.Commit.Applied || r.FenceResult == nil || r.FenceResult.ServiceConsumption == nil || calls != 1 || g.calls != 1 {
		t.Fatal("candidate-based actual deletion", err)
	}
	after := scheduledEffectReview(t, s)
	if after.Executor.Stage != PruneSucceeded || !reflect.DeepEqual(before.Authorities, after.Authorities) || !reflect.DeepEqual(before.Journals, after.Journals) {
		t.Fatal("candidate callback altered obligations")
	}
	if *after.Executor.FenceCandidate.Policy.Service != *f.inventory.FencePolicy.Service || after.Executor.FenceCandidate.Binding.InventoryID != f.id {
		t.Fatal("callback changed original candidate")
	}
	if _, err := s.Execute(t.Context(), after.ReviewID); err == nil || calls != 1 {
		t.Fatal("confirmed execution solicited another signature", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	identity.Close()
	c.CollectPruneCandidate, c.ServiceIdentity = nil, nil
	cold := openScheduledEffect(t, c)
	recovered, err := cold.Recover(t.Context(), scheduledEffectReview(t, cold).ReviewID)
	if err != nil || recovered.Commit.Applied || !reflect.DeepEqual(recovered.Commit.Effect, r.Commit.Effect) || calls != 1 || g.calls != 1 {
		t.Fatal("cold recovery recreated approval", err)
	}
}

func TestPruneCandidateCollectorRejectsInvalidConfigurationBeforeOwnership(t *testing.T) {
	f := newServicePruneFixture(t)
	c := f.runtimeConfig(t)
	identity, err := prunefence.NewServiceIdentity(*f.inventory.FencePolicy.Service, testKey(90), new(pruneServiceGuard))
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	candidate := func(context.Context, prunefence.Candidate) (custodyfence.Certificate, error) {
		t.Fatal("invalid configuration invoked collector")
		return custodyfence.Certificate{}, nil
	}
	claim := func(context.Context, custodyfence.Scope, custodyfence.Command) (custodyfence.Certificate, error) {
		t.Fatal("invalid configuration invoked legacy collector")
		return custodyfence.Certificate{}, nil
	}
	for _, name := range []string{"missing-service", "both-collectors"} {
		t.Run(name, func(t *testing.T) {
			bad := c
			bad.CollectPruneCandidate = candidate
			if name == "both-collectors" {
				bad.ServiceIdentity, bad.CollectPruneClaim = identity, claim
			}
			service, err := OpenScheduledPruneEffectService(t.Context(), bad)
			if service != nil {
				service.Close()
			}
			if !errors.Is(err, prunefence.ErrFence) {
				t.Fatal("invalid collector selection accepted", err)
			}
			review, err := RunScheduledPrune(t.Context(), c, "review", types.Hash{})
			if err != nil || review.Review.Executor.Stage != PruneAdmitted || review.Review.Executor.FenceCandidate != nil {
				t.Fatal("invalid configuration changed original execution", err)
			}
		})
	}
	legacy := newScheduledPruneFixture(t, pruneFencePolicy()).runtimeConfig(t)
	legacy.ServiceIdentity, legacy.CollectPruneCandidate = identity, candidate
	if service, err := OpenScheduledPruneEffectService(t.Context(), legacy); err == nil {
		service.Close()
		t.Fatal("candidate collection accepted an unenrolled request")
	}
}

func TestPruneCandidateCollectorFailureCannotRecreateSession(t *testing.T) {
	for _, mode := range []string{"disconnected", "substituted-certificate", "cancelled-after-quorum"} {
		t.Run(mode, func(t *testing.T) {
			f := newServicePruneFixture(t)
			w := newPruneWitnessFixture(t, f.inventory)
			g := new(pruneServiceGuard)
			identity, err := prunefence.NewServiceIdentity(*f.inventory.FencePolicy.Service, testKey(90), g)
			if err != nil {
				t.Fatal(err)
			}
			defer identity.Close()
			c := f.runtimeConfig(t)
			c.ServiceIdentity = identity
			run, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			c.CollectPruneCandidate = func(ctx context.Context, candidate prunefence.Candidate) (custodyfence.Certificate, error) {
				calls++
				if mode == "disconnected" {
					return custodyfence.Certificate{}, context.Canceled
				}
				scope, draft, err := candidate.Draft()
				if err != nil {
					return custodyfence.Certificate{}, err
				}
				if mode == "substituted-certificate" {
					draft.EvidenceID = testHash(213)
				}
				certificate, err := w.collect(ctx, scope, draft)
				if mode == "cancelled-after-quorum" {
					cancel()
				}
				return certificate, err
			}
			s := openScheduledEffect(t, c)
			before := scheduledEffectReview(t, s)
			if _, err := s.Execute(run, before.ReviewID); err == nil {
				t.Fatal("invalid approval executed")
			}
			after := scheduledEffectReview(t, s)
			if after.Executor.Stage != PruneAdmitted || after.Executor.FenceCandidate == nil || after.Executor.FenceClaim != nil || !reflect.DeepEqual(before.Authorities, after.Authorities) || !reflect.DeepEqual(before.Journals, after.Journals) || !reflect.DeepEqual(before.Storage, after.Storage) || g.calls != 0 {
				t.Fatal("approval failure changed effect or obligations")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			cold := openScheduledEffect(t, c)
			if _, err := cold.Execute(t.Context(), scheduledEffectReview(t, cold).ReviewID); err == nil || calls != 1 {
				t.Fatal("cold copy recreated volatile candidate", err)
			}
		})
	}
}
