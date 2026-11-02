//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// Test-only HTTP and filesystem failure controls; no runtime flag or production
// environment variable can select them. The real guard still journals choices.
type pruneGuardFault struct {
	mu             sync.Mutex
	mode, path     string
	calls, choices atomic.Int32
}

func (f *pruneGuardFault) set(mode, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode, f.path = mode, path
}
func (f *pruneGuardFault) handler(real http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.mu.Lock()
		mode, path := f.mode, f.path
		f.mu.Unlock()
		if mode == "guard-unavailable" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		reply := httptest.NewRecorder()
		real.ServeHTTP(reply, r)
		if reply.Code == http.StatusOK {
			f.choices.Add(1)
			if mode == "guard-loss" {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
			if mode == "result-write" {
				if err := os.Chmod(path, 0500); err != nil {
					http.Error(w, "fixture fault failed", 500)
					return
				}
			}
		}
		for k, v := range reply.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(reply.Code)
		_, _ = w.Write(reply.Body.Bytes())
	})
}
func pruneFailureSnapshot(t testing.TB, f *pruneServiceOwnerCLIFixture) store.PruneExecution {
	t.Helper()
	for _, r := range f.inventory.Replicas {
		aid, _ := r.Assignment.ID()
		if aid != f.inventory.Request.AssignmentID {
			continue
		}
		rid, _ := f.inventory.Request.ID()
		e, err := store.OpenPinnedPruneExecutor(f.config.Runtime.ExecutorPath, f.config.Runtime.ExecutorPinsPath, r.Assignment, rid)
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		s, err := e.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Fatal("no primary")
	return store.PruneExecution{}
}
func pruneFailureEffect(t testing.TB, f *pruneServiceOwnerCLIFixture) (workchain.CanonicalPruneEffect, bool) {
	t.Helper()
	c := f.config.Runtime
	s, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(c.ChainPath, c.ChainPinsPath, c.Base, c.Parameters, c.StoragePolicy, f.inventory.Request.StorageID, c.StorageMigrationID)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, r := range f.inventory.Replicas {
		aid, _ := r.Assignment.ID()
		if aid == f.inventory.Request.AssignmentID {
			id, _ := r.Admission.ID()
			e, found, err := s.CanonicalPruneEffect(id)
			if err != nil {
				t.Fatal(err)
			}
			return e, found
		}
	}
	t.Fatal("missing primary")
	return workchain.CanonicalPruneEffect{}, false
}
func pruneFailureAuthorities(t testing.TB, f *pruneServiceOwnerCLIFixture) []store.Coordination {
	t.Helper()
	var all []store.Coordination
	for _, r := range f.inventory.Replicas {
		aid, _ := r.Assignment.ID()
		for _, p := range f.config.Runtime.Authorities {
			if p.AssignmentID != aid {
				continue
			}
			s, err := store.OpenCoordinator(p.AuthorityPath, p.AuthorityPinsPath, r.Assignment, aid)
			if err != nil {
				t.Fatal(err)
			}
			v, err := s.Snapshot()
			ce := s.Close()
			if err != nil || ce != nil {
				t.Fatal(err, ce)
			}
			all = append(all, v)
		}
	}
	return all
}
func pruneFailureInput(t testing.TB, f *pruneServiceOwnerCLIFixture) service.SettlementInput {
	t.Helper()
	path, err := filepath.EvalSymlinks(filepath.Join(f.public, "plan"))
	if err != nil {
		t.Fatal(err)
	}
	raw := pruneServiceCLIRead(t, path)
	p, err := store.DecodeScheduledPrunePlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := p.ID()
	return service.SettlementInput{PlanPath: path, PlanID: id}
}
func pruneFailureExecute(t testing.TB, f *pruneServiceOwnerCLIFixture, mode string) (*service.Owner, wire.Position) {
	t.Helper()
	if mode == "quorum-loss" {
		f.witnessServers[0].Close()
		f.witnessServers[1].Close()
	}
	pending := filepath.Join(f.config.Runtime.ExecutorPinsPath, "pending")
	f.fault.set(mode, pending)
	owner := f.open(t, wire.Position{}, nil)
	calls := 0
	_, err := owner.Execute(t.Context(), f.request, func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		calls++
		_, d, e := ch.Candidate.Draft()
		if e != nil {
			return d, e
		}
		return d.Sign(pruneCLIKey(4))
	})
	if mode == "result-write" {
		if e := os.Chmod(pending, 0700); e != nil {
			t.Fatal(e)
		}
	}
	f.fault.set("", "")
	if err == nil || calls != 1 {
		t.Fatal("fault did not retain an unknown attempt", err, calls)
	}
	s, err := owner.Snapshot()
	if err != nil || s.Position.Sequence != 1 || s.Response != nil {
		t.Fatal("lost held intent", err)
	}
	return owner, s.Position
}
func TestPruneServiceQuorumAndGuardFailuresKeepOriginalObligations(t *testing.T) {
	for _, mode := range []string{"quorum-loss", "guard-unavailable", "guard-loss"} {
		t.Run(mode, func(t *testing.T) {
			f := preparePruneServiceOwnerCLI(t)
			before := pruneFailureAuthorities(t, f)
			owner, pos := pruneFailureExecute(t, f, mode)
			s := pruneFailureSnapshot(t, f)
			if s.FenceResult != nil || s.FenceSettlement != nil || s.FenceCandidate == nil {
				t.Fatal("missing candidate or fabricated outcome")
			}
			if _, ok := pruneFailureEffect(t, f); ok {
				t.Fatal("failure performed deletion")
			}
			want := int32(0)
			if mode == "guard-loss" {
				want = 1
			}
			p, e := f.guard.Position()
			if e != nil || p.Sequence != uint32(want) || f.fault.choices.Load() != want {
				t.Fatal("guard decision changed", p, e)
			}
			if mode == "quorum-loss" && f.fault.calls.Load() != 0 {
				t.Fatal("minority reached guard")
			}
			if _, e = owner.ReviewSettlement(t.Context(), f.request, pruneFailureInput(t, f)); e == nil {
				t.Fatal("missing effect accepted for settlement")
			}
			if _, e = owner.Recover(t.Context(), f.request); e == nil {
				t.Fatal("failure became signed result")
			}
			owner.Close()
			owner = f.open(t, pos, &f.request)
			guardCalls := f.fault.calls.Load()
			if _, e = owner.Execute(t.Context(), f.request, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
				t.Error("cold attempt requested new approval")
				return custodyfence.Command{}, nil
			}); !errors.Is(e, service.ErrHeld) {
				t.Fatal("cold retry", e)
			}
			if f.fault.calls.Load() != guardCalls || !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) {
				t.Fatal("retry changed choices or original accounting")
			}
		})
	}
}

func pruneReadSettlementReview(t testing.TB, path string) store.ScheduledPruneCommandResult {
	t.Helper()
	var r store.ScheduledPruneCommandResult
	if err := json.Unmarshal(pruneServiceCLIRead(t, path), &r); err != nil {
		t.Fatal(err)
	}
	return r
}
