//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	fixture "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

type recoveryChooser func(context.Context, guard.Request) ([64]byte, error)

func (f recoveryChooser) Choose(ctx context.Context, q guard.Request) ([64]byte, error) {
	return f(ctx, q)
}

func interruptedCoreFixture(t testing.TB, stage string, guarded bool) (*protectedFixture, custodyfence.Certificate, wire.Request, []byte, types.Hash) {
	t.Helper()
	x := newProtectedFixture(t, guarded, true, true)
	claim := x.claim(t)
	raw, _ := claim.CanonicalBytes()
	fault := errors.New("execution interrupted")
	hit := false
	x.b.executionHook = func(at string) error {
		if at == stage {
			hit = true
			return fault
		}
		return nil
	}
	_, q, payload, err := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: raw, Now: 1}, "retained-core")
	if !hit || !errors.Is(err, fault) {
		t.Fatal("fault not reached", stage, err)
	}
	scope, _ := x.c.Scope()
	sid, _ := scope.ID()
	return x, claim, q, payload, sid
}
func reopenCoreTarget(t testing.TB, x *protectedFixture, q wire.Request) {
	t.Helper()
	pos, _ := x.b.Position()
	did, _ := x.bd.ID()
	fixture.Require(t, x.b.Close())
	var err error
	x.b, err = Open(x.broot, did, pos, &q)
	fixture.Require(t, err)
	x.b.SetGuard(x.guard)
	x.b.clock = func() uint64 { return x.c.Plan.Challenge.IssuedAt + x.c.CustodyPolicy.MaximumProofAge + 30 }
	x.b.executionHook = func(stage string) error {
		if stage == "consumed-before-read" || stage == "source-before-result" {
			return fmt.Errorf("recovery repeated execution at %s", stage)
		}
		return nil
	}
}
func recoveredCore(t testing.TB, x *protectedFixture, q wire.Request, payload []byte, claim custodyfence.Certificate) (v2.Result, []byte) {
	t.Helper()
	raw, err := x.b.ExecuteRuntime(t.Context(), q, payload)
	fixture.Require(t, err)
	response, err := wire.DecodeResponse(raw)
	fixture.Require(t, err)
	fixture.Require(t, response.Verify(x.bd, q))
	result, err := v2.DecodeResult(response.Data)
	fixture.Require(t, err)
	fixture.Require(t, result.Verify(x.c, claim))
	return result, raw
}

func TestGuardedProfile5RetainedCoreColdRecoveryPreservesEvidence(t *testing.T) {
	for _, stage := range []string{"core-result-before-seal", "sealed-result-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			x, claim, q, payload, sid := interruptedCoreFixture(t, stage, true)
			core, err := x.b.jobRead(sid, "core-result", v2.MaximumResultBytes)
			fixture.Require(t, err)
			original, err := v2.DecodeResult(core)
			fixture.Require(t, err)
			if original.Verify(x.c, claim) == nil {
				t.Fatal("bare core accepted as protected result")
			}
			source, err := x.b.currentExecutionSource()
			fixture.Require(t, err)
			accounting := x.state.Snapshot()
			beforeGuard, err := x.guardStore.Position()
			fixture.Require(t, err)
			reopenCoreTarget(t, x, q)
			if len(x.b.execution.sessions) != 0 {
				t.Fatal("cold recovery recreated volatile session")
			}
			result, response := recoveredCore(t, x, q, payload, claim)
			if result.SessionSignature != original.SessionSignature || !reflect.DeepEqual(result.Entry, original.Entry) || result.Protection.CheckedAt != original.Entry.Record.Proof.RespondedAt {
				t.Fatal("recovery changed signed evidence or time")
			}
			retained, err := x.b.jobRead(sid, "core-result", v2.MaximumResultBytes)
			fixture.Require(t, err)
			if !bytes.Equal(core, retained) {
				t.Fatal("rewrote core result")
			}
			after, err := x.b.currentExecutionSource()
			fixture.Require(t, err)
			if !reflect.DeepEqual(source, after) || !reflect.DeepEqual(accounting, x.state.Snapshot()) {
				t.Fatal("recovery changed source or obligations")
			}
			afterGuard, err := x.guardStore.Position()
			fixture.Require(t, err)
			want := beforeGuard.Sequence + 1 // authenticated outer response
			if stage == "core-result-before-seal" {
				want++
			}
			if afterGuard.Sequence != want {
				t.Fatal("wrong guard choice count", afterGuard.Sequence, want)
			}
			_, again := recoveredCore(t, x, q, payload, claim)
			if !bytes.Equal(response, again) {
				t.Fatal("exact response retry changed")
			}
			pin, err := x.guardStore.Position()
			fixture.Require(t, err)
			if pin != afterGuard {
				t.Fatal("retry consumed guard slot")
			}
			// The ordinary result quorum still remains mandatory for source acceptance.
			bundle := x.recordBundle(t, claim, result)
			if err := bundle.Verify(x.c); err != nil {
				t.Fatal(err)
			}
			at := x.b.clock()
			cid, _ := x.c.ID()
			bid, _ := bundle.ID()
			consent := v2.RetainedAcceptance{ContextID: cid, BundleID: bid, EvidenceID: f.Hash("retained core recovery"), NotBefore: at, NotAfter: at + 60}
			consent, err = consent.Sign(x.c, bundle, "authority", f.Key(101))
			fixture.Require(t, err)
			consent, err = consent.Sign(x.c, bundle, "consumer", f.Key(4))
			fixture.Require(t, err)
			x.a.clock = func() uint64 { return at }
			assertRetainedAcceptanceClosure(t, x, bundle, consent, at)
		})
	}
}

func TestGuardedProfile5RetainedCoreLostGuardReply(t *testing.T) {
	x := newProtectedFixture(t, true, true, true)
	claim := x.claim(t)
	data, _ := claim.CanonicalBytes()
	hit := false
	fault := errors.New("guard reply dropped")
	x.b.SetGuard(recoveryChooser(func(ctx context.Context, q guard.Request) ([64]byte, error) {
		seal, err := x.guard.Choose(ctx, q)
		if err == nil && q.Kind == guard.Effect {
			hit = true
			return [64]byte{}, fault
		}
		return seal, err
	}))
	_, q, payload, err := protectedCall(t, x.b, x.bd, v2.ProtectedCommand{Kind: v2.ProtectedExecute, Admission: x.binding, Data: data, Now: 1}, "lost-seal")
	if !hit || !errors.Is(err, fault) {
		t.Fatal("lost reply not reached", err)
	}
	before, err := x.guardStore.Position()
	fixture.Require(t, err)
	reopenCoreTarget(t, x, q)
	recoveredCore(t, x, q, payload, claim)
	after, err := x.guardStore.Position()
	fixture.Require(t, err)
	if after.Sequence != before.Sequence+1 {
		t.Fatal("lost effect reply selected a new effect")
	}
}

func TestGuardedProfile5RetainedCoreRejectsMissingOrSubstitutedEvidence(t *testing.T) {
	for _, name := range []string{"core-truncated", "core-signature", "core-missing", "entry", "candidate", "consumed", "admission", "different-request", "unguarded"} {
		t.Run(name, func(t *testing.T) {
			x, _, q, payload, sid := interruptedCoreFixture(t, "core-result-before-seal", name != "unguarded")
			if name == "unguarded" {
				reopenCoreTarget(t, x, q)
			} else {
				path := "core-result"
				switch name {
				case "entry", "candidate", "consumed", "admission":
					path = name
				}
				if name != "different-request" {
					p := x.b.jobPath(sid, path)
					raw, err := os.ReadFile(p)
					fixture.Require(t, err)
					if name == "core-missing" {
						fixture.Require(t, os.Remove(p))
					} else {
						if name == "core-truncated" {
							raw = raw[:len(raw)-1]
						} else {
							raw[len(raw)-1] ^= 1
						}
						fixture.Require(t, os.WriteFile(p, raw, 0600))
					}
				} else {
					q.Nonce = f.Hash("other pending request")
					var err error
					q, err = q.Sign(f.Key(14))
					fixture.Require(t, err)
				}
			}
			before, _ := x.b.Position()
			guardBefore, err := x.guardStorePosition()
			fixture.Require(t, err)
			x.b.executionHook = nil
			if _, err := x.b.ExecuteRuntime(t.Context(), q, payload); err == nil {
				t.Fatal("invalid evidence recovered")
			}
			after, _ := x.b.Position()
			guardAfter, err := x.guardStorePosition()
			fixture.Require(t, err)
			if before != after || guardBefore != guardAfter {
				t.Fatal("invalid evidence consumed service or guard position")
			}
			if _, err := os.Stat(filepath.Join(x.broot, "execution", "jobs", sid.String(), "result")); !os.IsNotExist(err) {
				t.Fatal("invalid evidence published result", err)
			}
		})
	}
}
func (x *protectedFixture) guardStorePosition() (guard.Position, error) {
	if x.guardStore == nil {
		return guard.Position{}, nil
	}
	return x.guardStore.Position()
}

func TestGuardedProfile5RetainedCoreReplacementRespectsOriginalChoice(t *testing.T) {
	for _, stage := range []string{"core-result-before-seal", "sealed-result-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			x, claim, q, payload, sid := interruptedCoreFixture(t, stage, true)
			source, err := x.b.currentExecutionSource()
			fixture.Require(t, err)
			accounting := x.state.Snapshot()
			oldKey := bytes.Clone(x.b.key)
			defer clear(oldKey)
			replacement := x.replaceSigner(t, x.bd.Gateway, 231)
			x.activateService(t, true, replacement, 231, &q)
			x.b.executionHook = func(stage string) error {
				if stage == "consumed-before-read" || stage == "source-before-result" {
					return errors.New("replacement executed again")
				}
				return nil
			}
			if stage == "sealed-result-before-publish" {
				before, err := x.guardStore.Position()
				fixture.Require(t, err)
				if _, err := x.b.ExecuteRuntime(t.Context(), q, payload); err == nil {
					t.Fatal("successor replaced the original occupied effect slot")
				}
				after, err := x.guardStore.Position()
				fixture.Require(t, err)
				if before != after {
					t.Fatal("conflict consumed guard position")
				}
				if _, err := x.b.jobRead(sid, "result", v2.MaximumResultBytes); !os.IsNotExist(err) {
					t.Fatal("conflicting result published", err)
				}
			} else {
				result, _ := recoveredCore(t, x, q, payload, claim)
				if result.Protection.Replacement == nil {
					t.Fatal("successor lost replacement binding")
				}
				forged := *result.Protection
				forged.Replacement = nil
				forged.GuardSeal = [64]byte{}
				forged, err = forged.Sign(oldKey)
				fixture.Require(t, err)
				request, err := forged.GuardRequest()
				fixture.Require(t, err)
				if _, err = guard.Obtain(t.Context(), x.guard, x.dep.Guard, request, oldKey); err == nil {
					t.Fatal("revoked service copy acquired new seal")
				}
			}
			after, err := x.b.currentExecutionSource()
			fixture.Require(t, err)
			if !reflect.DeepEqual(source, after) || !reflect.DeepEqual(accounting, x.state.Snapshot()) {
				t.Fatal("replacement changed source or obligations")
			}
		})
	}
}

func TestGuardedProfile5RetainedCoreRechecksEvidenceAcrossSeal(t *testing.T) {
	for _, stage := range []string{"retained-core-before-seal", "sealed-result-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			x, _, q, payload, sid := interruptedCoreFixture(t, "core-result-before-seal", true)
			reopenCoreTarget(t, x, q)
			path := x.b.jobPath(sid, "core-result")
			original, err := os.ReadFile(path)
			fixture.Require(t, err)
			hit := false
			x.b.executionHook = func(at string) error {
				if at == stage {
					hit = true
					raw := bytes.Clone(original)
					raw[len(raw)-1] ^= 1
					return os.WriteFile(path, raw, 0600)
				}
				return nil
			}
			before, _ := x.b.Position()
			if _, err := x.b.ExecuteRuntime(t.Context(), q, payload); err == nil || !hit {
				t.Fatal("changed evidence published", err)
			}
			after, _ := x.b.Position()
			if before != after {
				t.Fatal("invalid recovery advanced service")
			}
			if _, err := x.b.jobRead(sid, "result", v2.MaximumResultBytes); !os.IsNotExist(err) {
				t.Fatal("published changed evidence", err)
			}
		})
	}
}

func TestGuardedProfile5RetainedCoreCancelledSealCanRecoverExactly(t *testing.T) {
	x, claim, q, payload, _ := interruptedCoreFixture(t, "core-result-before-seal", true)
	reopenCoreTarget(t, x, q)
	source, err := x.b.currentExecutionSource()
	fixture.Require(t, err)
	before, err := x.guardStore.Position()
	fixture.Require(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	x.b.SetGuard(recoveryChooser(func(ctx context.Context, request guard.Request) ([64]byte, error) {
		seal, err := x.guard.Choose(ctx, request)
		if err == nil && request.Kind == guard.Effect {
			cancel()
		}
		return seal, err
	}))
	if _, err := x.b.ExecuteRuntime(ctx, q, payload); err == nil {
		t.Fatal("cancelled seal exposed a result")
	}
	x.b.SetGuard(x.guard)
	recoveredCore(t, x, q, payload, claim)
	after, err := x.guardStore.Position()
	fixture.Require(t, err)
	if after.Sequence != before.Sequence+2 {
		t.Fatal("cancellation changed effect choice")
	}
	current, err := x.b.currentExecutionSource()
	fixture.Require(t, err)
	if !reflect.DeepEqual(source, current) {
		t.Fatal("cancellation recovery repeated source execution")
	}
}

func TestGuardedProfile5RetainedCoreConcurrentExactRecovery(t *testing.T) {
	x, _, q, payload, _ := interruptedCoreFixture(t, "core-result-before-seal", true)
	reopenCoreTarget(t, x, q)
	before, err := x.guardStore.Position()
	fixture.Require(t, err)
	type response struct {
		raw []byte
		err error
	}
	done := make(chan response, 2)
	for i := 0; i < 2; i++ {
		go func() { b, e := x.b.ExecuteRuntime(t.Context(), q, payload); done <- response{b, e} }()
	}
	a, b := <-done, <-done
	fixture.Require(t, a.err)
	fixture.Require(t, b.err)
	if !bytes.Equal(a.raw, b.raw) {
		t.Fatal("concurrent recovery produced different responses")
	}
	after, err := x.guardStore.Position()
	fixture.Require(t, err)
	if after.Sequence != before.Sequence+2 {
		t.Fatal("concurrent recovery selected more than one result")
	}
}
