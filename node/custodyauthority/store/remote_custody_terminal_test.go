package store

import (
	"bytes"
	"context"
	"errors"
	"github.com/libp2p/go-libp2p/core/network"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func openRemoteTerminalPair(t testing.TB, f *remoteExecutionFixture, config RemoteCustodyAuditRuntimeConfig) (*RemoteCustodyAuditRuntime, *RemoteCustodyServeService, string) {
	t.Helper()
	a, err := OpenRemoteCustodyAuditRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := OpenRemoteCustodyServeService(t.Context(), f.serveConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Start(t.Context(), testKey(15), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PrepareChallenge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Begin(t.Context()); err != nil {
		t.Fatal(err)
	}
	return a, b, b.Addresses()[0]
}

func TestRemoteCustodyNetworkResultAndExplicitIndependentCompletion(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	config := f.auditConfig(t)
	a, b, address := openRemoteTerminalPair(t, f, config)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	result, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address)
	if err != nil || result.JournalSequence != 1 {
		t.Fatal("managed remote exchange", result, err)
	}
	aHead, aExists, err := f.base.journal.Head()
	if err != nil || !aExists {
		t.Fatal(err)
	}
	bHead, bExists, err := f.base.serve.journal.Head()
	if err != nil || !bExists {
		t.Fatal(err)
	}
	aID, _ := aHead.ID()
	bID, _ := bHead.ID()
	if aID != bID {
		t.Fatal("separate original journals committed different responses")
	}
	before := testCoordination(t, a.life.owner)
	if before.Authority.Remote == nil || before.Authority.Pending != 2 {
		t.Fatal("delivery implicitly released authority", before)
	}
	reply, err := a.SealQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address)
	if err != nil || reply.Seal.Disposition != remoteworker.RetainedResult || reply.Seal.ResultID != aID {
		t.Fatal("seal", reply, err)
	}
	sealed := testCoordination(t, a.life.owner)
	if sealed.Authority.Remote != nil || sealed.Authority.Pending != 2 {
		t.Fatal("drain completed tickets", sealed)
	}
	terminal, err := a.CaptureTerminal(ctx, reply)
	if err != nil {
		t.Fatal(err)
	}
	if err := terminal.Validate(f.scope); err != nil {
		t.Fatal(err)
	}
	encoded, err := terminal.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRemoteCustodyTerminal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := decoded.CanonicalBytes()
	if !bytes.Equal(got, encoded) {
		t.Fatal("terminal lost canonical bytes")
	}
	for _, bad := range [][]byte{encoded[:len(encoded)-1], append(append([]byte(nil), encoded...), 0), append([]byte{0}, encoded...)} {
		if _, err := DecodeRemoteCustodyTerminal(bad); err == nil {
			t.Fatal("noncanonical terminal accepted")
		}
	}
	config.Audit.SessionConfig.Now = func() uint64 { return f.base.serve.now + f.scope.CustodyPolicy.MaximumProofAge + 1000 }
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	a, err = OpenRemoteCustodyAuditRuntime(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	reopened, err := a.CaptureTerminal(ctx, reply)
	if err != nil {
		t.Fatal("retained local acceptance was lost", err)
	}
	tid, _ := terminal.ID()
	rid, _ := reopened.ID()
	if tid != rid {
		t.Fatal("capture refreshed historical result")
	}
	auditID, _ := f.audit.ID()
	serveID, _ := f.scope.Worker.Plan.Admission.ID()
	var first custodyauthority.Entry
	for _, ticket := range []types.Hash{auditID, serveID} {
		current := testCoordination(t, a.life.owner)
		draft, err := BuildRemoteCustodyCompleteCommand(f.scope, terminal, ticket, current.Confirmed)
		if err != nil {
			t.Fatal(err)
		}
		entry := remoteStoreSign(t, draft, 4)
		if first == (custodyauthority.Entry{}) {
			first = entry
		}
		commit, err := a.ApplyComplete(ctx, terminal, entry)
		if err != nil || !commit.Appended {
			t.Fatal("typed completion", commit, err)
		}
	}
	current := testCoordination(t, a.life.owner)
	if current.Authority.Pending != 0 || current.Confirmed.Sequence != 6 {
		t.Fatal(current)
	}
	retry, err := a.ApplyComplete(ctx, terminal, first)
	if err != nil || retry.Appended || retry.Snapshot.Sequence != 6 {
		t.Fatal("historical retry", retry, err)
	}
	if _, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err == nil {
		t.Fatal("drained ticket enabled network execution")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteCustodySignedDrainWithoutLocalAcceptanceCannotComplete(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "started_without_result"
		if expired {
			name = "replica_committed_proof_expired_at_A"
		}
		t.Run(name, func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := f.auditConfig(t)
			var now atomic.Uint64
			now.Store(f.base.serve.now)
			config.Audit.SessionConfig.Now = now.Load
			a, b, address := openRemoteTerminalPair(t, f, config)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			if expired {
				b.hooks.at = func(stage string) error {
					if stage == "remote-data-admitted" {
						now.Store(f.base.serve.now + f.scope.CustodyPolicy.MaximumProofAge + 1000)
					}
					return nil
				}
			} else {
				a.hooks.at = func(stage string) error {
					if stage == "remote-audit-start-confirmed" {
						return errors.New("stop before data")
					}
					return nil
				}
			}
			if _, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err == nil {
				t.Fatal("unaccepted result succeeded")
			}
			aState, err := f.base.journal.State()
			if err != nil || aState.Sequence != 0 {
				t.Fatal("A accepted an expired/absent proof", aState, err)
			}
			reply, err := a.SealQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address)
			if err != nil {
				t.Fatalf("seal failed: %v; B retained cleanup failure: %v", err, b.retainedFailure())
			}
			want := remoteworker.NoResult
			if expired {
				want = remoteworker.RetainedResult
			}
			if reply.Seal.Disposition != want {
				t.Fatal("wrong immutable disposition", reply.Seal)
			}
			if _, err := a.CaptureTerminal(ctx, reply); err == nil {
				t.Fatal("B metadata manufactured local A acceptance")
			}
			current := testCoordination(t, a.life.owner)
			if current.Authority.Remote != nil || current.Authority.Pending != 2 {
				t.Fatal("drain manufactured completion", current)
			}
		})
	}
}

func TestRemoteCustodyTerminalScopeRefusesBeforeAnyExecution(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	for _, mutation := range []func(*RemoteCustodyScope){
		func(s *RemoteCustodyScope) { s.Worker.PlanID = testHash(229) },
		func(s *RemoteCustodyScope) { s.PreviousReceipt = s.InitialReceipt; s.PreviousReceipt.RetainUntil++ },
		func(s *RemoteCustodyScope) {
			s.Worker.Plan.AuthorityTransportPublicKey = s.Worker.Assignment.AuthorityPublicKey
		},
		func(s *RemoteCustodyScope) { s.Worker.Begin.Command.ExpectedSequence++ },
		func(s *RemoteCustodyScope) { s.Challenge.Nonce = testHash(230) },
	} {
		scope, err := freezeRemoteCustodyScope(f.scope)
		if err != nil {
			t.Fatal(err)
		}
		mutation(&scope)
		if validateRemoteCustodyScope(scope) == nil {
			t.Fatal("substituted scope accepted")
		}
	}
}

// This fixed envelope tests the codec, not current authority. The separate real
// network test above establishes original local acceptance and scope binding.
func remoteTerminalCodecVector(t testing.TB) RemoteCustodyTerminal {
	t.Helper()
	old := custodyTerminalGolden(t)
	intent := old.Intent
	intent.ConsumerPublicKey = testPublic(4)
	intentID, _ := intent.ID()
	audit := remoteStoreSign(t, custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: intent.AssignmentID,
		ExpectedHead: intent.AssignmentID, Kind: custodyauthority.Admit, Purpose: custodyauthority.Audit, OperationID: intentID}, 4)
	entryID, _ := old.Entry.ID()
	seal := remoteworker.Seal{PlanID: testHash(216), BeginID: testHash(217), SealingID: testHash(218), Disposition: remoteworker.RetainedResult, ResultID: entryID}
	sealID, _ := seal.ID()
	drain := remoteStoreSign(t, custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: intent.AssignmentID,
		ExpectedSequence: 3, ExpectedHead: seal.BeginID, Kind: custodyauthority.RemoteDrained, OperationID: seal.BeginID, TicketID: testHash(219), EvidenceID: sealID}, 14)
	return RemoteCustodyTerminal{PlanID: seal.PlanID, BeginID: seal.BeginID, AuditAdmission: audit, Intent: intent, Seal: seal, Drained: drain, Entry: old.Entry}
}

func TestRemoteCustodyTerminalCodecVectorAndSubstitution(t *testing.T) {
	terminal := remoteTerminalCodecVector(t)
	b, err := terminal.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := terminal.ID()
	if len(b) != 3809 || id.String() != "65bdc27adc12bbb246f043845034d5f43ffdba2a64f31a6325332d00dc580eab" {
		t.Fatalf("remote terminal golden changed: bytes=%d id=%s", len(b), id)
	}
	parsed, err := DecodeRemoteCustodyTerminal(b)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := parsed.ID()
	if got != id {
		t.Fatal("terminal id changed")
	}
	for _, offset := range []int{0, 8, 10, 80, len(b) - 1} {
		bad := append([]byte(nil), b...)
		bad[offset] ^= 1
		if _, err := DecodeRemoteCustodyTerminal(bad); err == nil {
			t.Fatal("substituted canonical bytes accepted", offset)
		}
	}
	for _, mutate := range []func(*RemoteCustodyTerminal){
		func(v *RemoteCustodyTerminal) {
			v.Seal.Disposition = remoteworker.NoResult
			v.Seal.ResultID = types.Hash{}
		},
		func(v *RemoteCustodyTerminal) { v.Seal.ResultID = testHash(220) },
		func(v *RemoteCustodyTerminal) { v.BeginID = testHash(221) },
		func(v *RemoteCustodyTerminal) { v.Intent.PriorHeadID = testHash(222) },
	} {
		v, err := DecodeRemoteCustodyTerminal(b)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&v)
		if _, err := v.CanonicalBytes(); err == nil {
			t.Fatal("substituted terminal accepted")
		}
	}
}

func FuzzDecodeRemoteCustodyTerminal(f *testing.F) {
	v := remoteTerminalCodecVector(f)
	b, err := v.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("OMCRTERM"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		v, err := DecodeRemoteCustodyTerminal(input)
		if err != nil {
			return
		}
		canonical, err := v.CanonicalBytes()
		if err != nil || !bytes.Equal(input, canonical) {
			t.Fatal("noncanonical remote terminal", err)
		}
	})
}

type remoteCleanupFaultStream struct {
	network.Stream
	closeErr, resetErr error
	closes, resets     int
}

func (s *remoteCleanupFaultStream) Close() error { s.closes++; return s.closeErr }
func (s *remoteCleanupFaultStream) Reset() error { s.resets++; return s.resetErr }

func TestRemoteCustodyStreamDrainRequiresConfirmedCloseOrReset(t *testing.T) {
	closeErr, resetErr := errors.New("graceful close failed"), errors.New("abort failed")
	for _, test := range []struct {
		close, reset error
		wantReset    int
	}{
		{nil, nil, 0}, {closeErr, nil, 1}, {closeErr, resetErr, 1},
	} {
		underlying := &remoteCleanupFaultStream{closeErr: test.close, resetErr: test.reset}
		owned := &remoteCustodyNetworkStream{Stream: underlying}
		for range 2 {
			err := owned.Close()
			if test.reset != nil {
				if !errors.Is(err, closeErr) || !errors.Is(err, resetErr) {
					t.Fatal("lost uncertain cleanup", err)
				}
			} else if err != nil {
				t.Fatal("channel termination failed", err)
			}
		}
		if underlying.closes != 1 || underlying.resets != test.wantReset {
			t.Fatal("cleanup was repeated or abort omitted", underlying)
		}
	}
}
