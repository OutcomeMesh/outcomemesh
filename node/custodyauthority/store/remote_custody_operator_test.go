package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestRemoteCustodySealReplyFailureRetainsOriginalHold(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	a, b, address := openRemoteTerminalPair(t, f, f.auditConfig(t))
	if _, err := a.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err != nil {
		t.Fatal(err)
	}
	b.hooks.at = func(stage string) error {
		if stage == "remote-control-drained-before-response-write" {
			return errors.New("injected lost sealed reply")
		}
		return nil
	}
	if _, err := a.SealQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), address); err == nil {
		t.Fatal("lost reply confirmed A's drain")
	}
	b.controlWG.Wait()
	state := testCoordination(t, a.life.owner)
	if state.Authority.Remote == nil || state.Confirmed.Sequence != 3 || state.Authority.Pending != 2 {
		t.Fatal("lost reply released original obligation", state)
	}
	r, err := b.Review(t.Context())
	if err != nil || r.WorkerStage != remoteworker.Sealed || r.SealID.IsZero() {
		t.Fatal("B seal not retained", r, err)
	}
	b.hooks.at = nil
	reply, err := a.SealQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), address)
	sealID, _ := reply.Seal.ID()
	if err != nil || sealID != r.SealID {
		t.Fatal("retry replaced sealed history", err)
	}
	if current := testCoordination(t, a.life.owner); current.Authority.Remote != nil || current.Confirmed.Sequence != 4 || current.Authority.Pending != 2 {
		t.Fatal("retry did not independently confirm exact drain", current)
	}
}

func TestRemoteCustodyOperatorReviewsNeverGrantStaleActions(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	cfg := f.auditConfig(t)
	a, err := OpenRemoteCustodyAuditRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r, err := a.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := r.ID()
	run, err := WithRemoteCustodyReview(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.PrepareChallenge(run); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Begin(run); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ExecuteQUIC(run, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), "invalid"); !errors.Is(err, ErrManagedCustodyReview) {
		t.Fatal("stale comparison reached network", err)
	}
	if _, err := WithRemoteCustodyReview(context.Background(), types.Hash{}); err == nil {
		t.Fatal("zero comparison accepted")
	}
	before, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := before.Snapshot(t.Context())
	_ = before.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRemoteCustodyServe(t.Context(), f.serveConfig()); err != nil {
		t.Fatal(err)
	}
	worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	after, err := worker.Snapshot(t.Context())
	if err != nil || !reflect.DeepEqual(snapshot, after) {
		t.Fatal("inspection sealed or advanced worker", after, err)
	}
}

func TestRemoteCustodyOperatorRetainedFilesAndHistoricalReconciliation(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	cfg := f.auditConfig(t)
	a, b, address := openRemoteTerminalPair(t, f, cfg)
	if _, err := a.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err != nil {
		t.Fatal(err)
	}
	reply, err := a.SealQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), address)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "drain")
	id, err := PublishRemoteCustodyDrain(t.Context(), path, f.scope, reply)
	if err != nil {
		t.Fatal(err)
	}
	// Different exchange nonces produce the same portable sealed evidence.
	reply.Nonce = testHash(255)
	again, err := PublishRemoteCustodyDrain(t.Context(), path, f.scope, reply)
	if err != nil || again != id {
		t.Fatal("unstable retained metadata", again, err)
	}
	stored, err := LoadRemoteCustodyDrain(path, id, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	a, err = OpenRemoteCustodyAuditRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	reconciled, err := a.ReconcileQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), address)
	if err != nil {
		t.Fatal("lost output could not recover confirmed drain", err)
	}
	_, rid, err := RemoteCustodyDrainArtifact(f.scope, reconciled)
	if err != nil || rid != id {
		t.Fatal("reconciliation selected another result", err)
	}
	out := filepath.Join(t.TempDir(), "terminal")
	term, err := a.CaptureTerminalToFile(t.Context(), stored, out)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := term.ID()
	if _, err := LoadRemoteCustodyTerminal(out, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CaptureTerminalToFile(t.Context(), stored, out); err != nil {
		t.Fatal("exact capture retry", err)
	}
	if _, err := a.CaptureTerminalToFile(t.Context(), stored, filepath.Join(f.authorityPath, "forbidden")); err == nil {
		t.Fatal("published into authority root")
	}
	if err := os.WriteFile(out, []byte("conflict"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CaptureTerminalToFile(t.Context(), stored, out); err == nil {
		t.Fatal("replaced retained terminal")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}
