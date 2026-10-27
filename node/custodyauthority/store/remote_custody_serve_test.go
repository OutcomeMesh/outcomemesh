package store

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func remoteServeTestOpen(t testing.TB, f *remoteExecutionFixture, config RemoteCustodyServeServiceConfig) *RemoteCustodyServeService {
	t.Helper()
	service, err := OpenRemoteCustodyServeService(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(t.Context(), testKey(15), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if len(service.Addresses()) == 0 {
		t.Fatal("remote service did not expose a direct address")
	}
	return service
}

func remoteServeTestControl(t testing.TB, f *remoteExecutionFixture, service *RemoteCustodyServeService, kind remotewire.Kind, key byte) (remotewire.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	client, err := libp2ptransport.New(ctx, testKey(key), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, _, err := client.OpenRemoteCustodyControlStream(ctx, service.Addresses()[0], runtimePeer(15))
	if err != nil {
		return remotewire.Response{}, err
	}
	request := remotewire.Request{Version: remotewire.Version0, Kind: kind, Nonce: testHash(byte(220 + kind)), Plan: f.scope.Worker.Plan, Begin: f.scope.Worker.Begin}
	response, err := remotewire.Exchange(ctx, stream, request, 2*time.Second)
	if err == nil {
		err = remotewire.ValidateResponse(f.scope.Worker.Assignment, request, response)
	}
	return response, err
}

type remoteServeTestAuditResult struct {
	response workarchive.CustodyResponse
	err      error
}

func remoteServeTestAudit(t testing.TB, f *remoteExecutionFixture, service *RemoteCustodyServeService) <-chan remoteServeTestAuditResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	client, err := libp2ptransport.New(ctx, testKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	stream, _, err := client.OpenArchiveCustodyStream(ctx, service.Addresses()[0], runtimePeer(15))
	if err != nil {
		ch := make(chan remoteServeTestAuditResult, 1)
		ch <- remoteServeTestAuditResult{err: err}
		return ch
	}
	auditor, err := workarchive.NewCustodyAuditorSession(f.scope.Manifest, f.scope.PreviousReceipt, f.scope.CustodyPolicy, f.base.config.SessionConfig)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan remoteServeTestAuditResult, 1)
	go func() {
		response, _, err := auditor.Audit(ctx, stream, f.scope.Challenge)
		_ = client.Close()
		ch <- remoteServeTestAuditResult{response, err}
	}()
	return ch
}

func TestRemoteCustodyServeStartSealRetainedAckAndNoAuthorityCopy(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	owner := f.openOwner(t)
	appendCoordinated(t, owner, f.scope.Worker.Begin)
	before := testCoordination(t, owner)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	service := remoteServeTestOpen(t, f, f.serveConfig())
	if _, err := remoteServeTestControl(t, f, service, remotewire.Reconcile, 16); err == nil {
		t.Fatal("prepared Reconcile mutated worker")
	}
	if state, err := service.worker.Snapshot(t.Context()); err != nil || state.Stage != remoteworker.Prepared {
		t.Fatal(state, err)
	}
	if _, err := remoteServeTestControl(t, f, service, remotewire.Start, 17); err == nil {
		t.Fatal("unlisted controller started work")
	}
	if response, err := remoteServeTestControl(t, f, service, remotewire.Start, 16); err != nil || response.Status != remotewire.StatusStarted {
		t.Fatal(response, err)
	}
	result := <-remoteServeTestAudit(t, f, service)
	if result.err != nil {
		t.Fatal(result.err)
	}
	head, exists, err := f.base.serve.journal.Head()
	if err != nil || !exists {
		t.Fatal(exists, err)
	}
	headID, _ := head.ID()
	response, err := remoteServeTestControl(t, f, service, remotewire.Seal, 16)
	if err != nil || response.Status != remotewire.StatusDrained || response.Seal.Disposition != remoteworker.RetainedResult || response.Seal.ResultID != headID {
		t.Fatal(response, err)
	}
	if err := ValidateRemoteCustodyDrain(f.scope, response.Seal, response.Drain); err != nil {
		t.Fatal(err)
	}
	if result := <-remoteServeTestAudit(t, f, service); result.err == nil {
		t.Fatal("sealed service replayed a custody response")
	}
	retry, err := remoteServeTestControl(t, f, service, remotewire.Reconcile, 16)
	if err != nil || retry.Seal != response.Seal || retry.Drain != response.Drain {
		t.Fatal("sealed reconciliation refreshed acknowledgement", retry, err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	service = remoteServeTestOpen(t, f, f.serveConfig())
	if _, err := remoteServeTestControl(t, f, service, remotewire.Start, 16); err == nil {
		t.Fatal("reopened sealed worker accepted Start")
	}
	retry, err = remoteServeTestControl(t, f, service, remotewire.Reconcile, 16)
	if err != nil || retry.Seal != response.Seal || retry.Drain != response.Drain {
		t.Fatal("reopened seal changed acknowledgement", retry, err)
	}
	owner = f.openOwner(t)
	after := testCoordination(t, owner)
	if !reflect.DeepEqual(before, after) || after.Authority.Remote == nil {
		t.Fatal("B cleared A hold or changed its authority", after)
	}
}

func TestRemoteCustodyServeReopenedStartedNeverFresh(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Start(t.Context(), f.scope.Worker.BeginID); err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	config := f.serveConfig()
	var nowCalls atomic.Int32
	config.SessionConfig.Now = func() uint64 { nowCalls.Add(1); return f.base.serve.now }
	service := remoteServeTestOpen(t, f, config)
	if response, err := remoteServeTestControl(t, f, service, remotewire.Reconcile, 16); err != nil || response.Status != remotewire.StatusStarted {
		t.Fatal(response, err)
	}
	if _, err := remoteServeTestControl(t, f, service, remotewire.Start, 16); err == nil {
		t.Fatal("reopened Started created a fresh allowance")
	}
	if result := <-remoteServeTestAudit(t, f, service); result.err == nil {
		t.Fatal("reopened Started signed without committed cache")
	}
	if nowCalls.Load() != 0 {
		t.Fatal("reopened noncached worker reached proof session", nowCalls.Load())
	}
	response, err := remoteServeTestControl(t, f, service, remotewire.Seal, 16)
	if err != nil || response.Seal.Disposition != remoteworker.NoResult || !response.Seal.ResultID.IsZero() {
		t.Fatal(response, err)
	}
	if state, err := f.base.serve.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("unknown start minted a proof", state.Sequence, err)
	}
}

func TestRemoteCustodyServeReopenedCacheCannotRefreshExpiredProof(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Start(t.Context(), f.scope.Worker.BeginID); err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	entry, _, err := f.base.serve.journal.Append(f.base.answer(t))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := entry.ID()
	config := f.serveConfig()
	config.SessionConfig.Now = func() uint64 { return entry.Record.Proof.RespondedAt + f.scope.CustodyPolicy.MaximumProofAge + 1 }
	service := remoteServeTestOpen(t, f, config)
	if _, err := remoteServeTestControl(t, f, service, remotewire.Start, 16); err != nil {
		t.Fatal("exact committed cache was unavailable", err)
	}
	if result := <-remoteServeTestAudit(t, f, service); result.err == nil {
		t.Fatal("expired cache was refreshed or delivered")
	}
	current, ok, err := f.base.serve.journal.Head()
	currentID, _ := current.ID()
	if err != nil || !ok || currentID != id {
		t.Fatal("expired retry changed committed evidence", err)
	}
	response, err := remoteServeTestControl(t, f, service, remotewire.Seal, 16)
	if err != nil || response.Seal.ResultID != id || response.Seal.Disposition != remoteworker.RetainedResult {
		t.Fatal("historical drain lost exact old result", response, err)
	}
}

func TestRemoteCustodyServeCloseSealsBeforeCancellingAndRetainsOwner(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	service := remoteServeTestOpen(t, f, f.serveConfig())
	if _, err := remoteServeTestControl(t, f, service, remotewire.Start, 16); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	service.hooks.at = func(stage string) error {
		if stage == "remote-data-admitted" {
			close(entered)
			<-release
		}
		return nil
	}
	result := remoteServeTestAudit(t, f, service)
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- service.Close() }()
	deadline := time.After(2 * time.Second)
	for {
		state, err := service.worker.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if state.Stage == remoteworker.Sealing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Close did not retain sealing before drain")
		case <-time.After(time.Millisecond):
		}
	}
	if other, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker); !errors.Is(err, remoteworker.ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("Close released original worker before callback drain", err)
	}
	select {
	case err := <-closed:
		t.Fatal("Close returned while accepted callback was blocked", err)
	default:
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if response := <-result; response.err == nil {
		t.Fatal("cancelled data call reported delivery")
	}
	worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	state, err := worker.Snapshot(t.Context())
	if err != nil || state.Stage != remoteworker.Sealed || state.Seal == nil || state.Seal.Disposition != remoteworker.NoResult {
		t.Fatal("Close did not preserve closed unknown branch", state, err)
	}
	if _, err := worker.Start(t.Context(), f.scope.Worker.BeginID); !errors.Is(err, remoteworker.ErrTransition) {
		t.Fatal("Close reopened Start", err)
	}
}

func TestRemoteCustodyServeOpenRejectsRoleKeysAndOverlappingRoots(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	for _, mutate := range []func(*RemoteCustodyServeServiceConfig){
		func(c *RemoteCustodyServeServiceConfig) { c.ControlPrivateKey = testKey(15) },
		func(c *RemoteCustodyServeServiceConfig) { c.ReplicaPrivateKey = testKey(14) },
		func(c *RemoteCustodyServeServiceConfig) { c.JournalPath = c.WorkerPath },
		func(c *RemoteCustodyServeServiceConfig) { c.ObjectPath = c.JournalPath },
	} {
		config := f.serveConfig()
		mutate(&config)
		if service, err := OpenRemoteCustodyServeService(t.Context(), config); err == nil {
			_ = service.Close()
			t.Fatal("invalid B owner/key placement opened")
		}
	}
	worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal("failed Open leaked original worker owner", err)
	}
	defer worker.Close()
	state, err := worker.Snapshot(t.Context())
	if err != nil || state.Stage != remoteworker.Prepared {
		t.Fatal("failed Open sealed or started work", state, err)
	}
}
