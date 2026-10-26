package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func managedServeServiceConfig(f *managedServeFixture) ManagedCustodyServeServiceConfig {
	scope := f.config
	scope.Objects = nil
	scope.AuditorPeerID = runtimePeer(44)
	return ManagedCustodyServeServiceConfig{AuthorityPath: f.archive.f.authorityPath, AuthorityPinsPath: f.archive.f.pinsPath,
		Assignment: f.archive.policy.Assignments[0], Session: scope, ObjectPath: f.config.Objects.Directory(),
		ObjectPolicy: workarchive.DefaultObjectStorePolicy(), ServerPeerID: runtimePeer(45)}
}

func openManagedServeService(t testing.TB, f *managedServeFixture) (*ManagedCustodyServeService, ManagedCustodyServeServiceConfig) {
	t.Helper()
	config := managedServeServiceConfig(f)
	if err := f.archive.f.coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	service, err := OpenManagedCustodyServeService(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service, config
}

func assertManagedServeServiceBusy(t testing.TB, config ManagedCustodyServeServiceConfig) {
	t.Helper()
	other, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Assignment, config.Session.AssignmentID)
	if !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("original coordinator was released", err)
	}
}

func TestManagedCustodyServeServiceZeroAndNilLifecycle(t *testing.T) {
	for _, service := range []*ManagedCustodyServeService{nil, {}} {
		if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if len(service.Addresses()) != 0 {
			t.Fatal("unopened service exposed routes")
		}
		for range 2 {
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestManagedCustodyServeServiceOwnershipAndFailedStart(t *testing.T) {
	f := newManagedServeFixture(t)
	config := managedServeServiceConfig(f)
	if other, err := OpenManagedCustodyServeService(config); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("duplicate original owner accepted", err)
	}
	before := testCoordination(t, f.archive.f.coordinator)
	service, config := openManagedServeService(t, f)
	assertManagedServeServiceBusy(t, config)
	if err := service.Start(t.Context(), testKey(46), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrManagedCustodyServeService) {
		t.Fatal("wrong server identity accepted", err)
	}
	if len(service.Addresses()) != 0 {
		t.Fatal("failed Start leaked a listener")
	}
	assertManagedServeServiceBusy(t, config)
	select {
	case <-service.Done():
		t.Fatal("failed Start released ownership")
	default:
	}
	if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrManagedCustodyServeStarted) {
		t.Fatal("second Start accepted", err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.Done():
	default:
		t.Fatal("Close returned before Done")
	}
	if len(service.Addresses()) != 0 {
		t.Fatal("closed service retained routes")
	}
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Assignment, config.Session.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if !reflect.DeepEqual(before, testCoordination(t, owner)) {
		t.Fatal("service lifecycle changed authority")
	}
}

func TestManagedCustodyServeServicePinnedQUICAndReopen(t *testing.T) {
	f := newManagedServeFixture(t)
	before := testCoordination(t, f.archive.f.coordinator)
	service, config := openManagedServeService(t, f)
	var first workarchive.CustodyResponse
	for cycle := range 2 {
		if cycle != 0 {
			var err error
			service, err = OpenManagedCustodyServeService(config)
			if err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		if err := service.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
			cancel()
			t.Fatal(err)
		}
		client, err := libp2ptransport.New(ctx, testKey(44), libp2ptransport.DefaultConfig(), nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		addresses := service.Addresses()
		if len(addresses) != 1 {
			t.Fatal("missing managed server route", addresses)
		}
		stream, peer, err := client.OpenArchiveCustodyStream(ctx, addresses[0], config.ServerPeerID)
		if err != nil || peer != config.ServerPeerID {
			t.Fatal("pinned route failed", err)
		}
		auditor, err := workarchive.NewCustodyAuditorSession(config.Session.Manifest, config.Session.InitialReceipt,
			config.Session.CustodyPolicy, config.Session.SessionConfig)
		if err != nil {
			t.Fatal(err)
		}
		response, _, err := auditor.Audit(ctx, stream, f.challenge)
		if err != nil {
			t.Fatal("managed server exchange failed", err)
		}
		if cycle == 0 {
			first = response
		} else if !reflect.DeepEqual(first, response) {
			t.Fatal("reopened service regenerated its signed response")
		}
		if !reflect.DeepEqual(before, testCoordination(t, service.coordinator)) {
			t.Fatal("network delivery changed authority")
		}
		f.state(t, 1)
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		cancel()
	}
}

type managedServeServiceStream struct {
	network.Stream
	workarchive.CustodySessionStream
	resets atomic.Int32
}

func (stream *managedServeServiceStream) Read(p []byte) (int, error) {
	return stream.CustodySessionStream.Read(p)
}
func (stream *managedServeServiceStream) Write(p []byte) (int, error) {
	return stream.CustodySessionStream.Write(p)
}
func (stream *managedServeServiceStream) SetDeadline(deadline time.Time) error {
	return stream.CustodySessionStream.SetDeadline(deadline)
}
func (stream *managedServeServiceStream) Close() error { return stream.CustodySessionStream.Close() }
func (stream *managedServeServiceStream) Reset() error { stream.resets.Add(1); return nil }

type managedServeServiceCloseFailure struct {
	*managedServeStream
	err error
}

func (stream *managedServeServiceCloseFailure) Close() error {
	_ = stream.managedServeStream.Close()
	return stream.err
}

func TestManagedCustodyServeServiceRetainsCleanupFailure(t *testing.T) {
	f := newManagedServeFixture(t)
	service, config := openManagedServeService(t, f)
	if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("managed service stream cleanup failed")
	raw := &managedServeServiceCloseFailure{managedServeStream: newManagedServeStream(t, f.challenge), err: injected}
	stream := &managedServeServiceStream{CustodySessionStream: raw}
	service.handle(service.runContext, config.Session.AuditorPeerID, stream)
	select {
	case <-service.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup failure did not stop the service")
	}
	if err := service.Close(); !errors.Is(err, injected) {
		t.Fatal("service hid actual stream-close failure", err)
	}
	if err := service.Close(); !errors.Is(err, injected) {
		t.Fatal("repeated Close lost cleanup failure", err)
	}
	if raw.closes.Load() != 1 {
		t.Fatal("cleanup failure repeated actual Close", raw.closes.Load())
	}
	owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Assignment, config.Session.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if current := testCoordination(t, owner); current.Authority.Pending != 2 || current.Pending != nil {
		t.Fatal("cleanup failure changed authority")
	}
	f.state(t, 1)
}

func TestManagedCustodyServeServiceCloseDrainsActualStreamClose(t *testing.T) {
	f := newManagedServeFixture(t)
	service, config := openManagedServeService(t, f)
	if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	raw := newManagedServeStream(t, f.challenge)
	raw.closeEntered, raw.releaseClose = make(chan struct{}), release
	stream := &managedServeServiceStream{CustodySessionStream: raw}
	handled := make(chan struct{})
	go func() { defer close(handled); service.handle(service.runContext, config.Session.AuditorPeerID, stream) }()
	select {
	case <-raw.closeEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not reach actual close")
	}
	closed := make(chan error, 1)
	go func() { closed <- service.Close() }()
	select {
	case err := <-closed:
		t.Fatal("released owners before actual close", err)
	case <-time.After(30 * time.Millisecond):
	}
	deadline := time.After(5 * time.Second)
	for {
		service.gate.Lock()
		accepting := service.accepting
		service.gate.Unlock()
		if !accepting {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Close did not close handler admission")
		case <-time.After(time.Millisecond):
		}
	}
	assertManagedServeServiceBusy(t, config)
	lateRaw := newManagedServeStream(t, f.challenge)
	late := &managedServeServiceStream{CustodySessionStream: lateRaw}
	service.handle(t.Context(), config.Session.AuditorPeerID, late)
	if late.resets.Load() != 1 || lateRaw.reads.Load() != 0 || lateRaw.writes.Load() != 0 {
		t.Fatal("closed admission gate touched the session")
	}
	once.Do(func() { close(release) })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close failed to drain the handler")
	}
	<-handled
	if raw.closes.Load() != 1 {
		t.Fatal("actual stream close repeated", raw.closes.Load())
	}
}

func TestManagedCustodyServeServiceCancellationDrainsBeforeOwnerRelease(t *testing.T) {
	for _, blockRequest := range []bool{true, false} {
		t.Run(map[bool]string{true: "request", false: "auditor-eof"}[blockRequest], func(t *testing.T) {
			f := newManagedServeFixture(t)
			service, config := openManagedServeService(t, f)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := service.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			var once sync.Once
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			raw := &managedServeCancellationStream{managedServeStream: newManagedServeStream(t, f.challenge),
				blockRequest: blockRequest, blocked: make(chan struct{}), closed: make(chan struct{}),
				closeStarted: make(chan struct{}), release: release}
			stream := &managedServeServiceStream{CustodySessionStream: raw}
			handled := make(chan struct{})
			go func() { defer close(handled); service.handle(service.runContext, config.Session.AuditorPeerID, stream) }()
			select {
			case <-raw.blocked:
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not block on input")
			}
			cancel()
			select {
			case <-raw.closeStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("context cancellation did not close accepted stream")
			}
			assertManagedServeServiceBusy(t, config)
			select {
			case <-service.Done():
				t.Fatal("context cancellation released owners before cleanup")
			default:
			}
			once.Do(func() { close(release) })
			select {
			case <-service.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled service did not drain")
			}
			<-handled
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, config.Assignment, config.Session.AssignmentID)
			if err != nil {
				t.Fatal(err)
			}
			if current := testCoordination(t, owner); current.Authority.Pending != 2 || current.Pending != nil {
				t.Fatal("cancellation changed pending authority")
			}
			_ = owner.Close()
			sequence := uint64(1)
			if blockRequest {
				sequence = 0
			}
			f.state(t, sequence)
		})
	}
}

func TestManagedCustodyServeServiceRejectsInvalidScopeWithoutInitialization(t *testing.T) {
	for _, mode := range []string{"caller-objects", "missing-objects", "missing-journal", "overlap", "server-role-key", "same-peer", "unadmitted", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedServeFixture(t)
			config := managedServeServiceConfig(f)
			ctx := t.Context()
			switch mode {
			case "caller-objects":
				config.Session.Objects = f.config.Objects
			case "missing-objects":
				config.ObjectPath = filepath.Join(t.TempDir(), "missing-objects")
			case "missing-journal":
				config.Session.JournalPath = filepath.Join(t.TempDir(), "missing-journal")
			case "overlap":
				config.ObjectPath = config.AuthorityPath
			case "server-role-key":
				config.ServerPeerID = runtimePeer(1)
			case "same-peer":
				config.ServerPeerID = config.Session.AuditorPeerID
			case "unadmitted":
				snapshot := testCoordination(t, f.archive.f.coordinator).Authority
				command := config.Session.Admission.Command
				command.ExpectedSequence, command.ExpectedHead = snapshot.Sequence, snapshot.HeadID
				command, _ = command.Sign(testKey(4))
				config.Session.Admission, _ = custodyauthority.SignEntry(command, testKey(1))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := testCoordination(t, f.archive.f.coordinator)
			if err := f.archive.f.coordinator.Close(); err != nil {
				t.Fatal(err)
			}
			service, err := OpenManagedCustodyServeServiceContext(ctx, config)
			if err == nil || service != nil {
				if service != nil {
					_ = service.Close()
				}
				t.Fatal("invalid service scope accepted", err)
			}
			if mode == "missing-objects" || mode == "missing-journal" {
				path := config.ObjectPath
				if mode == "missing-journal" {
					path = config.Session.JournalPath
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("constructor created missing evidence", err)
				}
			}
			owner, err := OpenCoordinator(f.archive.f.authorityPath, f.archive.f.pinsPath, f.archive.policy.Assignments[0], f.config.AssignmentID)
			if err != nil {
				t.Fatal("failed constructor retained original owner", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, owner)) {
				t.Fatal("failed constructor changed authority")
			}
			_ = owner.Close()
		})
	}
}
