package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// Capture paths while their owners are still open. Complete deliberately has no
// primary paths: a missing or independently owned primary must not be consulted.
func archiveSecondaryServiceConfig(t testing.TB, p *archivePruneFixture, mode PruneSecondaryCommandMode) PruneSecondaryCommandServiceConfig {
	t.Helper()
	secondary := p.operations[1].Coordinator
	config := PruneSecondaryCommandServiceConfig{Session: archiveSecondarySessionConfig(p), Mode: mode,
		ExecutorPath: p.f.executorPath, ExecutorPinsPath: p.f.executorPinsPath,
		AuthorityPath: secondary.authority.path, AuthorityPinsPath: secondary.journal.path}
	if mode != PruneSecondaryCompletion {
		primary := p.operations[0].Coordinator
		config.PrimaryAuthorityPath, config.PrimaryAuthorityPinsPath = primary.authority.path, primary.journal.path
	}
	return config
}

func openArchiveSecondaryService(t testing.TB, p *archivePruneFixture, config PruneSecondaryCommandServiceConfig) *PruneSecondaryCommandService {
	t.Helper()
	if err := p.f.executor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.operations[1].Coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	if config.Mode != PruneSecondaryCompletion {
		if err := p.operations[0].Coordinator.Close(); err != nil {
			t.Fatal(err)
		}
	}
	service, err := OpenPruneSecondaryCommandService(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func startArchiveSecondaryService(t testing.TB, service *PruneSecondaryCommandService) string {
	t.Helper()
	if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if addresses := service.Addresses(); len(addresses) == 1 {
		return addresses[0]
	}
	t.Fatal("secondary service did not expose one route", service.Addresses())
	return ""
}

func archiveSecondaryServiceClient(t testing.TB) *libp2ptransport.Host {
	t.Helper()
	client, err := libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func assertArchiveSecondaryServiceOwnersBusy(t testing.TB, p *archivePruneFixture, config PruneSecondaryCommandServiceConfig) {
	t.Helper()
	if owner, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, p.policy.Assignments[0], p.f.id); !errors.Is(err, ErrBusy) {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("secondary service released executor ownership", err)
	}
	pairs := []struct {
		path, pins string
		index      int
	}{{config.AuthorityPath, config.AuthorityPinsPath, 1}}
	if config.PrimaryAuthorityPath != "" {
		pairs = append(pairs, struct {
			path, pins string
			index      int
		}{config.PrimaryAuthorityPath, config.PrimaryAuthorityPinsPath, 0})
	}
	for _, pair := range pairs {
		if owner, err := OpenCoordinator(pair.path, pair.pins, p.policy.Assignments[pair.index], p.operations[pair.index].Binding.AssignmentID); !errors.Is(err, ErrBusy) {
			if owner != nil {
				_ = owner.Close()
			}
			t.Fatal("secondary service released coordinator ownership", pair.index, err)
		}
	}
}

// The service must be closed first. This is an explicit local handoff to the
// existing guarded executor; the service itself never performs a prune/cancel.
func reopenArchiveSecondaryServiceOwners(t testing.TB, p *archivePruneFixture, config PruneSecondaryCommandServiceConfig) {
	t.Helper()
	var err error
	p.f.executor, err = OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, p.policy.Assignments[0], p.f.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.f.executor.Close() })
	for i, pair := range []struct{ path, pins string }{
		{config.PrimaryAuthorityPath, config.PrimaryAuthorityPinsPath}, {config.AuthorityPath, config.AuthorityPinsPath},
	} {
		owner, err := OpenCoordinator(pair.path, pair.pins, p.policy.Assignments[i], p.operations[i].Binding.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = owner.Close() })
		p.operations[i].Coordinator = owner
	}
	p.f.coordinator = p.operations[0].Coordinator
}

func archiveSecondaryServiceAdmissionOutbox(t testing.TB, p *archivePruneFixture, inventory ArchivePruneInventory) *AdmissionOutbox {
	t.Helper()
	intent := AdmissionIntent{ClientPeerID: runtimePeer(46), ServerPeerID: runtimePeer(45), Entry: inventory.Admissions[1]}
	id, err := intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := CreateAdmissionOutbox(filepath.Join(t.TempDir(), "admit"), p.policy.Assignments[1], intent, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	return outbox
}

func TestArchiveSecondaryServiceNilAndZeroLifecycle(t *testing.T) {
	for _, service := range []*PruneSecondaryCommandService{nil, {}} {
		if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if len(service.Addresses()) != 0 || service.Done() != nil {
			t.Fatal("unopened secondary service exposed a lifetime")
		}
		for range 2 {
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestArchiveSecondaryServiceBothThenOfflineOutcomeAndCompletion(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			var renewals []int
			if outcome == "succeeded" {
				renewals = []int{2, 1}
			}
			p, inventory := newArchiveSecondaryFixture(t, renewals)
			config := archiveSecondaryServiceConfig(t, p, PruneSecondaryBoth)
			before, primary := pruneSnapshot(t, p.f.executor), testCoordination(t, p.f.coordinator)
			service := openArchiveSecondaryService(t, p, config)
			assertArchiveSecondaryServiceOwnersBusy(t, p, config)
			if len(service.Addresses()) != 0 || testCoordination(t, service.runtime.coordinator).Authority.Sequence != 0 ||
				!reflect.DeepEqual(before, pruneSnapshot(t, service.runtime.executor)) {
				t.Fatal("open listened or advanced retained work")
			}
			address := startArchiveSecondaryService(t, service)
			if service.runtime.admission == nil || service.runtime.completion == nil {
				t.Fatal("both mode omitted a command handler")
			}
			client := archiveSecondaryServiceClient(t)
			admission := archiveSecondaryServiceAdmissionOutbox(t, p, inventory)
			ack, err := admission.Deliver(t.Context(), client, address, 2*time.Second)
			if err != nil || ack.EntryID != p.operations[1].Binding.TicketID {
				t.Fatal("managed secondary admission was not confirmed", err)
			}
			secondary := testCoordination(t, service.runtime.coordinator)
			if secondary.Pending != nil || secondary.Authority.Pending != 1 || secondary.Authority.Operations[0].OperationID != p.f.id ||
				!reflect.DeepEqual(primary, testCoordination(t, service.runtime.preparedSecondary.primary)) ||
				!reflect.DeepEqual(before, pruneSnapshot(t, service.runtime.executor)) {
				t.Fatal("managed admission changed the original request, primary or executor")
			}
			premature := testEntry(t, secondary.Authority, custodyauthority.Complete, types.Hash{}, ack.EntryID, testHash(98))
			if got, err := client.CompletePrune(t.Context(), address, runtimePeer(45), premature, 2*time.Second); !errors.Is(err, completionwire.ErrUnconfirmed) || got != (completionwire.Acknowledgement{}) {
				t.Fatal("preterminal completion was acknowledged", err)
			}
			if !reflect.DeepEqual(secondary, testCoordination(t, service.runtime.coordinator)) {
				t.Fatal("preterminal completion changed the target")
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			waitPruneRuntimeDone(t, service.runtime)
			reopenArchiveSecondaryServiceOwners(t, p, config)
			if outcome == "cancelled" {
				if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
					t.Fatal(err)
				}
			} else if commit, err := p.execute(t.Context()); err != nil || !commit.Applied {
				t.Fatal("offline guarded execution failed", err)
			}
			entry, terminal := archiveSecondaryCompletionEntry(t, p), pruneSnapshot(t, p.f.executor)
			completionConfig := archiveSecondaryServiceConfig(t, p, PruneSecondaryCompletion)
			if outcome == "cancelled" {
				// For the other outcome the primary remains externally owned. In
				// this branch both of its roots are absent from their original paths.
				if err := p.f.coordinator.Close(); err != nil {
					t.Fatal(err)
				}
				for _, root := range []string{config.PrimaryAuthorityPath, config.PrimaryAuthorityPinsPath} {
					if err := os.Rename(root, filepath.Join(t.TempDir(), "retained-primary")); err != nil {
						t.Fatal(err)
					}
				}
			}
			service = openArchiveSecondaryService(t, p, completionConfig)
			address = startArchiveSecondaryService(t, service)
			if service.runtime.admission != nil || service.runtime.completion == nil || service.runtime.preparedSecondary.primary != nil || len(service.runtime.preparedSecondary.owners) != 1 {
				t.Fatal("completion-only service acquired a primary or enabled admission")
			}
			intent := CompletionIntent{ClientPeerID: runtimePeer(46), ServerPeerID: runtimePeer(45), Entry: entry}
			id, _ := intent.ID()
			outbox, err := CreateCompletionOutbox(filepath.Join(t.TempDir(), "complete"), p.policy.Assignments[1], intent, id)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = outbox.Close() })
			completed, err := outbox.Deliver(t.Context(), client, address, 2*time.Second)
			entryID, _ := entry.ID()
			if err != nil || completed.EntryID != entryID {
				t.Fatal("completion-only delivery required the primary", err)
			}
			confirmed := testCoordination(t, service.runtime.coordinator)
			if confirmed.Pending != nil || confirmed.Authority.Pending != 0 || confirmed.Authority.Operations[0].OperationID != p.f.id ||
				!reflect.DeepEqual(terminal, pruneSnapshot(t, service.runtime.executor)) {
				t.Fatal("completion changed terminal executor history or original request")
			}
			// A valid historical Admit would succeed on an installed admission
			// handler; completion mode must reject the disabled protocol instead.
			if got, err := client.AdmitPrune(t.Context(), address, runtimePeer(45), inventory.Admissions[1], 2*time.Second); err == nil || got != (admissionwire.Acknowledgement{}) {
				t.Fatal("completion-only service accepted the admission protocol", err)
			}
			if !reflect.DeepEqual(confirmed, testCoordination(t, service.runtime.coordinator)) {
				t.Fatal("disabled protocol changed secondary history")
			}
			stop := appendCoordinated(t, service.runtime.coordinator, testEntry(t, confirmed.Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(80)))
			appendCoordinated(t, service.runtime.coordinator, testEntry(t, testCoordination(t, service.runtime.coordinator).Authority,
				custodyauthority.Retire, types.Hash{}, types.Hash{}, stop.EntryID))
			retired := testCoordination(t, service.runtime.coordinator)
			retry, err := client.CompletePrune(t.Context(), address, runtimePeer(45), entry, 2*time.Second)
			if err != nil || retry.EntryID != completed.EntryID || retry.Nonce == completed.Nonce ||
				!reflect.DeepEqual(retired, testCoordination(t, service.runtime.coordinator)) {
				t.Fatal("historical completion did not preserve a retired target", err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			if cached, err := outbox.Deliver(t.Context(), client, "offline", 2*time.Second); err != nil || cached != completed {
				t.Fatal("durable completion receipt required a live service", err)
			}
		})
	}
}

func TestArchiveSecondaryServiceAdmissionModeAndNoMaintenance(t *testing.T) {
	p, inventory := newArchiveSecondaryFixture(t, nil)
	config := archiveSecondaryServiceConfig(t, p, PruneSecondaryAdmission)
	service := openArchiveSecondaryService(t, p, config)
	address := startArchiveSecondaryService(t, service)
	if service.runtime.admission == nil || service.runtime.completion != nil {
		t.Fatal("admission mode enabled the wrong handlers")
	}
	before, executor := testCoordination(t, service.runtime.coordinator), pruneSnapshot(t, service.runtime.executor)
	if handle, err := service.runtime.EnterMaintenance(t.Context()); !errors.Is(err, ErrPruneRuntime) || handle != nil {
		t.Fatal("secondary runtime granted primary-only maintenance", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, service.runtime.coordinator)) || !reflect.DeepEqual(executor, pruneSnapshot(t, service.runtime.executor)) ||
		!reflect.DeepEqual([]string{address}, service.Addresses()) || service.runtime.quiesced {
		t.Fatal("rejected maintenance parked or changed the secondary service")
	}
	assertArchiveSecondaryServiceOwnersBusy(t, p, config)
	client := archiveSecondaryServiceClient(t)
	entry := testEntry(t, before.Authority, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, testHash(98))
	if got, err := client.CompletePrune(t.Context(), address, runtimePeer(45), entry, 2*time.Second); err == nil || got != (completionwire.Acknowledgement{}) {
		t.Fatal("admission-only service accepted completion protocol", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, service.runtime.coordinator)) {
		t.Fatal("disabled completion protocol changed authority")
	}
	if _, err := archiveSecondaryServiceAdmissionOutbox(t, p, inventory).Deliver(t.Context(), client, address, 2*time.Second); err != nil {
		t.Fatal("rejected maintenance or protocol disabled admission", err)
	}
}

func TestArchiveSecondaryServiceOpenRejectsPinsRolesAndPartialOwnership(t *testing.T) {
	p, _ := newArchiveSecondaryFixture(t, nil)
	config := archiveSecondaryServiceConfig(t, p, PruneSecondaryBoth)
	// Role rejection precedes owner acquisition, even while every real owner is
	// held. Include pins which are outside the selected target assignment.
	var keys [][32]byte
	for _, assignment := range p.policy.Assignments {
		keys = append(keys, assignment.AuthorityPublicKey, assignment.ReplicaPublicKey)
		keys = append(keys, assignment.Auditors...)
		for _, consumer := range assignment.Consumers {
			keys = append(keys, consumer.PublicKey)
		}
	}
	keys = append(keys, p.policy.CheckpointPolicy.TrustedAttestors...)
	keys = append(keys, p.policy.ReplicaPolicy.TrustedReplicas...)
	for _, key := range keys {
		for _, server := range []bool{false, true} {
			bad := config
			peer := types.DomainHash("OMESH/p2p/ed25519/v0", key[:])
			if server {
				bad.Session.ServerPeerID = peer
			} else {
				bad.Session.ClientPeerID = peer
			}
			if service, err := OpenPruneSecondaryCommandService(bad); !errors.Is(err, ErrPruneRuntime) || service != nil {
				t.Fatal("managed service reused an inventory control/evidence key", err)
			}
		}
	}
	_ = p.f.executor.Close()
	for _, operation := range p.operations {
		_ = operation.Coordinator.Close()
	}
	for _, field := range []string{"zero-mode", "unknown-mode", "zero-target", "primary-target", "unknown-target", "inventory-pin", "policy-pin", "missing-primary", "complete-with-primary", "short-timeout", "same-root", "nested-root", "symlink-root", "inventory-overlap", "missing-root"} {
		t.Run(field, func(t *testing.T) {
			bad := config
			switch field {
			case "zero-mode":
				bad.Mode = 0
			case "unknown-mode":
				bad.Mode = PruneSecondaryCommandMode(255)
			case "zero-target":
				bad.Session.AssignmentID = types.Hash{}
			case "primary-target":
				bad.Session.AssignmentID = p.f.request.AssignmentID
			case "unknown-target":
				bad.Session.AssignmentID = testHash(99)
			case "inventory-pin":
				bad.Session.InventoryID = testHash(99)
			case "policy-pin":
				bad.Session.PolicyID = testHash(99)
			case "missing-primary":
				bad.PrimaryAuthorityPinsPath = ""
			case "complete-with-primary":
				bad.Mode = PruneSecondaryCompletion
			case "short-timeout":
				bad.Session.Timeout = admissionwire.MinimumTimeout - 1
			case "same-root":
				bad.AuthorityPinsPath = bad.ExecutorPath
			case "nested-root":
				bad.AuthorityPath = filepath.Join(bad.ExecutorPinsPath, "nested")
			case "symlink-root":
				bad.AuthorityPath = filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(config.AuthorityPath, bad.AuthorityPath); err != nil {
					t.Fatal(err)
				}
			case "inventory-overlap":
				bad.AuthorityPath = filepath.Dir(config.Session.InventoryPath)
			case "missing-root":
				bad.AuthorityPath = filepath.Join(t.TempDir(), "missing")
			}
			if service, err := OpenPruneSecondaryCommandService(bad); err == nil || service != nil {
				if service != nil {
					_ = service.Close()
				}
				t.Fatal("invalid secondary service configuration opened", err)
			}
			if field == "missing-root" {
				if _, err := os.Lstat(bad.AuthorityPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed open bootstrapped an authority root", err)
				}
			}
			service, err := OpenPruneSecondaryCommandService(config)
			if err != nil {
				t.Fatal("failed open retained a lifetime lock", err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Hold the coordinator acquired LAST by assignment ID. A failed open must
	// release the already acquired executor and first coordinator, never this one.
	late, early := 1, 0
	if types.CompareHash(p.operations[0].Binding.AssignmentID, p.operations[1].Binding.AssignmentID) > 0 {
		late, early = 0, 1
	}
	paths := []struct{ path, pins string }{{config.PrimaryAuthorityPath, config.PrimaryAuthorityPinsPath}, {config.AuthorityPath, config.AuthorityPinsPath}}
	held, err := OpenCoordinator(paths[late].path, paths[late].pins, p.policy.Assignments[late], p.operations[late].Binding.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	heldBefore := testCoordination(t, held)
	if service, err := OpenPruneSecondaryCommandService(config); !errors.Is(err, ErrBusy) || service != nil {
		t.Fatal("secondary service stole an externally owned coordinator", err)
	}
	executor, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, p.policy.Assignments[0], p.f.id)
	if err != nil {
		t.Fatal("partial open leaked the executor", err)
	}
	_ = executor.Close()
	first, err := OpenCoordinator(paths[early].path, paths[early].pins, p.policy.Assignments[early], p.operations[early].Binding.AssignmentID)
	if err != nil {
		t.Fatal("partial open leaked the first coordinator", err)
	}
	_ = first.Close()
	if !reflect.DeepEqual(heldBefore, testCoordination(t, held)) {
		t.Fatal("partial open closed or changed the external coordinator")
	}
}

func TestArchiveSecondaryServiceStartupRechecksInventoryAndRetainsOwners(t *testing.T) {
	p, _ := newArchiveSecondaryFixture(t, nil)
	config := archiveSecondaryServiceConfig(t, p, PruneSecondaryBoth)
	service := openArchiveSecondaryService(t, p, config)
	before := testCoordination(t, service.runtime.coordinator)
	if err := service.Start(t.Context(), testKey(47), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrPruneRuntime) {
		t.Fatal("server key did not match the external peer pin", err)
	}
	assertArchiveSecondaryServiceOwnersBusy(t, p, config)
	data, err := os.ReadFile(config.Session.InventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, config.Session.InventoryPath, []byte("replaced after open"))
	if err := service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()); err == nil || len(service.Addresses()) != 0 {
		t.Fatal("Start listened using a changed inventory", err)
	}
	assertArchiveSecondaryServiceOwnersBusy(t, p, config)
	writeTestFile(t, config.Session.InventoryPath, data)
	if !reflect.DeepEqual(before, testCoordination(t, service.runtime.coordinator)) {
		t.Fatal("failed startup advanced the target")
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := service.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
		t.Fatal("corrected Start could not reuse the retained owners", err)
	}
	if err := service.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); !errors.Is(err, ErrPruneServiceStarted) {
		t.Fatal(err)
	}
	closed := make(chan error, 4)
	for range 4 {
		go func() { closed <- service.Close() }()
	}
	cancel()
	for range 4 {
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	}
	waitPruneRuntimeDone(t, service.runtime)
	if len(service.Addresses()) != 0 || !errors.Is(service.Start(t.Context(), testKey(45), libp2ptransport.DefaultConfig()), ErrClosed) {
		t.Fatal("closed secondary service restarted or advertised a route")
	}
	reopenArchiveSecondaryServiceOwners(t, p, config)
	if !reflect.DeepEqual(before, testCoordination(t, p.operations[1].Coordinator)) {
		t.Fatal("startup or concurrent shutdown advanced the target")
	}
}

func TestArchiveSecondaryServiceUncertaintyStopsAndPendingNeedsExplicitRetry(t *testing.T) {
	p, inventory := newArchiveSecondaryFixture(t, nil)
	config := archiveSecondaryServiceConfig(t, p, PruneSecondaryBoth)
	service := openArchiveSecondaryService(t, p, config)
	fault := errors.New("secondary independent confirmation unavailable")
	setCoordinatorHooks(service.runtime.coordinator, storeHooks{at: func(at string) error {
		if at == "confirm-before-publish" {
			return fault
		}
		return nil
	}})
	client := archiveSecondaryServiceClient(t)
	outbox := archiveSecondaryServiceAdmissionOutbox(t, p, inventory)
	if ack, err := outbox.Deliver(t.Context(), client, startArchiveSecondaryService(t, service), 2*time.Second); !errors.Is(err, admissionwire.ErrUnconfirmed) || ack != (admissionwire.Acknowledgement{}) {
		t.Fatal("poisoned target returned success", err)
	}
	waitPruneRuntimeDone(t, service.runtime)
	if err := service.Close(); !errors.Is(err, fault) || !errors.Is(err, ErrUncertain) {
		t.Fatal("secondary service concealed a fatal storage failure", err)
	}
	service, err := OpenPruneSecondaryCommandService(config)
	if err != nil {
		t.Fatal("uncertain service did not release its owners", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	pending := testCoordination(t, service.runtime.coordinator)
	if pending.Pending == nil || *pending.Pending != inventory.Admissions[1] {
		t.Fatal("open silently resolved the retained secondary attempt")
	}
	address := startArchiveSecondaryService(t, service)
	if !reflect.DeepEqual(pending, testCoordination(t, service.runtime.coordinator)) {
		t.Fatal("Start automatically resumed a retained command")
	}
	if _, err := outbox.Deliver(t.Context(), client, address, 2*time.Second); err != nil {
		t.Fatal("explicit retry could not confirm the retained command", err)
	}
	state := testCoordination(t, service.runtime.coordinator)
	if state.Pending != nil || state.Authority.Sequence != 1 || state.Authority.Operations[0].OperationID != p.f.id {
		t.Fatal("explicit retry duplicated or relabelled secondary admission")
	}
}

func TestArchiveSecondaryServiceCloseDrainsBeforeReleasingAllOwners(t *testing.T) {
	for _, shutdown := range []string{"close", "cancel"} {
		t.Run(shutdown, func(t *testing.T) {
			p, inventory := newArchiveSecondaryFixture(t, nil)
			config := archiveSecondaryServiceConfig(t, p, PruneSecondaryBoth)
			service := openArchiveSecondaryService(t, p, config)
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			service.runtime.hooks.at = func(at string) error {
				if at == "runtime-handler-entered" {
					close(reached)
					<-release
				}
				return nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := service.Start(ctx, testKey(45), libp2ptransport.DefaultConfig()); err != nil {
				t.Fatal(err)
			}
			client := archiveSecondaryServiceClient(t)
			outbox := archiveSecondaryServiceAdmissionOutbox(t, p, inventory)
			address := service.Addresses()[0]
			result := make(chan error, 1)
			go func() {
				ack, err := outbox.Deliver(t.Context(), client, address, 2*time.Second)
				if ack != (admissionwire.Acknowledgement{}) {
					t.Error("interrupted handler returned a successful acknowledgement")
				}
				result <- err
			}()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("secondary handler did not enter the drain barrier")
			}
			if shutdown == "cancel" {
				cancel()
			}
			closed := make(chan error, 2)
			go func() { closed <- service.Close() }()
			go func() { closed <- service.Close() }()
			select {
			case <-service.Done():
				t.Fatal("secondary service released owners before its handler returned")
			case <-time.After(20 * time.Millisecond):
			}
			assertArchiveSecondaryServiceOwnersBusy(t, p, config)
			unblock()
			first, second := <-closed, <-closed
			if first != second {
				t.Fatal("concurrent secondary Close returned different final errors", first, second)
			}
			if first != nil {
				t.Fatal(first)
			}
			waitPruneRuntimeDone(t, service.runtime)
			if err := <-result; !errors.Is(err, admissionwire.ErrUnconfirmed) {
				t.Fatal("interrupted delivery was not left retryable", err)
			}
			reopenArchiveSecondaryServiceOwners(t, p, config)
			if testCoordination(t, p.operations[1].Coordinator).Authority.Sequence != 0 {
				t.Fatal("an interrupted pre-read handler changed secondary authority")
			}
		})
	}
}
