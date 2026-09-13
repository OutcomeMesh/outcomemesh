package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type archivePruneFixture struct {
	f          *pruneFixture
	policy     ArchivePrunePolicy
	policyID   types.Hash
	replicas   []workarchive.Replica
	operations []RequiredOperation
	path       string
}

func newArchivePruneFixture(t testing.TB) *archivePruneFixture {
	t.Helper()
	f := newPruneFixtureWithStoragePositions(t, testHash(91), true)
	_ = f.executor.Close()
	_ = f.coordinator.Close()
	a := testAssignment()
	binding := workarchive.Binding{NetworkID: a.NetworkID, GenesisID: a.GenesisID, ActivationHeight: a.ActivationHeight, BaseID: a.BaseID}
	archive := filepath.Join(t.TempDir(), "archive")
	manifest, _, err := workarchive.ExportDirectory(archive, binding, f.chain, f.request.Boundary.Anchor.ID, workarchive.DefaultExportOptions())
	if err != nil {
		t.Fatal(err)
	}
	statement, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	var attestations []workarchive.Attestation
	for _, key := range []byte{51, 52} {
		attestation, err := workarchive.Attest(testKey(key), statement)
		if err != nil {
			t.Fatal(err)
		}
		attestations = append(attestations, attestation)
	}
	checkpoint, err := workarchive.NewCheckpoint(statement, attestations)
	if err != nil {
		t.Fatal(err)
	}
	p := &archivePruneFixture{f: f, path: filepath.Join(t.TempDir(), "availability.omav")}
	p.policy.Checkpoint = checkpoint
	p.policy.CheckpointPolicy = workarchive.Policy{Binding: binding, RequiredAttestations: 2}
	for _, attestation := range checkpoint.Attestations {
		p.policy.CheckpointPolicy.TrustedAttestors = append(p.policy.CheckpointPolicy.TrustedAttestors, attestation.PublicKey)
	}
	now := uint64(time.Now().Unix())
	for _, seed := range []byte{61, 62} {
		directory := filepath.Join(t.TempDir(), "replica")
		if err := os.CopyFS(directory, os.DirFS(archive)); err != nil {
			t.Fatal(err)
		}
		receipt, err := workarchive.CreateReplicaReceipt(directory, checkpoint, p.policy.CheckpointPolicy, f.base, f.parameters,
			workarchive.DefaultLimits(), testKey(seed), testHash(seed), now, now+20_000)
		if err != nil {
			t.Fatal(err)
		}
		p.replicas = append(p.replicas, workarchive.Replica{Directory: directory, Receipt: receipt})
	}
	sort.Slice(p.replicas, func(i, j int) bool {
		return bytes.Compare(p.replicas[i].Receipt.ReplicaPublicKey[:], p.replicas[j].Receipt.ReplicaPublicKey[:]) < 0
	})
	p.policy.ReplicaPolicy = workarchive.ReplicaPolicy{RequiredReplicas: 2, MaximumReceiptAge: 1_000, MinimumRemainingTerm: 100}
	custodyPolicy := workarchive.CustodyPolicy{TrustedAuditors: a.Auditors, MaximumChallengeLifetime: 60, MaximumProofAge: 100, MaximumRenewalTerm: 20_000}
	for i, replica := range p.replicas {
		p.policy.ReplicaPolicy.TrustedReplicas = append(p.policy.ReplicaPolicy.TrustedReplicas, replica.Receipt.ReplicaPublicKey)
		assignment, err := workarchive.CreateCustodyAuthorityAssignment(manifest, replica.Receipt, custodyPolicy, testHash(byte(100+i)),
			testPublic(1), a.Consumers, 16, 4)
		if err != nil {
			t.Fatal(err)
		}
		p.policy.Assignments = append(p.policy.Assignments, assignment)
	}
	bundle, err := workarchive.VerifyReplicaSet(p.replicas, checkpoint, p.policy.CheckpointPolicy, p.policy.ReplicaPolicy,
		f.base, f.parameters, workarchive.DefaultLimits(), now)
	if err != nil {
		t.Fatal(err)
	}
	f.request.AssignmentID, _ = p.policy.Assignments[0].ID()
	f.request.Boundary.StatementID, _ = statement.ID()
	f.request.Boundary.ManifestID, _ = manifest.ID()
	f.request.Boundary.AvailabilityID, _ = bundle.ID()
	f.request.Boundary.VerifiedAt, f.request.Boundary.RetainUntil = now, now+20_000
	f.id, _ = f.request.ID()
	f.executorPath, f.executorPinsPath = filepath.Join(t.TempDir(), "executor"), filepath.Join(t.TempDir(), "executor-pins")
	f.executor, err = CreatePinnedPruneExecutor(f.executorPath, f.executorPinsPath, p.policy.Assignments[0], f.request, f.id)
	if err != nil {
		t.Fatal(err)
	}
	for i, assignment := range p.policy.Assignments {
		authorityPath, pinsPath := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "authority-pins")
		id, _ := assignment.ID()
		coordinator, err := CreateCoordinatedAuthority(authorityPath, pinsPath, assignment, id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = coordinator.Close() })
		command, err := (custodyauthority.Command{AssignmentID: id, ExpectedHead: id, Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: f.id}).Sign(testKey(4))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(command, testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		commit := appendCoordinated(t, coordinator, entry)
		p.operations = append(p.operations, RequiredOperation{Coordinator: coordinator, Binding: OperationBinding{
			AssignmentID: id, TicketID: commit.EntryID, ConsumerPublicKey: testPublic(4), OperationID: f.id, Purpose: custodyauthority.Prune}})
		if i == 0 {
			f.coordinator, f.authorityPath, f.pinsPath, f.admission = coordinator, authorityPath, pinsPath, entry
			if err := f.executor.BindAdmission(t.Context(), coordinator, entry); err != nil {
				t.Fatal(err)
			}
		}
	}
	protection, err := f.chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	p.policy.RequestID, p.policy.StoragePairID = f.id, protection.PairID
	p.policy.ExecutorBindingID = pruneSnapshot(t, f.executor).Protection.BindingID
	p.policyID, err = p.policy.ID()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *archivePruneFixture) execute(ctx context.Context) (workchain.CanonicalPruneCommit, error) {
	return p.f.executor.ExecuteArchive(ctx, p.f.chain, p.policy, p.policyID, p.operations, p.replicas, p.path,
		p.f.base, p.f.parameters, workarchive.DefaultLimits())
}

func TestArchivePruneAllAssignmentsAndPinnedStorage(t *testing.T) {
	p := newArchivePruneFixture(t)
	before, err := p.f.chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.execute(t.Context())
	if err != nil || !result.Applied || result.Effect.Report.RemovedNodes == 0 {
		t.Fatal("managed prune did not apply", result, err)
	}
	after, err := p.f.chain.StorageProtection()
	if err != nil || after.Pending != nil || after.Database.Sequence != before.Database.Sequence+1 || after.Database != after.Confirmed {
		t.Fatal("effect not independently confirmed", err)
	}
	if state := pruneSnapshot(t, p.f.executor); state.Stage != PruneSucceeded || state.Protection.Pending != nil {
		t.Fatal("executor result not confirmed")
	}
	for _, operation := range p.operations {
		if state := testCoordination(t, operation.Coordinator); state.Authority.Pending != 1 || state.Authority.Sequence != 1 {
			t.Fatal("execution automatically completed authority")
		}
	}
	if _, err := p.execute(t.Context()); !errors.Is(err, ErrPruneStage) {
		t.Fatal("historical result relabelled live execution", err)
	}
	if historical, err := p.f.executor.Recover(t.Context(), p.f.chain); err != nil || historical.Applied || !reflect.DeepEqual(historical.Effect, result.Effect) {
		t.Fatal("historical recovery changed result", err)
	}
	if _, err := os.Stat(p.path); err != nil {
		t.Fatal("missing immutable bundle", err)
	}
}

func TestArchivePruneRejectsIncompleteOrChangedPolicyBeforeStart(t *testing.T) {
	for _, mode := range []string{"missing-operation", "duplicate-operation", "wrong-owner", "completed-secondary", "pending-secondary", "missing-replica", "repeated-replica",
		"policy-id", "policy-time", "pair", "executor-pair", "request", "receipt", "assignment", "unbound-chain", "output-overlap", "expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			p := newArchivePruneFixture(t)
			ctx := t.Context()
			switch mode {
			case "missing-operation":
				p.operations = p.operations[:1]
			case "duplicate-operation":
				p.operations[1] = p.operations[0]
			case "wrong-owner":
				p.operations[0].Coordinator, p.operations[1].Coordinator = p.operations[1].Coordinator, p.operations[0].Coordinator
			case "completed-secondary":
				c := p.operations[1].Coordinator
				appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, testHash(98)))
			case "pending-secondary":
				c := p.operations[1].Coordinator
				setCoordinatorHooks(c, storeHooks{at: func(at string) error {
					if at == "intent-after-publish" {
						return errors.New("retained secondary intent")
					}
					return nil
				}})
				_, _ = c.Append(t.Context(), testEntry(t, testCoordination(t, c).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(98)))
				authorityPath, pinsPath := c.authority.path, c.journal.path
				_ = c.Close()
				var err error
				p.operations[1].Coordinator, err = OpenCoordinator(authorityPath, pinsPath, p.policy.Assignments[1], p.operations[1].Binding.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = p.operations[1].Coordinator.Close() })
			case "missing-replica":
				p.replicas = p.replicas[:1]
			case "repeated-replica":
				p.replicas[1] = p.replicas[0]
			case "policy-id":
				p.policyID[0] ^= 1
			case "policy-time":
				p.policy.ReplicaPolicy.MaximumReceiptAge++
			case "pair":
				p.policy.StoragePairID = testHash(99)
				p.policyID, _ = p.policy.ID()
			case "executor-pair":
				p.policy.ExecutorBindingID = testHash(99)
				p.policyID, _ = p.policy.ID()
			case "request":
				p.policy.RequestID = testHash(99)
				p.policyID, _ = p.policy.ID()
			case "receipt":
				p.replicas[1].Receipt.RetainUntil++
			case "assignment":
				p.policy.Assignments[1].IncarnationID = testHash(99)
				p.policyID, _ = p.policy.ID()
			case "unbound-chain":
				other := newPruneFixture(t)
				_ = p.f.chain.Close()
				p.f.chain = other.chain
			case "output-overlap":
				p.path = filepath.Join(p.f.chainPath, "availability.omav")
			case "expired":
				p.policy.ReplicaPolicy.MinimumRemainingTerm = 30_000
				p.policyID, _ = p.policy.ID()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := pruneSnapshot(t, p.f.executor)
			if result, err := p.execute(ctx); err == nil || result.Applied {
				t.Fatal("invalid managed acceptance succeeded", mode, err)
			}
			if !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("rejection published start")
			}
			if _, err := os.Lstat(p.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejection wrote evidence", err)
			}
		})
	}
}

func TestArchivePruneGuardsSecondaryThroughResult(t *testing.T) {
	for _, point := range []string{"archive-before-verification", "archive-before-start", "prune-before-effect", "prune-after-effect", "pins-result-confirm-before-publish"} {
		t.Run(point, func(t *testing.T) {
			p := newArchivePruneFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			hooks := storeHooks{at: func(at string) error {
				if at == point {
					close(entered)
					<-release
				}
				return nil
			}}
			p.f.executor.hooks, p.f.executor.pins.hooks = hooks, hooks
			c := p.operations[1].Coordinator
			stop := testEntry(t, testCoordination(t, c).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(98))
			done := make(chan error, 1)
			go func() { _, err := p.execute(t.Context()); done <- err }()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("guard barrier not reached")
			}
			for _, operation := range p.operations {
				if operation.Coordinator.mu.TryLock() {
					operation.Coordinator.mu.Unlock()
					t.Fatal("required guard released")
				}
			}
			stopped := make(chan error, 1)
			go func() { _, err := c.Append(t.Context(), stop); stopped <- err }()
			select {
			case err := <-stopped:
				t.Fatal("stop crossed effect", err)
			case <-time.After(10 * time.Millisecond):
			}
			unblock()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := <-stopped; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestArchivePruneLockOrderIgnoresCallerOrderAndRejectsRelabelledOwners(t *testing.T) {
	p := newArchivePruneFixture(t)
	reversed := []RequiredOperation{p.operations[1], p.operations[0]}
	done := make(chan error, 2)
	for _, operations := range [][]RequiredOperation{p.operations, reversed} {
		go func() {
			for range 20 {
				if err := withRequiredOperations(t.Context(), operations, func() error { return nil }); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
	}
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("reversed input deadlocked")
		}
	}
	wrong := append([]RequiredOperation(nil), p.operations...)
	wrong[0].Binding.AssignmentID, wrong[1].Binding.AssignmentID = wrong[1].Binding.AssignmentID, wrong[0].Binding.AssignmentID
	// Even held mutexes must not prevent rejecting caller-relabelled owners.
	p.operations[0].Coordinator.mu.Lock()
	defer p.operations[0].Coordinator.mu.Unlock()
	if err := withRequiredOperations(t.Context(), wrong, func() error { t.Error("wrong owner ran"); return nil }); !errors.Is(err, custodyauthority.ErrAssignment) {
		t.Fatal(err)
	}
}

func TestArchivePruneCancellationBeforeAndAfterStart(t *testing.T) {
	for _, point := range []string{"archive-before-start", "prune-before-effect"} {
		t.Run(point, func(t *testing.T) {
			p := newArchivePruneFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p.f.executor.hooks.at = func(at string) error {
				if at == point {
					cancel()
				}
				return nil
			}
			if _, err := p.execute(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation not enforced", err)
			}
			want := PruneAdmitted
			if point == "prune-before-effect" {
				want = PruneStarted
			}
			if state := pruneSnapshot(t, p.f.executor); state.Stage != want || state.Protection.Pending != nil {
				t.Fatal("wrong cancellation disposition")
			}
			for _, operation := range p.operations {
				if testCoordination(t, operation.Coordinator).Authority.Pending != 1 {
					t.Fatal("cancelled call completed authority")
				}
			}
			if _, err := os.Stat(p.path); err != nil {
				t.Fatal("published evidence erased", err)
			}
			if point == "prune-before-effect" {
				_ = p.f.chain.Close()
				var err error
				p.f.chain, err = workchain.OpenPositionPinnedWithPolicy(p.f.chainPath, p.f.chainPositionPinsPath, p.f.base, p.f.parameters, p.f.policy, p.f.request.StorageID)
				if err != nil {
					t.Fatal(err)
				}
				protection, err := p.f.chain.StorageProtection()
				if err != nil || protection.Pending == nil || protection.Database != protection.Confirmed {
					t.Fatal("denied final authorization lost storage uncertainty", err)
				}
				if _, err := p.execute(t.Context()); !errors.Is(err, ErrPruneOutcome) {
					t.Fatal("cancelled retained start reran", err)
				}
				if _, err := p.f.executor.Recover(t.Context(), p.f.chain); !errors.Is(err, workchain.ErrStoragePinPending) {
					t.Fatal("absence inferred no effect", err)
				}
			}
		})
	}
}

func TestArchivePruneDetachesPolicyAndAllowsAdmittedDrain(t *testing.T) {
	p := newArchivePruneFixture(t)
	secondary := p.operations[1].Coordinator
	appendCoordinated(t, secondary, testEntry(t, testCoordination(t, secondary).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(98)))
	// The original caller slices are changed only after the private hook proves
	// all validation/copying has finished; no concurrent input writes at entry.
	p.f.executor.hooks.at = func(at string) error {
		if at == "archive-before-verification" {
			p.policy.ReplicaPolicy.TrustedReplicas[0] = [32]byte{}
			p.policy.CheckpointPolicy.TrustedAttestors[0] = [32]byte{}
			p.policy.Assignments[0].Consumers[0].PublicKey = [32]byte{}
			p.replicas[0].Directory = "not-the-accepted-replica"
			p.operations[0].Binding.TicketID = types.Hash{}
		}
		return nil
	}
	if result, err := p.execute(t.Context()); err != nil || !result.Applied {
		t.Fatal("caller mutation changed accepted policy or stopping prevented admitted drain", err)
	}
	if state := testCoordination(t, secondary); state.Authority.Phase != custodyauthority.Stopping || state.Authority.Pending != 1 {
		t.Fatal("drain changed stop or completed ticket")
	}
}
