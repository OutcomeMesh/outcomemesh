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
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// Retain the externally pinned preparation inputs and capture the original
// owners before closing them. Opening the service is a separate explicit step.
func archiveEffectServiceFixture(t testing.TB, p *archivePruneFixture) PruneArchiveEffectServiceConfig {
	t.Helper()
	var inventory ArchivePruneInventory
	if p.inventoryPath == "" {
		inventory = retainArchiveInventory(t, p)
	} else {
		var err error
		inventory, err = LoadArchivePruneInventoryFile(p.inventoryPath, p.inventoryID, p.policyID)
		if err != nil {
			t.Fatal(err)
		}
	}
	config := PruneArchiveEffectServiceConfig{
		InventoryPath: p.inventoryPath, InventoryID: p.inventoryID, PolicyID: p.policyID,
		ExecutorPath: p.f.executorPath, ExecutorPinsPath: p.f.executorPinsPath,
		ChainPath: p.f.chainPath, ChainPinsPath: p.f.chainPositionPinsPath,
		Base: p.f.base, Parameters: p.f.parameters, StoragePolicy: p.f.policy,
		AvailabilityPath: p.path, Limits: workarchive.DefaultLimits(),
	}
	for _, operation := range p.operations {
		owner := operation.Coordinator
		config.Authorities = append(config.Authorities, PruneArchiveAuthorityRoots{
			AssignmentID:  operation.Binding.AssignmentID,
			AuthorityPath: owner.authority.path, AuthorityPinsPath: owner.journal.path,
		})
	}
	for _, replica := range p.replicas {
		for _, assignment := range p.policy.Assignments {
			if assignment.ReplicaPublicKey == replica.Receipt.ReplicaPublicKey {
				id, _ := assignment.ID()
				config.Replicas = append(config.Replicas, PruneArchiveReplicaPath{AssignmentID: id, Directory: replica.Directory})
			}
		}
	}
	if inventory.Mode == ArchivePruneLineage {
		evidence, err := PrepareArchivePruneLineageEvidence(t.Context(), inventory, p.inventoryID, p.policyID, p.lineages)
		if err != nil {
			t.Fatal(err)
		}
		config.LineageID, _ = evidence.ID()
		config.LineagePath = filepath.Join(t.TempDir(), "lineage.omple")
		if err := SaveArchivePruneLineageEvidenceFile(t.Context(), config.LineagePath, evidence, config.LineageID); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.f.executor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range p.operations {
		if err := operation.Coordinator.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.f.chain.Close(); err != nil {
		t.Fatal(err)
	}
	return config
}

func openArchiveEffectService(t testing.TB, config PruneArchiveEffectServiceConfig) *PruneArchiveEffectService {
	t.Helper()
	service, err := OpenPruneArchiveEffectService(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func archiveEffectPrimary(t testing.TB, p *archivePruneFixture) custodyauthority.Assignment {
	t.Helper()
	for _, assignment := range p.policy.Assignments {
		if id, _ := assignment.ID(); id == p.f.request.AssignmentID {
			return assignment
		}
	}
	t.Fatal("missing fixture primary")
	return custodyauthority.Assignment{}
}

func assertArchiveEffectOwnersBusy(t testing.TB, p *archivePruneFixture, config PruneArchiveEffectServiceConfig) {
	t.Helper()
	if owner, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, archiveEffectPrimary(t, p), p.f.id); !errors.Is(err, ErrBusy) {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("effect service released executor ownership", err)
	}
	for _, root := range config.Authorities {
		var assignment custodyauthority.Assignment
		for _, candidate := range p.policy.Assignments {
			if id, _ := candidate.ID(); id == root.AssignmentID {
				assignment = candidate
			}
		}
		if owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, assignment, root.AssignmentID); !errors.Is(err, ErrBusy) {
			if owner != nil {
				_ = owner.Close()
			}
			t.Fatal("effect service released required authority", root.AssignmentID, err)
		}
	}
	if chain, err := workchain.OpenPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath, p.f.base, p.f.parameters, p.f.policy, p.f.request.StorageID); !errors.Is(err, workchain.ErrStoragePinBusy) {
		if chain != nil {
			_ = chain.Close()
		}
		t.Fatal("effect service released protected chain ownership", err)
	}
}

func assertArchiveEffectOwnersReleased(t testing.TB, p *archivePruneFixture, config PruneArchiveEffectServiceConfig) {
	t.Helper()
	executor, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, archiveEffectPrimary(t, p), p.f.id)
	if err != nil {
		t.Fatal("executor lock leaked", err)
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, root := range config.Authorities {
		var assignment custodyauthority.Assignment
		for _, candidate := range p.policy.Assignments {
			if id, _ := candidate.ID(); id == root.AssignmentID {
				assignment = candidate
			}
		}
		owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, assignment, root.AssignmentID)
		if err != nil {
			t.Fatal("authority lock leaked", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	chain, err := workchain.OpenPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath, p.f.base, p.f.parameters, p.f.policy, p.f.request.StorageID)
	if err != nil {
		t.Fatal("chain lock leaked", err)
	}
	if err := chain.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPruneArchiveEffectServiceExecutesBothModesWithoutCompletion(t *testing.T) {
	for _, renewals := range [][]int{nil, {2, 1}, {2, 0}} {
		name := "initial"
		if renewals != nil {
			name = "lineage"
		}
		t.Run(name, func(t *testing.T) {
			p := newArchivePruneFixtureWithRenewals(t, renewals)
			config := archiveEffectServiceFixture(t, p)
			service := openArchiveEffectService(t, config)
			assertArchiveEffectOwnersBusy(t, p, config)
			review, err := service.Review(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			id, err := review.ID()
			if err != nil || id.IsZero() || review.InventoryID != config.InventoryID || review.PolicyID != config.PolicyID ||
				review.RequestID != p.f.id || review.StorageID != p.f.request.StorageID || review.LineageEvidenceID != config.LineageID {
				t.Fatal("review lost independently configured scope", review, err)
			}
			again, err := service.Review(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			againID, _ := again.ID()
			if againID != id {
				t.Fatal("non-mutating review changed its ID")
			}
			if _, err := os.Stat(config.AvailabilityPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("review published availability evidence", err)
			}
			assertArchiveEffectOwnersBusy(t, p, config)
			result, err := service.Execute(t.Context(), id)
			if err != nil || !result.Applied || result.Effect.Report.RemovedNodes == 0 {
				t.Fatal("reviewed archive effect did not apply", result, err)
			}
			assertArchiveEffectOwnersBusy(t, p, config)
			if second, err := service.Execute(t.Context(), id); err == nil || second.Applied {
				t.Fatal("repeated review executed another effect", err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			assertArchiveEffectOwnersReleased(t, p, config)
			executor, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, archiveEffectPrimary(t, p), p.f.id)
			if err != nil {
				t.Fatal(err)
			}
			state := pruneSnapshot(t, executor)
			if err := executor.Close(); err != nil {
				t.Fatal(err)
			}
			if state.Stage != PruneSucceeded || state.Effect == nil || !reflect.DeepEqual(*state.Effect, result.Effect) ||
				state.ArchiveInventoryID != config.InventoryID || state.Protection.Pending != nil {
				t.Fatal("owned effect lost original confirmed provenance")
			}
			chain, err := workchain.OpenPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath, p.f.base, p.f.parameters, p.f.policy, p.f.request.StorageID)
			if err != nil {
				t.Fatal(err)
			}
			protection, err := chain.StorageProtection()
			if err != nil || protection.Pending != nil || protection.Database != protection.Confirmed || protection.Database.Sequence != review.Storage.Sequence+1 {
				t.Fatal("effect not independently confirmed exactly once", protection, err)
			}
			if err := chain.Close(); err != nil {
				t.Fatal(err)
			}
			for _, root := range config.Authorities {
				var assignment custodyauthority.Assignment
				for _, candidate := range p.policy.Assignments {
					if aid, _ := candidate.ID(); aid == root.AssignmentID {
						assignment = candidate
					}
				}
				owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, assignment, root.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				position := testCoordination(t, owner)
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				if position.Pending != nil || position.Authority.Sequence != 1 || position.Authority.Pending != 1 {
					t.Fatal("effect automatically completed an original authority", root.AssignmentID)
				}
			}
		})
	}
}

func TestPruneArchiveEffectServiceRejectsIncompleteScopeAndReleasesOwners(t *testing.T) {
	for _, mode := range []string{"inventory-pin", "policy-pin", "missing-owner", "duplicate-owner", "unknown-owner", "aliased-owner", "missing-replica", "relabelled-replica", "output-overlap", "missing-chain", "missing-authority", "lineage-pin", "unexpected-lineage"} {
		t.Run(mode, func(t *testing.T) {
			var p *archivePruneFixture
			if mode == "lineage-pin" {
				p = newArchivePruneFixtureWithRenewals(t, []int{2, 1})
			} else {
				p = newArchivePruneFixture(t)
			}
			original := archiveEffectServiceFixture(t, p)
			config := original
			config.Authorities = append([]PruneArchiveAuthorityRoots(nil), original.Authorities...)
			config.Replicas = append([]PruneArchiveReplicaPath(nil), original.Replicas...)
			switch mode {
			case "inventory-pin":
				config.InventoryID = testHash(99)
			case "policy-pin":
				config.PolicyID = testHash(99)
			case "missing-owner":
				config.Authorities = config.Authorities[:1]
			case "duplicate-owner":
				config.Authorities[1] = config.Authorities[0]
			case "unknown-owner":
				config.Authorities[1].AssignmentID = testHash(99)
			case "aliased-owner":
				config.Authorities[1].AuthorityPath = config.Authorities[0].AuthorityPath
			case "missing-replica":
				config.Replicas = config.Replicas[:1]
			case "relabelled-replica":
				config.Replicas[1].AssignmentID = config.Replicas[0].AssignmentID
			case "output-overlap":
				config.AvailabilityPath = filepath.Join(config.ChainPath, "availability.omav")
			case "missing-chain":
				config.ChainPath = filepath.Join(t.TempDir(), "missing-chain")
			case "missing-authority":
				config.Authorities[1].AuthorityPath = filepath.Join(t.TempDir(), "missing-authority")
			case "lineage-pin":
				config.LineageID = testHash(99)
			case "unexpected-lineage":
				config.LineagePath, config.LineageID = original.InventoryPath, testHash(99)
			}
			service, err := OpenPruneArchiveEffectService(config)
			if service != nil {
				_ = service.Close()
			}
			if err == nil {
				t.Fatal("incomplete or substituted owned scope accepted", mode)
			}
			assertArchiveEffectOwnersReleased(t, p, original)
			if _, err := os.Stat(original.AvailabilityPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("open performed an effect", err)
			}
		})
	}
}

func TestPruneArchiveEffectServicePartialOpenReleasesOnlyAcquiredOwners(t *testing.T) {
	for _, mode := range []string{"later-authority-busy", "chain-busy"} {
		t.Run(mode, func(t *testing.T) {
			p := newArchivePruneFixture(t)
			config := archiveEffectServiceFixture(t, p)
			var closeHeld func() error
			var expected error
			if mode == "chain-busy" {
				chain, err := workchain.OpenPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath, p.f.base, p.f.parameters, p.f.policy, p.f.request.StorageID)
				if err != nil {
					t.Fatal(err)
				}
				closeHeld, expected = chain.Close, workchain.ErrStoragePinBusy
			} else {
				// Pick the final owner in canonical acquisition order so startup
				// must clean up both the executor and at least one coordinator.
				root := config.Authorities[0]
				for _, candidate := range config.Authorities {
					if types.CompareHash(root.AssignmentID, candidate.AssignmentID) < 0 {
						root = candidate
					}
				}
				var assignment custodyauthority.Assignment
				for _, candidate := range p.policy.Assignments {
					if id, _ := candidate.ID(); id == root.AssignmentID {
						assignment = candidate
					}
				}
				owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, assignment, root.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				closeHeld, expected = owner.Close, ErrBusy
			}
			defer func() { _ = closeHeld() }()
			service, err := OpenPruneArchiveEffectService(config)
			if service != nil {
				_ = service.Close()
			}
			if !errors.Is(err, expected) {
				t.Fatal("startup did not refuse the externally held final owner", err)
			}
			// The first original pair is immediately available even while the
			// intentionally held later owner remains unavailable to startup.
			executor, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, archiveEffectPrimary(t, p), p.f.id)
			if err != nil {
				t.Fatal("partial startup leaked the executor", err)
			}
			if err := executor.Close(); err != nil {
				t.Fatal(err)
			}
			if err := closeHeld(); err != nil {
				t.Fatal(err)
			}
			assertArchiveEffectOwnersReleased(t, p, config)
		})
	}
}

func TestPruneArchiveEffectServiceWrongReviewAndChangedArtifactsNeverStart(t *testing.T) {
	for _, mode := range []string{"zero-review", "wrong-review", "modified-inventory", "missing-inventory", "modified-lineage", "missing-lineage", "modified-replica"} {
		t.Run(mode, func(t *testing.T) {
			var p *archivePruneFixture
			if mode == "modified-lineage" || mode == "missing-lineage" {
				p = newArchivePruneFixtureWithRenewals(t, []int{1, 1})
			} else {
				p = newArchivePruneFixture(t)
			}
			config := archiveEffectServiceFixture(t, p)
			service := openArchiveEffectService(t, config)
			review, err := service.Review(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			id, _ := review.ID()
			switch mode {
			case "zero-review":
				id = types.Hash{}
			case "wrong-review":
				id = testHash(99)
			case "modified-inventory":
				writeTestFile(t, config.InventoryPath, []byte("substituted inventory"))
			case "missing-inventory":
				if err := os.Rename(config.InventoryPath, config.InventoryPath+".saved"); err != nil {
					t.Fatal(err)
				}
			case "modified-lineage":
				writeTestFile(t, config.LineagePath, []byte("substituted lineage"))
			case "missing-lineage":
				if err := os.Rename(config.LineagePath, config.LineagePath+".saved"); err != nil {
					t.Fatal(err)
				}
			case "modified-replica":
				// The replica's manifest is part of real full archive verification,
				// not merely a path or receipt in the local comparison digest.
				if err := os.Rename(config.Replicas[1].Directory, config.Replicas[1].Directory+".saved"); err != nil {
					t.Fatal(err)
				}
			}
			if result, err := service.Execute(t.Context(), id); err == nil || result.Applied {
				t.Fatal("changed review inputs executed", err)
			}
			state := pruneSnapshot(t, service.executor)
			if state.Stage != PruneAdmitted || state.Protection.Pending != nil || !state.ArchiveInventoryID.IsZero() {
				t.Fatal("rejection retained a new start")
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			assertArchiveEffectOwnersReleased(t, p, config)
		})
	}
}

type archiveEffectRetainedState struct {
	Executor    PruneExecution
	Authorities []Coordination
	Storage     workchain.StorageProtection
}

func readArchiveEffectRetainedState(t testing.TB, p *archivePruneFixture, config PruneArchiveEffectServiceConfig) archiveEffectRetainedState {
	t.Helper()
	var result archiveEffectRetainedState
	executor, err := OpenPinnedPruneExecutor(config.ExecutorPath, config.ExecutorPinsPath, archiveEffectPrimary(t, p), p.f.id)
	if err != nil {
		t.Fatal(err)
	}
	result.Executor = pruneSnapshot(t, executor)
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, root := range config.Authorities {
		var assignment custodyauthority.Assignment
		for _, candidate := range p.policy.Assignments {
			if id, _ := candidate.ID(); id == root.AssignmentID {
				assignment = candidate
			}
		}
		owner, err := OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, assignment, root.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		result.Authorities = append(result.Authorities, testCoordination(t, owner))
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
	chain, err := workchain.OpenPositionPinnedWithPolicy(config.ChainPath, config.ChainPinsPath, p.f.base, p.f.parameters, p.f.policy, p.f.request.StorageID)
	if err != nil {
		t.Fatal(err)
	}
	result.Storage, err = chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Close(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPruneArchiveEffectServiceDoesNotResumeOrReclassifyRetainedWork(t *testing.T) {
	for _, stage := range []string{"pending-authority", "completed-secondary", "pending-start", "started", "pending-result", "succeeded", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			p := newArchivePruneFixture(t)
			retainArchiveInventory(t, p)
			fault := errors.New("retained effect session fixture interruption")
			switch stage {
			case "pending-authority":
				owner := p.operations[1].Coordinator
				entry := testEntry(t, testCoordination(t, owner).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(98))
				setCoordinatorHooks(owner, storeHooks{at: func(at string) error {
					if at == "intent-after-publish" {
						return fault
					}
					return nil
				}})
				if _, err := owner.Append(t.Context(), entry); !errors.Is(err, fault) {
					t.Fatal("missed authority interruption", err)
				}
			case "completed-secondary":
				owner := p.operations[1].Coordinator
				appendCoordinated(t, owner, testEntry(t, testCoordination(t, owner).Authority, custodyauthority.Complete,
					types.Hash{}, p.operations[1].Binding.TicketID, testHash(98)))
			case "cancelled":
				if _, err := p.f.executor.CancelBeforeStart(t.Context(), p.f.coordinator); err != nil {
					t.Fatal(err)
				}
			default:
				point := map[string]string{"pending-start": "pins-start-intent-after-publish", "started": "prune-before-effect", "pending-result": "pins-result-confirm-before-publish"}[stage]
				if point != "" {
					hook := func(at string) error {
						if at == point {
							return fault
						}
						return nil
					}
					p.f.executor.hooks.at, p.f.executor.pins.hooks.at = hook, hook
				}
				if _, err := p.execute(t.Context()); (stage == "succeeded" && err != nil) || (stage != "succeeded" && !errors.Is(err, fault)) {
					t.Fatal("missed executor fixture state", stage, err)
				}
			}
			config := archiveEffectServiceFixture(t, p)
			before := readArchiveEffectRetainedState(t, p, config)
			service, err := OpenPruneArchiveEffectService(config)
			if err == nil {
				review, reviewErr := service.Review(t.Context())
				if reviewErr == nil {
					id, _ := review.ID()
					if result, executeErr := service.Execute(t.Context(), id); executeErr == nil || result.Applied {
						t.Fatal("ineligible retained state executed", stage, executeErr)
					}
				}
			}
			if service != nil {
				_ = service.Close()
			}
			after := readArchiveEffectRetainedState(t, p, config)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("owned open/review executed recovery or changed terminal evidence", stage)
			}
		})
	}
}

func TestPruneArchiveEffectServiceDetachesConfigurationAndReview(t *testing.T) {
	p := newArchivePruneFixtureWithRenewals(t, []int{1, 1})
	config := archiveEffectServiceFixture(t, p)
	service := openArchiveEffectService(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	// Caller-owned slices and nested Base slices must not alter the accepted
	// filesystem, consensus context or review state after ownership is acquired.
	config.Authorities[0].AssignmentID = testHash(99)
	config.Authorities[0].AuthorityPath = filepath.Join(t.TempDir(), "different-owner")
	config.Replicas[0].Directory = filepath.Join(t.TempDir(), "different-replica")
	oldWork, oldTimestamp := config.Base.Tip.CumulativeWork[0], config.Base.RecentTimestamps[0]
	config.Base.Tip.CumulativeWork[0] ^= 1
	config.Base.RecentTimestamps[0]++
	defer func() { config.Base.Tip.CumulativeWork[0], config.Base.RecentTimestamps[0] = oldWork, oldTimestamp }()
	review.Authorities[0].AssignmentID = testHash(99)
	second, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	secondID, _ := second.ID()
	if secondID != id {
		t.Fatal("caller changed retained effect configuration or a later review")
	}
	if result, err := service.Execute(t.Context(), id); err != nil || !result.Applied {
		t.Fatal("caller changed guarded execution inputs", err)
	}
}

func TestPruneArchiveEffectServiceStaleReviewRequiresExplicitNewReview(t *testing.T) {
	p := newArchivePruneFixture(t)
	config := archiveEffectServiceFixture(t, p)
	service := openArchiveEffectService(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	// Exercise a changed original retained head through a package-private test
	// seam. The public capability deliberately exposes no owner mutation API.
	owner := service.coordinators[0]
	appendCoordinated(t, owner, testEntry(t, testCoordination(t, owner).Authority, custodyauthority.Stop, types.Hash{}, types.Hash{}, testHash(98)))
	if result, err := service.Execute(t.Context(), id); !errors.Is(err, ErrPruneArchiveEffectReview) || result.Applied {
		t.Fatal("old review followed a changed authority head", err)
	}
	if state := pruneSnapshot(t, service.executor); state.Stage != PruneAdmitted || state.Protection.Pending != nil {
		t.Fatal("stale review created a start")
	}
	fresh, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	freshID, _ := fresh.ID()
	if freshID == id {
		t.Fatal("review digest did not bind retained authority position")
	}
	// Stop permits already admitted work to drain. Only the newly inspected
	// local comparison value can select that explicit drain attempt.
	if result, err := service.Execute(t.Context(), freshID); err != nil || !result.Applied {
		t.Fatal("explicit reviewed drain failed", err)
	}
}

func TestPruneArchiveEffectServiceRechecksLineageAfterArchiveReplay(t *testing.T) {
	p := newArchivePruneFixtureWithRenewals(t, []int{2, 1})
	config := archiveEffectServiceFixture(t, p)
	service := openArchiveEffectService(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	var renamed bool
	service.executor.hooks.at = func(at string) error {
		if at == "archive-before-start" {
			if err := os.Rename(config.LineagePath, config.LineagePath+".saved"); err != nil {
				return err
			}
			renamed = true
		}
		return nil
	}
	if result, err := service.Execute(t.Context(), id); err == nil || result.Applied || !renamed {
		t.Fatal("replay silently used a lost retained lineage file", err)
	}
	state := pruneSnapshot(t, service.executor)
	if state.Stage != PruneAdmitted || state.Protection.Pending != nil || !state.ArchiveInventoryID.IsZero() {
		t.Fatal("lost lineage evidence left a new start")
	}
	protection, err := service.chain.StorageProtection()
	if err != nil || protection.Database != review.Storage || protection.Pending != nil {
		t.Fatal("lost lineage changed chain state", err)
	}
	// Immutable availability may already have been published during replay;
	// neither that artifact nor verified detached bodies grant execution.
	if _, err := os.Stat(config.AvailabilityPath); err != nil {
		t.Fatal("expected retained pre-start availability evidence", err)
	}
}

func TestPruneArchiveEffectServiceContextFailuresAreNonMutating(t *testing.T) {
	p := newArchivePruneFixture(t)
	config := archiveEffectServiceFixture(t, p)
	service := openArchiveEffectService(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if _, err := service.Review(ctx); err == nil {
			t.Fatal("invalid review context accepted")
		}
		if result, err := service.Execute(ctx, id); err == nil || result.Applied {
			t.Fatal("invalid execution context accepted", err)
		}
	}
	again, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	againID, _ := again.ID()
	if againID != id {
		t.Fatal("context rejection mutated owned state")
	}
}

func TestPruneArchiveEffectServiceConcurrentExecuteAppliesExactlyOnce(t *testing.T) {
	p := newArchivePruneFixture(t)
	config := archiveEffectServiceFixture(t, p)
	service := openArchiveEffectService(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	type outcome struct {
		result workchain.CanonicalPruneCommit
		err    error
	}
	results := make(chan outcome, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, err := service.Execute(t.Context(), id)
			results <- outcome{result, err}
		}()
	}
	workers.Wait()
	close(results)
	applied := 0
	for result := range results {
		if result.err == nil && result.result.Applied {
			applied++
		} else if result.err == nil {
			t.Fatal("non-applying retry reported live success")
		}
	}
	if applied != 1 {
		t.Fatal("concurrent reviewed callers did not apply exactly one effect", applied)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	state := readArchiveEffectRetainedState(t, p, config)
	if state.Executor.Stage != PruneSucceeded || state.Storage.Database.Sequence != review.Storage.Sequence+1 {
		t.Fatal("duplicate effect survived restart")
	}
}

func TestPruneArchiveEffectServiceCloseWaitsForGuardedEffect(t *testing.T) {
	p := newArchivePruneFixture(t)
	config := archiveEffectServiceFixture(t, p)
	service := openArchiveEffectService(t, config)
	review, err := service.Review(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := review.ID()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	service.executor.hooks.at = func(at string) error {
		if at == "archive-before-verification" {
			close(entered)
			<-release
		}
		return nil
	}
	effectDone := make(chan error, 1)
	go func() {
		result, err := service.Execute(t.Context(), id)
		if err == nil && !result.Applied {
			err = errors.New("guarded effect not applied")
		}
		effectDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("effect did not enter original guards")
	}
	closeStarted, closeDone := make(chan struct{}), make(chan error, 1)
	go func() { close(closeStarted); closeDone <- service.Close() }()
	<-closeStarted
	select {
	case err := <-closeDone:
		t.Fatal("Close released owners before effect drained", err)
	case <-time.After(30 * time.Millisecond):
	}
	assertArchiveEffectOwnersBusy(t, p, config)
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-effectDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("effect did not drain")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after effect")
	}
	assertArchiveEffectOwnersReleased(t, p, config)
	if _, err := service.Review(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal("closed capability reviewed owners", err)
	}
	if result, err := service.Execute(context.Background(), id); !errors.Is(err, ErrClosed) || result.Applied {
		t.Fatal("closed capability executed", err)
	}
}
