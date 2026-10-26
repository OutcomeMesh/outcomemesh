package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type PruneSecondaryCommandMode uint8

const (
	PruneSecondaryAdmission PruneSecondaryCommandMode = 1 + iota
	PruneSecondaryCompletion
	PruneSecondaryBoth
)

func (mode PruneSecondaryCommandMode) String() string {
	switch mode {
	case PruneSecondaryAdmission:
		return "admit"
	case PruneSecondaryCompletion:
		return "complete"
	case PruneSecondaryBoth:
		return "both"
	default:
		return "invalid"
	}
}

// PruneSecondaryCommandServiceConfig selects one original executor and target
// using the independently pinned inventory. Admission/both additionally require
// the original primary coordinator. Completion mode rejects primary roots.
// All owner roots and the dedicated inventory parent must be disjoint.
type PruneSecondaryCommandServiceConfig struct {
	Session                                        PreparedArchiveSecondaryCommandConfig
	Mode                                           PruneSecondaryCommandMode
	ExecutorPath, ExecutorPinsPath                 string
	AuthorityPath, AuthorityPinsPath               string // selected secondary
	PrimaryAuthorityPath, PrimaryAuthorityPinsPath string // admission/both only
}

type preparedSecondaryService struct {
	config  PreparedArchiveSecondaryCommandConfig
	mode    PruneSecondaryCommandMode
	primary *Coordinator
	owners  []*Coordinator // immutable acquisition order, released in reverse
}

// PruneSecondaryCommandService owns one selected secondary's command lifetime.
// The private runtime shares the primary service's admission gate and drain
// ordering. This wrapper deliberately exposes no maintenance, owner pointer,
// signer, WorkChain handle or execution/cancellation API.
type PruneSecondaryCommandService struct{ runtime *PruneCommandService }

// OpenPruneSecondaryCommandService opens only existing protected owners. It
// derives assignments and request from the independently pinned package, opens
// executor pins before their writer, then coordinators in assignment-ID order.
// Partial failure releases acquired owners in reverse; no root is bootstrapped,
// repaired or resumed. Completion mode never acquires the primary coordinator.
// No listener is created until Start. Stop/drain/Close before an offline effect
// or other operator takes these same owners; reopening alone advances no work.
func OpenPruneSecondaryCommandService(config PruneSecondaryCommandServiceConfig) (_ *PruneSecondaryCommandService, err error) {
	scope := config.Session
	if config.Mode < PruneSecondaryAdmission || config.Mode > PruneSecondaryBoth || scope.AssignmentID.IsZero() ||
		scope.Timeout < admissionwire.MinimumTimeout || scope.Timeout > admissionwire.MaximumTimeout ||
		scope.Timeout < completionwire.MinimumTimeout || scope.Timeout > completionwire.MaximumTimeout ||
		config.ExecutorPath == "" || config.ExecutorPinsPath == "" || config.AuthorityPath == "" || config.AuthorityPinsPath == "" {
		return nil, ErrPruneRuntime
	}
	needsPrimary := config.Mode != PruneSecondaryCompletion
	if needsPrimary && (config.PrimaryAuthorityPath == "" || config.PrimaryAuthorityPinsPath == "") ||
		!needsPrimary && (config.PrimaryAuthorityPath != "" || config.PrimaryAuthorityPinsPath != "") {
		return nil, ErrPruneRuntime
	}
	scope.InventoryPath, err = storePath(scope.InventoryPath)
	if err != nil {
		return nil, err
	}
	inventory, err := LoadArchivePruneInventoryFile(scope.InventoryPath, scope.InventoryID, scope.PolicyID)
	if err != nil {
		return nil, err
	}
	if err := validatePreparedArchiveSecondaryPeers(inventory, scope); err != nil {
		return nil, err
	}
	var primary, target custodyauthority.Assignment
	for _, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID()
		if id == inventory.Request.AssignmentID {
			primary = assignment
		}
		if id == scope.AssignmentID {
			target = assignment
		}
	}
	if scope.AssignmentID == inventory.Request.AssignmentID || target.ReplicaPublicKey == [32]byte{} || primary.ReplicaPublicKey == [32]byte{} {
		return nil, ErrPruneInventory
	}
	paths := []string{config.ExecutorPath, config.ExecutorPinsPath, config.AuthorityPath, config.AuthorityPinsPath,
		filepath.Dir(scope.InventoryPath)}
	if needsPrimary {
		paths = append(paths, config.PrimaryAuthorityPath, config.PrimaryAuthorityPinsPath)
	}
	// Resolve aliases/containment before opening even the first lifetime lock.
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			paths[i], paths[j], err = coordinatorPaths(paths[i], paths[j])
			if err != nil {
				return nil, err
			}
		}
	}
	executor, err := OpenPinnedPruneExecutor(paths[0], paths[1], primary, inventory.Policy.RequestID)
	if err != nil {
		return nil, err
	}
	prepared := &preparedSecondaryService{config: scope, mode: config.Mode}
	defer func() {
		if err != nil {
			for i := len(prepared.owners) - 1; i >= 0; i-- {
				err = errors.Join(err, prepared.owners[i].Close())
			}
			err = errors.Join(err, executor.Close())
		}
	}()
	type pair struct {
		assignment custodyauthority.Assignment
		id         types.Hash
		path, pins string
	}
	pairs := []pair{{target, scope.AssignmentID, paths[2], paths[3]}}
	if needsPrimary {
		pairs = append(pairs, pair{primary, inventory.Request.AssignmentID, paths[5], paths[6]})
	}
	sort.Slice(pairs, func(i, j int) bool { return types.CompareHash(pairs[i].id, pairs[j].id) < 0 })
	var secondary *Coordinator
	for _, pair := range pairs {
		owner, err := OpenCoordinator(pair.path, pair.pins, pair.assignment, pair.id)
		if err != nil {
			return nil, err
		}
		prepared.owners = append(prepared.owners, owner)
		if pair.id == scope.AssignmentID {
			secondary = owner
		} else {
			prepared.primary = owner
		}
	}
	// Static session checks are repeated at Start before creating any listener.
	if needsPrimary {
		if _, err := NewPreparedArchiveSecondaryAdmissionServer(executor, prepared.primary, secondary, scope); err != nil {
			return nil, err
		}
	}
	if config.Mode != PruneSecondaryAdmission {
		if _, err := NewPreparedArchiveSecondaryCompletionServer(executor, secondary, scope); err != nil {
			return nil, err
		}
	}
	runtime := &PruneCommandService{executor: executor, coordinator: secondary, preparedSecondary: prepared,
		serverPeerID: scope.ServerPeerID, clientPeerID: scope.ClientPeerID, timeout: scope.Timeout, done: make(chan struct{})}
	return &PruneSecondaryCommandService{runtime: runtime}, nil
}

func (service *PruneSecondaryCommandService) Start(ctx context.Context, key ed25519.PrivateKey, config libp2ptransport.Config) error {
	if service == nil || service.runtime == nil {
		return ErrClosed
	}
	return service.runtime.Start(ctx, key, config)
}

func (service *PruneSecondaryCommandService) Addresses() []string {
	if service == nil || service.runtime == nil {
		return nil
	}
	return service.runtime.Addresses()
}

func (service *PruneSecondaryCommandService) Done() <-chan struct{} {
	if service == nil || service.runtime == nil {
		return nil
	}
	return service.runtime.Done()
}

func (service *PruneSecondaryCommandService) Close() error {
	if service == nil || service.runtime == nil {
		return nil
	}
	return service.runtime.Close()
}
