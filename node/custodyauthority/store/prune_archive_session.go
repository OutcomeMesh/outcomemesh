package store

import (
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// PreparedArchiveSecondaryCommandConfig fixes ONE selected secondary and both
// independently reviewed transport identities. It contains no key, listener or
// runtime ownership. Protect the inventory and both external content pins.
type PreparedArchiveSecondaryCommandConfig struct {
	InventoryPath                       string
	InventoryID, PolicyID, AssignmentID types.Hash
	ServerPeerID, ClientPeerID          types.Hash
	Timeout                             time.Duration
}

// Only the explicit constructors below populate a detached scope. Default
// primary constructors leave it nil; no wire request can select another mode.
type preparedArchiveSecondarySession struct {
	config  PreparedArchiveSecondaryCommandConfig
	primary *Coordinator // admission only; completion needs no live primary
}

// NewPreparedArchiveSecondaryAdmissionServer installs the existing wire adapter
// for the exact packaged secondary admission. It opens/resumes no owner or host.
// The caller retains all three original owners through handler drain, supplies
// the authenticated peer from its transport and checks host.ID()==ServerPeerID.
// Both peer pins are checked against every assignment's declared keys and the
// pinned checkpoint-attestor/replica trust keys in the inventory.
// Use one selected secondary per host: registering another handler for the same
// protocol replaces it, rather than adding a route. No primary/multi-target
// multiplexing or ownership handoff is inferred by this constructor.
func NewPreparedArchiveSecondaryAdmissionServer(executor *PruneExecutor, primary, secondary *Coordinator,
	config PreparedArchiveSecondaryCommandConfig,
) (*PruneAdmissionServer, error) {
	if executor == nil || primary == nil || secondary == nil {
		return nil, ErrClosed
	}
	config, primaryID, err := validatePreparedArchiveSecondarySession(executor, secondary, config)
	if err != nil {
		return nil, err
	}
	if primary == secondary || primary.assignmentID != primaryID {
		return nil, ErrPruneInventory
	}
	state, err := primary.Snapshot()
	if err != nil {
		return nil, err
	}
	if state.Authority.AssignmentID != primaryID {
		return nil, ErrPruneInventory
	}
	return &PruneAdmissionServer{executor: executor, coordinator: secondary, peer: config.ClientPeerID,
		timeout: config.Timeout, prepared: &preparedArchiveSecondarySession{config: config, primary: primary}}, nil
}

// NewPreparedArchiveSecondaryCompletionServer uses the existing Complete wire
// exchange for one selected secondary. It can be constructed before a terminal
// outcome exists: every Serve independently checks the actual confirmed executor
// state through CompletePreparedArchiveSecondary. No constructor observation is
// reused as authority. The primary owner may already be closed or drained.
// Caller host identity, single-target registration and ownership rules are the
// same as for NewPreparedArchiveSecondaryAdmissionServer.
func NewPreparedArchiveSecondaryCompletionServer(executor *PruneExecutor, secondary *Coordinator,
	config PreparedArchiveSecondaryCommandConfig,
) (*PruneCompletionServer, error) {
	if executor == nil || secondary == nil {
		return nil, ErrClosed
	}
	config, _, err := validatePreparedArchiveSecondarySession(executor, secondary, config)
	if err != nil {
		return nil, err
	}
	return &PruneCompletionServer{executor: executor, coordinator: secondary, peer: config.ClientPeerID,
		timeout: config.Timeout, prepared: &preparedArchiveSecondarySession{config: config}}, nil
}

// Static validation and detached diagnostics only. Pending stages and terminal
// history remain eligible for explicit reconciliation, never implicit recovery.
// The concrete guarded operation re-loads these exact pins on EACH request and
// re-syncs the package under the required owners before any authority write.
func validatePreparedArchiveSecondarySession(executor *PruneExecutor, secondary *Coordinator,
	config PreparedArchiveSecondaryCommandConfig,
) (PreparedArchiveSecondaryCommandConfig, types.Hash, error) {
	if config.AssignmentID.IsZero() || config.Timeout < admissionwire.MinimumTimeout || config.Timeout > admissionwire.MaximumTimeout ||
		config.Timeout < completionwire.MinimumTimeout || config.Timeout > completionwire.MaximumTimeout {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, ErrPruneRuntime
	}
	path, err := storePath(config.InventoryPath)
	if err != nil {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, err
	}
	config.InventoryPath = path
	inventory, err := LoadArchivePruneInventoryFile(path, config.InventoryID, config.PolicyID)
	if err != nil {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, err
	}
	state, err := executor.Snapshot()
	if err != nil {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, err
	}
	if state.Protection == nil {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, ErrPrunePin
	}
	if state.Request.StorageID.IsZero() || state.RequestID != inventory.Policy.RequestID ||
		state.Protection.BindingID != inventory.Policy.ExecutorBindingID || config.AssignmentID == state.Request.AssignmentID ||
		(!state.ArchiveInventoryID.IsZero() && state.ArchiveInventoryID != config.InventoryID) {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, ErrPruneInventory
	}
	targetFound, primaryMatches := false, state.Admission == nil
	for i, assignment := range inventory.Policy.Assignments {
		id, _ := assignment.ID()
		targetFound = targetFound || id == config.AssignmentID
		if state.Admission != nil && inventory.Admissions[i] == *state.Admission {
			primaryMatches = true
		}
	}
	if err := validatePreparedArchiveSecondaryPeers(inventory, config); err != nil {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, err
	}
	if !targetFound || !primaryMatches || secondary.assignmentID != config.AssignmentID {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, ErrPruneInventory
	}
	target, err := secondary.Snapshot()
	if err != nil {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, err
	}
	if target.Authority.AssignmentID != config.AssignmentID {
		return PreparedArchiveSecondaryCommandConfig{}, types.Hash{}, ErrPruneInventory
	}
	return config, state.Request.AssignmentID, nil
}

func validatePreparedArchiveSecondaryPeers(inventory ArchivePruneInventory, config PreparedArchiveSecondaryCommandConfig) error {
	if len(inventory.Policy.Assignments) == 0 || len(inventory.Policy.Assignments) > workarchive.MaximumReplicas {
		return ErrPruneInventory
	}
	for _, assignment := range inventory.Policy.Assignments {
		if err := validatePruneRuntimePeers(assignment, config.ServerPeerID, config.ClientPeerID); err != nil {
			return err
		}
	}
	for _, keys := range [][][32]byte{inventory.Policy.CheckpointPolicy.TrustedAttestors, inventory.Policy.ReplicaPolicy.TrustedReplicas} {
		for _, key := range keys {
			id, err := transport.PeerIDFromPublicKey(key[:])
			if err != nil || id == config.ServerPeerID || id == config.ClientPeerID {
				return ErrPruneRuntime
			}
		}
	}
	return nil
}
