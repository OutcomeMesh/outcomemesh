package workchain

import "github.com/outcomemesh/outcomemesh/core/types"

// CanonicalPruneInspection is a historical local observation at one confirmed
// storage position. A nil Effect means only that this database had no record for
// the queried ticket. It is not proof of no effect, a grant or copy fencing.
type CanonicalPruneInspection struct {
	TicketID types.Hash
	Storage  StorageProtection
	Effect   *CanonicalPruneEffect
}

// InspectCanonicalPrune reads the position and result under the same chain lock.
// Unpinned stores, uncertain/pending positions and read failures return errors;
// errors never become an observation of absence. It performs no state transition.
func (store *Store) InspectCanonicalPrune(ticketID types.Hash) (CanonicalPruneInspection, error) {
	if store == nil || ticketID.IsZero() {
		return CanonicalPruneInspection{}, ErrCanonicalPrune
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if err := store.openErrorLocked(); err != nil {
		return CanonicalPruneInspection{}, err
	}
	protection, err := store.storageProtectionLocked()
	if err != nil {
		return CanonicalPruneInspection{}, err
	}
	if protection.Pending != nil || protection.Database != protection.Confirmed {
		return CanonicalPruneInspection{}, ErrStoragePinPending
	}
	effect, found, err := store.persistence.pruneEffect(ticketID)
	if err != nil {
		return CanonicalPruneInspection{}, err
	}
	result := CanonicalPruneInspection{TicketID: ticketID, Storage: protection}
	if found {
		result.Effect = &effect
	}
	return result, nil
}
