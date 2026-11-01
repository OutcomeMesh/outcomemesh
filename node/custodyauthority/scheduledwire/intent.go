package scheduledwire

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

const IntentBytes = 10 + 7*types.HashSize + custodyauthority.MaximumEntryBytes

// Intent is immutable operator input, not a current permission. ReviewID is the
// receiver's independently reviewed local command position. InventoryID is zero
// only for admission, before accepted tickets can form an inventory. The server
// must validate these hashes against full original artifacts and retained owners.
type Intent struct {
	ClientPeerID, ServerPeerID types.Hash
	PlanID, RequestID          types.Hash
	ExecutorBindingID          types.Hash
	InventoryID, ReviewID      types.Hash
	Entry                      custodyauthority.Entry
}

var intentMagic = []byte("OMCPSINT\x00\x00")

func (i Intent) CanonicalBytes() ([]byte, error) {
	if i.ClientPeerID.IsZero() || i.ServerPeerID.IsZero() || i.ClientPeerID == i.ServerPeerID ||
		i.PlanID.IsZero() || i.RequestID.IsZero() || i.ExecutorBindingID.IsZero() || i.ReviewID.IsZero() ||
		i.Entry.Version != custodyauthority.ScheduleVersion2 || i.Entry.Command.Version != custodyauthority.ScheduleVersion2 {
		return nil, ErrProtocol
	}
	c := i.Entry.Command
	switch c.Kind {
	case custodyauthority.Admit:
		if c.Purpose != custodyauthority.Prune || c.OperationID != i.RequestID || !i.InventoryID.IsZero() {
			return nil, ErrProtocol
		}
	case custodyauthority.Complete:
		if i.InventoryID.IsZero() {
			return nil, ErrProtocol
		}
	default:
		return nil, ErrProtocol
	}
	entry, err := i.Entry.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrProtocol, err)
	}
	raw := append([]byte(nil), intentMagic...)
	for _, h := range []types.Hash{i.ClientPeerID, i.ServerPeerID, i.PlanID, i.RequestID, i.ExecutorBindingID, i.InventoryID, i.ReviewID} {
		raw = append(raw, h[:]...)
	}
	return append(raw, entry...), nil
}

func (i Intent) ID() (types.Hash, error) {
	raw, err := i.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-scheduled-prune/intent/id/v0", raw), nil
}

func DecodeIntent(raw []byte) (Intent, error) {
	if len(raw) != IntentBytes || !bytes.HasPrefix(raw, intentMagic) {
		return Intent{}, ErrProtocol
	}
	var i Intent
	offset := 10
	for _, h := range []*types.Hash{&i.ClientPeerID, &i.ServerPeerID, &i.PlanID, &i.RequestID, &i.ExecutorBindingID, &i.InventoryID, &i.ReviewID} {
		copy(h[:], raw[offset:offset+types.HashSize])
		offset += types.HashSize
	}
	var err error
	i.Entry, err = custodyauthority.DecodeEntry(raw[offset:])
	if err != nil {
		return Intent{}, errors.Join(ErrProtocol, err)
	}
	if _, err := i.CanonicalBytes(); err != nil {
		return Intent{}, err
	}
	return i, nil
}
