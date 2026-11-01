package store

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
)

const scheduledPruneReceiptBytes = 10 + types.HashSize + scheduledwire.AcknowledgementBytes + types.HashSize

var ErrScheduledPruneIntent = errors.New("invalid pinned scheduled Prune delivery intent")

func validateScheduledPruneIntent(a custodyauthority.Assignment, i scheduledwire.Intent, expected types.Hash) error {
	id, err := i.ID()
	if err != nil || expected.IsZero() || id != expected {
		return errors.Join(ErrScheduledPruneIntent, err)
	}
	aid, err := a.ID()
	if err != nil || aid != i.Entry.Command.AssignmentID || a.AuthorityPublicKey != i.Entry.AuthorityPublicKey {
		return errors.Join(ErrScheduledPruneIntent, err)
	}
	for _, c := range a.Consumers {
		if c.PublicKey == i.Entry.Command.ActorPublicKey && c.Purposes&custodyauthority.Prune != 0 {
			return nil
		}
	}
	return custodyauthority.ErrActor
}

// This checksum protects local framing, not authenticity against a copied or
// compromised owner. Only the concrete pinned exchange can publish a receipt.
func scheduledPruneReceipt(id types.Hash, ack scheduledwire.Acknowledgement) ([]byte, error) {
	raw, err := ack.CanonicalBytes()
	if err != nil || id.IsZero() || ack.IntentID != id {
		return nil, errors.Join(ErrScheduledPruneIntent, err)
	}
	result := append([]byte("OMCSDONE\x00\x00"), id[:]...)
	result = append(result, raw...)
	sum := types.DomainHash("OMESH/custody-scheduled-prune/receipt/v0", result)
	return append(result, sum[:]...), nil
}

func decodeScheduledPruneReceipt(raw []byte, intent scheduledwire.Intent) (scheduledwire.Acknowledgement, error) {
	if len(raw) != scheduledPruneReceiptBytes || !bytes.HasPrefix(raw, []byte("OMCSDONE\x00\x00")) {
		return scheduledwire.Acknowledgement{}, ErrScheduledPruneIntent
	}
	id, err := intent.ID()
	if err != nil || !bytes.Equal(raw[10:42], id[:]) {
		return scheduledwire.Acknowledgement{}, errors.Join(ErrScheduledPruneIntent, err)
	}
	end := len(raw) - types.HashSize
	sum := types.DomainHash("OMESH/custody-scheduled-prune/receipt/v0", raw[:end])
	if !bytes.Equal(sum[:], raw[end:]) {
		return scheduledwire.Acknowledgement{}, ErrScheduledPruneIntent
	}
	ack, err := scheduledwire.DecodeAcknowledgement(raw[42:end])
	if err != nil || ack.IntentID != id {
		return scheduledwire.Acknowledgement{}, errors.Join(ErrScheduledPruneIntent, err)
	}
	return ack, nil
}
