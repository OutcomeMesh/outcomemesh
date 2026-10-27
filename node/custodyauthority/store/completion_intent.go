package store

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
)

const (
	CompletionIntentBytes  = 10 + 2*types.HashSize + custodyauthority.MaximumEntryBytes
	completionReceiptBytes = 10 + types.HashSize + completionwire.AcknowledgementBytes + types.HashSize
)

var ErrCompletionIntent = errors.New("invalid pinned completion delivery intent")

// CompletionIntent fixes one already co-signed command and both transport peers.
// Retain its ID independently before Create/Open. An endpoint address is only a
// caller-selected route to ServerPeerID; it is never the source of that trust pin.
// This intent does not prove a terminal effect or a current authority position.
type CompletionIntent struct {
	ClientPeerID types.Hash
	ServerPeerID types.Hash
	Entry        custodyauthority.Entry
}

func (intent CompletionIntent) CanonicalBytes() ([]byte, error) {
	if intent.ClientPeerID.IsZero() || intent.ServerPeerID.IsZero() || intent.ClientPeerID == intent.ServerPeerID ||
		intent.Entry.Version != custodyauthority.Version0 || intent.Entry.Command.Version != custodyauthority.Version0 ||
		intent.Entry.Command.Kind != custodyauthority.Complete {
		return nil, ErrCompletionIntent
	}
	entry, err := intent.Entry.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrCompletionIntent, err)
	}
	encoded := append([]byte("OMCCSEND\x00\x00"), intent.ClientPeerID[:]...)
	encoded = append(encoded, intent.ServerPeerID[:]...)
	return append(encoded, entry...), nil
}

func (intent CompletionIntent) ID() (types.Hash, error) {
	encoded, err := intent.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-completion/intent/id/v0", encoded), nil
}

func DecodeCompletionIntent(encoded []byte) (CompletionIntent, error) {
	if len(encoded) != CompletionIntentBytes || !bytes.HasPrefix(encoded, []byte("OMCCSEND\x00\x00")) {
		return CompletionIntent{}, ErrCompletionIntent
	}
	var intent CompletionIntent
	copy(intent.ClientPeerID[:], encoded[10:42])
	copy(intent.ServerPeerID[:], encoded[42:74])
	var err error
	intent.Entry, err = custodyauthority.DecodeEntry(encoded[74:])
	if err != nil {
		return CompletionIntent{}, errors.Join(ErrCompletionIntent, err)
	}
	if _, err := intent.CanonicalBytes(); err != nil {
		return CompletionIntent{}, err
	}
	return intent, nil
}

func validateCompletionIntent(assignment custodyauthority.Assignment, intent CompletionIntent, expectedID types.Hash) error {
	if assignment.Version != custodyauthority.Version0 {
		return ErrCompletionIntent
	}
	aid, err := assignment.ID()
	if err != nil || aid != intent.Entry.Command.AssignmentID || intent.Entry.AuthorityPublicKey != assignment.AuthorityPublicKey {
		return errors.Join(ErrCompletionIntent, err)
	}
	id, err := intent.ID()
	if err != nil || expectedID.IsZero() || id != expectedID ||
		intent.Entry.Command.ExpectedSequence >= 2*uint64(assignment.MaximumOperations)+2 {
		return errors.Join(ErrCompletionIntent, err)
	}
	for _, consumer := range assignment.Consumers {
		if consumer.PublicKey == intent.Entry.Command.ActorPublicKey && consumer.Purposes&custodyauthority.Prune != 0 {
			return nil
		}
	}
	return custodyauthority.ErrActor
}

// The checksummed receipt is a local observation of an authenticated exchange,
// not a signed portable proof. The concrete delivery path alone can publish it.
func completionReceipt(intentID types.Hash, ack completionwire.Acknowledgement) ([]byte, error) {
	encoded, err := ack.CanonicalBytes()
	if err != nil || intentID.IsZero() {
		return nil, errors.Join(ErrCompletionIntent, err)
	}
	result := append([]byte("OMCCDONE\x00\x00"), intentID[:]...)
	result = append(result, encoded...)
	sum := types.DomainHash("OMESH/custody-completion/receipt/v0", result)
	return append(result, sum[:]...), nil
}

func decodeCompletionReceipt(encoded []byte, intent CompletionIntent) (completionwire.Acknowledgement, error) {
	if len(encoded) != completionReceiptBytes || !bytes.HasPrefix(encoded, []byte("OMCCDONE\x00\x00")) {
		return completionwire.Acknowledgement{}, ErrCompletionIntent
	}
	id, err := intent.ID()
	if err != nil || !bytes.Equal(encoded[10:42], id[:]) {
		return completionwire.Acknowledgement{}, errors.Join(ErrCompletionIntent, err)
	}
	bodyEnd := len(encoded) - types.HashSize
	sum := types.DomainHash("OMESH/custody-completion/receipt/v0", encoded[:bodyEnd])
	if !bytes.Equal(sum[:], encoded[bodyEnd:]) {
		return completionwire.Acknowledgement{}, ErrCompletionIntent
	}
	ack, err := completionwire.DecodeAcknowledgement(encoded[42:bodyEnd])
	entryID, _ := intent.Entry.ID()
	if err != nil || ack.EntryID != entryID {
		return completionwire.Acknowledgement{}, errors.Join(ErrCompletionIntent, err)
	}
	return ack, nil
}
