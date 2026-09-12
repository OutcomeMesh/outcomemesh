package store

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
)

const (
	AdmissionIntentBytes  = 10 + 2*types.HashSize + custodyauthority.MaximumEntryBytes
	admissionReceiptBytes = 10 + types.HashSize + admissionwire.AcknowledgementBytes + types.HashSize
)

var ErrAdmissionIntent = errors.New("invalid pinned admission delivery intent")

// AdmissionIntent fixes one already co-signed command and both transport peers.
// Retain its ID independently before Create/Open. An endpoint address is only a
// caller-selected route to ServerPeerID; it is never the source of that trust pin.
// OperationID binds the separately prepared PruneRequest; its bytes are not
// retained here. This intent does not prove server preparation, current authority
// or permission to execute. The server must validate its own retained request.
type AdmissionIntent struct {
	ClientPeerID types.Hash
	ServerPeerID types.Hash
	Entry        custodyauthority.Entry
}

func (intent AdmissionIntent) CanonicalBytes() ([]byte, error) {
	if intent.ClientPeerID.IsZero() || intent.ServerPeerID.IsZero() || intent.ClientPeerID == intent.ServerPeerID ||
		intent.Entry.Command.Kind != custodyauthority.Admit || intent.Entry.Command.Purpose != custodyauthority.Prune {
		return nil, ErrAdmissionIntent
	}
	entry, err := intent.Entry.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrAdmissionIntent, err)
	}
	encoded := append([]byte("OMCASEND\x00\x00"), intent.ClientPeerID[:]...)
	encoded = append(encoded, intent.ServerPeerID[:]...)
	return append(encoded, entry...), nil
}

func (intent AdmissionIntent) ID() (types.Hash, error) {
	encoded, err := intent.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-admission/intent/id/v0", encoded), nil
}

func DecodeAdmissionIntent(encoded []byte) (AdmissionIntent, error) {
	if len(encoded) != AdmissionIntentBytes || !bytes.HasPrefix(encoded, []byte("OMCASEND\x00\x00")) {
		return AdmissionIntent{}, ErrAdmissionIntent
	}
	var intent AdmissionIntent
	copy(intent.ClientPeerID[:], encoded[10:42])
	copy(intent.ServerPeerID[:], encoded[42:74])
	var err error
	intent.Entry, err = custodyauthority.DecodeEntry(encoded[74:])
	if err != nil {
		return AdmissionIntent{}, errors.Join(ErrAdmissionIntent, err)
	}
	if _, err := intent.CanonicalBytes(); err != nil {
		return AdmissionIntent{}, err
	}
	return intent, nil
}

func validateAdmissionIntent(assignment custodyauthority.Assignment, intent AdmissionIntent, expectedID types.Hash) error {
	aid, err := assignment.ID()
	if err != nil || aid != intent.Entry.Command.AssignmentID || intent.Entry.AuthorityPublicKey != assignment.AuthorityPublicKey {
		return errors.Join(ErrAdmissionIntent, err)
	}
	id, err := intent.ID()
	if err != nil || expectedID.IsZero() || id != expectedID ||
		intent.Entry.Command.ExpectedSequence > 2*(uint64(assignment.MaximumOperations)-1) {
		return errors.Join(ErrAdmissionIntent, err)
	}
	// Before Admit, at most N-1 admissions and N-1 completions can exist;
	// Stop and Retire forbid new admissions. This is only a static bound, not
	// a current-head check or a claim that the operation is still admissible.
	for _, consumer := range assignment.Consumers {
		if consumer.PublicKey == intent.Entry.Command.ActorPublicKey && consumer.Purposes&custodyauthority.Prune != 0 {
			return nil
		}
	}
	return custodyauthority.ErrActor
}

// The checksummed receipt is a local observation of an authenticated exchange,
// not a signed portable proof. The concrete delivery path alone can publish it.
func admissionReceipt(intentID types.Hash, ack admissionwire.Acknowledgement) ([]byte, error) {
	encoded, err := ack.CanonicalBytes()
	if err != nil || intentID.IsZero() {
		return nil, errors.Join(ErrAdmissionIntent, err)
	}
	result := append([]byte("OMCADONE\x00\x00"), intentID[:]...)
	result = append(result, encoded...)
	sum := types.DomainHash("OMESH/custody-admission/receipt/v0", result)
	return append(result, sum[:]...), nil
}

func decodeAdmissionReceipt(encoded []byte, intent AdmissionIntent) (admissionwire.Acknowledgement, error) {
	if len(encoded) != admissionReceiptBytes || !bytes.HasPrefix(encoded, []byte("OMCADONE\x00\x00")) {
		return admissionwire.Acknowledgement{}, ErrAdmissionIntent
	}
	id, err := intent.ID()
	if err != nil || !bytes.Equal(encoded[10:42], id[:]) {
		return admissionwire.Acknowledgement{}, errors.Join(ErrAdmissionIntent, err)
	}
	bodyEnd := len(encoded) - types.HashSize
	sum := types.DomainHash("OMESH/custody-admission/receipt/v0", encoded[:bodyEnd])
	if !bytes.Equal(sum[:], encoded[bodyEnd:]) {
		return admissionwire.Acknowledgement{}, ErrAdmissionIntent
	}
	ack, err := admissionwire.DecodeAcknowledgement(encoded[42:bodyEnd])
	entryID, _ := intent.Entry.ID()
	if err != nil || ack.EntryID != entryID {
		return admissionwire.Acknowledgement{}, errors.Join(ErrAdmissionIntent, err)
	}
	return ack, nil
}
