package custodyv2

import (
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

// OpenReplacementAdmissionWitness replays the original root and exact retained
// pin. It never creates a genesis or resets spending, pending work or retention.
// VoteAt additionally binds the certificate to the signed job's guard key.
func OpenReplacementAdmissionWitness(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, expected custodyfence.WitnessPin, r guard.ReplacementReceipt, enrollment ...EnrollmentBinding) (*AdmissionWitness, error) {
	return openAdmissionMember(path, g, pin, key, enrollment, &r, func(w *AdmissionWitness) error {
		if w.pin() != expected {
			return ErrAdmissionHead
		}
		return nil
	})
}
func RecoverReplacementAdmissionVote(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, before custodyfence.WitnessPin, attempt AdmissionEntry, r guard.ReplacementReceipt, enrollment ...EnrollmentBinding) (*AdmissionWitness, error) {
	if err := attempt.Verify(g); err != nil {
		return nil, err
	}
	id, _ := attempt.ID()
	if attempt.ExpectedSequence != before.Position.Sequence || attempt.ExpectedHead != before.Position.HeadID || !before.PendingID.IsZero() && before.PendingID != id {
		return nil, ErrAdmissionHead
	}
	return openAdmissionMember(path, g, pin, key, enrollment, &r, func(w *AdmissionWitness) error {
		actual := w.pin()
		if actual.Position != before.Position || actual.PendingID != before.PendingID && actual.PendingID != id {
			return ErrAdmissionHead
		}
		return w.state.ValidateNext(attempt)
	})
}
func RecoverReplacementAdmissionCommit(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, before custodyfence.WitnessPin, attempt AdmissionCertificate, r guard.ReplacementReceipt, enrollment ...EnrollmentBinding) (*AdmissionWitness, error) {
	raw, err := attempt.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	attempt, err = DecodeAdmissionCertificate(raw)
	if err != nil {
		return nil, err
	}
	if err = attempt.Verify(g); err != nil {
		return nil, err
	}
	if attempt.Entry.ExpectedSequence != before.Position.Sequence || attempt.Entry.ExpectedHead != before.Position.HeadID {
		return nil, ErrAdmissionHead
	}
	return openAdmissionMember(path, g, pin, key, enrollment, &r, func(w *AdmissionWitness) error { return w.canCommitAt(before, attempt, raw) })
}
