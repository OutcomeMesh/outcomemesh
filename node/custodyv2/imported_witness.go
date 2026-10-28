package custodyv2

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
)

// VerifyImported verifies complete historical one-choice selection of the exact
// imported descriptor. It is not a live exclusion certificate for legacy keys.
func (b EnrollmentBinding) VerifyImported(g AdmissionGenesis) error {
	if g.Version != PolicyVersionImported || b.Version != PolicyVersionImported {
		return ErrEnrollmentRequired
	}
	expected, err := g.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := b.Registry.Validate(); err != nil {
		return err
	}
	if err := validateRegistryCandidateFields(b.Registry, g); err != nil {
		return err
	}
	raw, err := b.CanonicalBytes()
	if err != nil {
		return err
	}
	b, err = DecodeEnrollmentBinding(raw)
	if err != nil {
		return err
	}
	q, err := wire.DecodeCertificate(b.Certificate)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, q.Selection.Candidate) {
		return ErrEnrollmentRequired
	}
	return q.Verify(b.Registry, g.Assignment.Base.AuthorityPublicKey, g.Assignment.Base.RemoteControlPublicKey)
}
func importedEnrollment(g AdmissionGenesis, bindings []EnrollmentBinding) ([]byte, error) {
	if g.Version != PolicyVersionImported {
		if len(bindings) != 0 {
			return nil, ErrEnrollmentRequired
		}
		return nil, nil
	}
	if len(bindings) != 1 {
		return nil, ErrEnrollmentRequired
	}
	if err := bindings[0].VerifyImported(g); err != nil {
		return nil, err
	}
	return bindings[0].CanonicalBytes()
}
func admissionReady(g AdmissionGenesis, pin types.Hash, pub [32]byte, enrollment []byte) []byte {
	prefix := "OMCVAWR2"
	if g.Version == PolicyVersionImported {
		prefix = "OMCVAWR5"
	}
	raw := append(append([]byte(prefix), pin[:]...), pub[:]...)
	if g.Version == PolicyVersionImported {
		h := types.DomainHash("OMESH/custody/v5/retained-enrollment", enrollment)
		raw = append(raw, h[:]...)
	}
	return raw
}

// Imported owners retain permanent-lock change time as well as inode identity.
// This rejects ordinary immediate inode reuse; it is not hardware rollback protection.
func admissionPlacementFor(path string, g AdmissionGenesis) ([]byte, error) {
	raw, err := admissionPlacement(path)
	if err != nil || g.Version != PolicyVersionImported {
		return raw, err
	}
	info, err := os.Lstat(filepath.Join(path, "owner.lock"))
	if err != nil {
		return nil, err
	}
	seconds, nanos, err := importedLockChange(info)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Placement                                json.RawMessage
		LockChangeSeconds, LockChangeNanoseconds int64
	}{raw, seconds, nanos})
}
