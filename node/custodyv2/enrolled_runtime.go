package custodyv2

import (
	"crypto/ed25519"
	"github.com/outcomemesh/outcomemesh/core/types"
)

// These constructors are the sole profile-4 owner entry points. Ordinary raw
// and profile-3 constructors cannot adopt the retained enrollment implicitly.
func CreateEnrolledTarget(path string, c Context, pin types.Hash, sources Sources, admission AdmissionBinding, enrollment EnrollmentBinding) error {
	if c.Assignment.Policy.Version != PolicyVersionEnrolled {
		return ErrEnrollmentRequired
	}
	return createRootEnrolled(path, c, pin, "target", sources, &admission, &enrollment)
}
func OpenEnrolledTarget(path string, c Context, pin types.Hash, sources Sources, admission AdmissionBinding, enrollment EnrollmentBinding, replica, control ed25519.PrivateKey) (*Target, error) {
	if c.Assignment.Policy.Version != PolicyVersionEnrolled {
		return nil, ErrEnrollmentRequired
	}
	return openTargetEnrolled(path, c, pin, sources, &admission, &enrollment, replica, control)
}
func CreateEnrolledAcceptor(path string, c Context, pin types.Hash, journal string, admission AdmissionBinding, enrollment EnrollmentBinding) error {
	if c.Assignment.Policy.Version != PolicyVersionEnrolled {
		return ErrEnrollmentRequired
	}
	return createRootEnrolled(path, c, pin, "acceptor", Sources{Journal: journal}, &admission, &enrollment)
}
func OpenEnrolledAcceptor(path string, c Context, pin types.Hash, journal string, admission AdmissionBinding, enrollment EnrollmentBinding, key ed25519.PrivateKey) (*Acceptor, error) {
	if c.Assignment.Policy.Version != PolicyVersionEnrolled {
		return nil, ErrEnrollmentRequired
	}
	return openAcceptorEnrolled(path, c, pin, journal, &admission, &enrollment, key)
}
