package custodyv2

import (
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/types"
)

// These explicit constructors retain independently selected admission proof.
// Raw constructors never discover/adopt that proof from an untrusted root.
func CreateRequiredTarget(path string, c Context, pin types.Hash, sources Sources, binding AdmissionBinding) error {
	if c.Assignment.Policy.Version != PolicyVersionAdmission {
		return ErrAdmissionRequired
	}
	return createRootBound(path, c, pin, "target", sources, &binding)
}
func OpenRequiredTarget(path string, c Context, pin types.Hash, sources Sources, binding AdmissionBinding, replica, control ed25519.PrivateKey) (*Target, error) {
	if c.Assignment.Policy.Version != PolicyVersionAdmission {
		return nil, ErrAdmissionRequired
	}
	return openTargetBound(path, c, pin, sources, &binding, replica, control)
}
func CreateRequiredAcceptor(path string, c Context, pin types.Hash, journal string, binding AdmissionBinding) error {
	if c.Assignment.Policy.Version != PolicyVersionAdmission {
		return ErrAdmissionRequired
	}
	return createRootBound(path, c, pin, "acceptor", Sources{Journal: journal}, &binding)
}
func OpenRequiredAcceptor(path string, c Context, pin types.Hash, journal string, binding AdmissionBinding, key ed25519.PrivateKey) (*Acceptor, error) {
	if c.Assignment.Policy.Version != PolicyVersionAdmission {
		return nil, ErrAdmissionRequired
	}
	return openAcceptorBound(path, c, pin, journal, &binding, key)
}
