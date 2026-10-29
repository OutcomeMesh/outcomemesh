//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const replacementFile = "signer-replacement"
const replacementFileBytes = ed25519.PrivateKeySize + guard.ReplacementReceiptBytes

func (o *Owner) replacementCopy() *guard.ReplacementReceipt {
	if o.replacement == nil {
		return nil
	}
	r := *o.replacement
	return &r
}
func (o *Owner) loadReplacement() error {
	raw, err := privateRead(filepath.Join(o.root, replacementFile), replacementFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(raw) != replacementFileBytes {
		clear(raw)
		return ErrOwner
	}
	defer clear(raw)
	r, err := guard.DecodeReplacementReceipt(raw[ed25519.PrivateKeySize:])
	key := ed25519.PrivateKey(raw[:ed25519.PrivateKeySize])
	if err != nil || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) {
		return ErrOwner
	}
	var signer [32]byte
	copy(signer[:], key[32:])
	principal, err := r.Principal(o.descriptor.Guard, signer)
	if err != nil || principal != o.identity.PublicKey || o.replacementRoleConflict(signer) {
		return ErrOwner
	}
	stamp, err := PlacementID(filepath.Join(o.root, replacementFile), false)
	if err != nil {
		return err
	}
	clear(o.key)
	o.key = append(ed25519.PrivateKey(nil), key...)
	o.replacement = &r
	o.replacementBytes = append([]byte(nil), raw...)
	o.replacementStamp = stamp
	return nil
}
func (o *Owner) checkReplacement() error {
	path := filepath.Join(o.root, replacementFile)
	if o.replacement == nil {
		_, err := os.Lstat(path)
		if !errors.Is(err, os.ErrNotExist) {
			return ErrOwner
		}
		return nil
	}
	b, err := privateRead(path, replacementFileBytes)
	defer clear(b)
	if err != nil || !bytes.Equal(b, o.replacementBytes) {
		return ErrOwner
	}
	stamp, err := PlacementID(path, false)
	if err != nil || stamp != o.replacementStamp {
		return ErrOwner
	}
	return nil
}

// ActivateReplacement keeps the original descriptor, root, source, deployment,
// current position and complete runtime history. One exclusive, no-overwrite
// private file installs the new key. Unknown effects are not settled or retried.
// A locally revoked owner is never reactivated. Partial files remain blocked.
func ActivateReplacement(ctx context.Context, root string, descriptorID types.Hash, pin wire.Position, attempt *wire.Request, r guard.ReplacementReceipt, key ed25519.PrivateKey) error {
	if ctx == nil || ctx.Err() != nil || len(key) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) {
		return ErrOwner
	}
	proof, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	var signer [32]byte
	copy(signer[:], key[32:])
	o, err := Open(root, descriptorID, pin, attempt)
	if err != nil {
		return err
	}
	defer o.Close()
	principal, err := r.Principal(o.descriptor.Guard, signer)
	if err != nil || principal != o.identity.PublicKey || o.revoked || o.replacementRoleConflict(signer) || o.position != pin || o.execution == nil || o.execution.deployment.Guard != o.descriptor.Guard {
		return ErrOwner
	}
	raw := append(append([]byte(nil), key...), proof...)
	defer clear(raw)
	if o.replacement != nil {
		if !bytes.Equal(raw, o.replacementBytes) {
			return ErrOwner
		}
		// Confirm durability again after an exact interrupted installation.
		f, err := os.OpenFile(filepath.Join(root, replacementFile), os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		err = errors.Join(f.Sync(), f.Close())
		if err != nil {
			return err
		}
		if err = o.checkReplacement(); err != nil {
			return err
		}
		return syncDir(root)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = o.check(); err != nil {
		return err
	}
	return publish(filepath.Join(root, replacementFile), raw)
}

func (o *Owner) replacementRoleConflict(key [32]byte) bool {
	if gatewayRoleConflict(o.g, o.b, key) {
		return true
	}
	d := o.descriptor
	roles := append([][32]byte{d.Gateway, d.Issuer, d.Guard}, d.Clients...)
	if o.execution != nil {
		dep := o.execution.deployment
		roles = append(roles, dep.A.Gateway, dep.B.Gateway, dep.Authority, dep.Control)
	}
	for _, role := range roles {
		if key == role {
			return true
		}
	}
	return key == ([32]byte{})
}
