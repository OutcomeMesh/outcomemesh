//go:build linux || darwin

package pruneservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

const signerFile = "signer-succession"
const signerHeader = "OMPSKEY1"
const signerSeedOffset = len(signerHeader) + len(types.Hash{})
const signerProofOffset = signerSeedOffset + ed25519.SeedSize
const signerRecordBytes = signerProofOffset + prunefence.SuccessionBytes

func (o *Owner) serviceIdentity(guard guardwire.Chooser) (*prunefence.ServiceIdentity, error) {
	if o.succession != nil {
		return prunefence.NewSuccessorServiceIdentity(*o.descriptor.Policy.Service, o.key, guard, *o.succession)
	}
	return prunefence.NewServiceIdentity(*o.descriptor.Policy.Service, o.key, guard)
}

func (o *Owner) verifySignerRoles(s prunefence.ServiceSuccession) error {
	if err := o.inventory.CheckSuccessorRoles(s); err != nil {
		return err
	}
	q := s.Replacement.Request
	for _, key := range [][32]byte{q.Successor, q.Authority} {
		if key == o.descriptor.Transport {
			return ErrOwner
		}
		for _, endpoint := range o.config.Witnesses {
			if key == endpoint.Transport {
				return ErrOwner
			}
		}
		for _, source := range o.config.Runtime.Sources {
			if slices.Contains(source.CustodyPolicy.TrustedAuditors, key) {
				return ErrOwner
			}
		}
	}
	return nil
}

func (o *Owner) loadSuccessor(did types.Hash) error {
	path := filepath.Join(o.root, signerFile)
	// Lstat distinguishes an absent record from an invalid or dangling private path.
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := o.capture(signerFile); err != nil {
		return err
	}
	raw, err := privateRead(path, signerRecordBytes)
	defer clear(raw)
	if err != nil || len(raw) != signerRecordBytes || string(raw[:len(signerHeader)]) != signerHeader ||
		!bytes.Equal(raw[len(signerHeader):signerSeedOffset], did[:]) {
		return errors.Join(ErrOwner, err)
	}
	d := o.descriptor
	s, err := prunefence.DecodeServiceSuccession(raw[signerProofOffset:], d.Policy, d.Binding)
	if err != nil {
		return err
	}
	if err = o.verifySignerRoles(s); err != nil {
		return err
	}
	key := ed25519.NewKeyFromSeed(raw[signerSeedOffset:signerProofOffset])
	if !bytes.Equal(key[32:], s.Replacement.Request.Successor[:]) {
		clear(key)
		return ErrOwner
	}
	clear(o.key)
	o.key, o.succession, o.signerFileHash = key, &s, sha256.Sum256(raw)
	// A crash can leave all bytes visible before the file or its name is synced.
	return o.syncSignerFile()
}

func (o *Owner) checkSignerFile() error {
	path := filepath.Join(o.root, signerFile)
	if o.succession == nil {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return ErrOwner
	}
	raw, err := privateRead(path, signerRecordBytes)
	defer clear(raw)
	if err != nil || sha256.Sum256(raw) != o.signerFileHash {
		return errors.Join(ErrOwner, err)
	}
	return nil
}

func (o *Owner) syncSignerFile() error {
	f, err := os.OpenFile(filepath.Join(o.root, signerFile), os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	if err = errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = o.checkFiles(); err != nil {
		return err
	}
	return syncDirectory(o.root)
}

// ReviewSuccessorPaths checks external paths using only the immutable config
// committed by the public descriptor. Review does not open any signing key,
// runtime store or owner lock.
func ReviewSuccessorPaths(root string, configID types.Hash, report string, inputs ...string) error {
	raw, err := privateRead(filepath.Join(root, "config"), MaximumConfigBytes)
	if err != nil {
		return err
	}
	if types.DomainHash(domain+"configuration/v0", raw) != configID {
		return ErrOwner
	}
	config, err := DecodeConfig(raw)
	if err != nil {
		return err
	}
	return checkSuccessorPaths(root, config, report, inputs)
}

func checkSuccessorPaths(root string, config Config, report string, inputs []string) error {
	// The CLI publishes this file after the owner releases its lock. A peer
	// must not be able to redirect publication by replacing a public ancestor.
	if err := checkNonreplaceableParent(report); err != nil {
		return err
	}
	protected := append(originalPaths(config), root)
	placements := make([]os.FileInfo, 0, len(protected))
	for _, path := range protected {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		placements = append(placements, info)
	}
	for _, path := range append([]string{report}, inputs...) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrOwner
		}
		parent := filepath.Dir(path)
		if resolved, err := filepath.EvalSymlinks(parent); err != nil || resolved != parent {
			return ErrOwner
		}
		for _, p := range protected {
			if nested(p, path) || nested(path, p) {
				return ErrOwner
			}
		}
		// Physical identity also catches alternate spellings on a
		// case-insensitive filesystem and a hard link to an original file.
		for p := path; ; p = filepath.Dir(p) {
			info, err := os.Lstat(p)
			if err != nil {
				if p == path && errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
			if p == path {
				native, ok := info.Sys().(*syscall.Stat_t)
				// A name outside the tree can still reference a file inside a
				// protected subtree. Rule that out without enumerating its files.
				if !info.Mode().IsRegular() || !ok || native.Nlink != 1 {
					return ErrOwner
				}
			}
			for _, placement := range placements {
				if os.SameFile(info, placement) {
					return ErrOwner
				}
			}
			if p == filepath.Dir(p) {
				break
			}
		}
	}
	return nil
}

// ActivateSuccessor installs one signer for the descriptor's still untouched
// admission. The exclusive owner and original runtime locks span the check and
// publication. An exact retry can confirm only the same installation. File-based
// callers supply the report destination followed by their external inputs.
func ActivateSuccessor(ctx context.Context, root string, did types.Hash, pin wire.Position, s prunefence.ServiceSuccession, key ed25519.PrivateKey, externalPaths ...string) (returnErr error) {
	if ctx == nil || pin != (wire.Position{}) || len(key) != ed25519.PrivateKeySize {
		return ErrPosition
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(key, derived) || !bytes.Equal(key[32:], s.Replacement.Request.Successor[:]) {
		return ErrOwner
	}
	o, err := Open(ctx, root, did, pin, nil)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, o.Close()) }()
	d := o.descriptor
	if len(externalPaths) > 0 {
		if err = checkSuccessorPaths(root, o.config, externalPaths[0], externalPaths[1:]); err != nil {
			return err
		}
	}
	proof, err := s.CanonicalBytes(d.Policy, d.Binding)
	if err != nil {
		return err
	}
	if err = o.verifySignerRoles(s); err != nil {
		return err
	}
	if err = validatePlacement(ctx, root, o.config); err != nil {
		return err
	}
	runtime, err := store.OpenScheduledPruneEffectService(ctx, o.config.Runtime)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, runtime.Close()) }()
	r, err := runtime.Review(ctx)
	if err != nil {
		return err
	}
	if r.ReviewID != d.ReviewID || r.ScopeID != d.ScopeID || r.Executor.Stage != store.PruneAdmitted ||
		r.Executor.FenceCandidate != nil || r.Executor.Protection == nil || r.Executor.Protection.Pending != nil {
		return ErrHeld
	}
	if err = o.check(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if o.succession != nil {
		if *o.succession != s || !bytes.Equal(o.key, key) {
			return ErrOwner
		}
		return nil // openConfigured confirmed this exact record's durability.
	}
	record := make([]byte, signerRecordBytes)
	defer clear(record)
	copy(record, signerHeader)
	copy(record[len(signerHeader):], did[:])
	copy(record[signerSeedOffset:], key[:ed25519.SeedSize])
	copy(record[signerProofOffset:], proof)
	return publish(filepath.Join(root, signerFile), record)
}
