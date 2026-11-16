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

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodygateway"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	"golang.org/x/sys/unix"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Both paths are required on every retry. At most one may contain the original.
func transferLocation(r TransferReview) (string, error) {
	src, dst := r.containers()
	if !validTransferPaths(r.Source, r.Destination, r.Bundle) || nested(src, dst) || nested(dst, src) {
		return "", ErrOwner
	}
	for _, p := range []string{src, dst} {
		if err := checkNonreplaceableParent(p); err != nil {
			return "", err
		}
	}
	s, err := absent(src)
	if err != nil {
		return "", err
	}
	d, err := absent(dst)
	if err != nil {
		return "", err
	}
	if s == d {
		return "", ErrOwner
	}
	if s {
		return r.Destination, nil
	}
	return r.Source, nil
}

func duplicateTransferLock(root string, held *os.File) (*os.File, error) {
	path := filepath.Join(root, "lock")
	a, err := held.Stat()
	if err != nil {
		return nil, err
	}
	b, err := os.Lstat(path)
	if err != nil || !os.SameFile(a, b) {
		return nil, errors.Join(ErrOwner, err)
	}
	fd, err := unix.FcntlInt(held.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// A dedicated container can contain the named original roots and intermediate
// directories only. Moving it must not carry unrelated operator data or a mount.
func checkTransferBundle(ctx context.Context, o *Owner, container string) error {
	if _, err := custodygateway.PlacementID(container, true); err != nil {
		return err
	}
	paths := append(originalPaths(o.config), o.root)
	for _, p := range paths {
		if p == container || !nested(container, p) || p != o.root && (nested(p, o.root) || nested(o.root, p)) {
			return ErrOwner
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if _, err = custodygateway.PlacementID(p, info.IsDir()); err != nil {
			return err
		}
	}
	rootInfo, err := os.Lstat(container)
	if err != nil {
		return err
	}
	dev := rootInfo.Sys().(*syscall.Stat_t).Dev
	mount, err := transferMountID(container)
	if err != nil {
		return err
	}
	return filepath.WalkDir(container, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		location, err := transferMountID(p)
		if err != nil {
			return err
		}
		if location != mount {
			return syscall.EXDEV
		}
		n, ok := info.Sys().(*syscall.Stat_t)
		if !ok || n.Dev != dev || n.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || !info.IsDir() && (!info.Mode().IsRegular() || n.Nlink != 1) {
			return ErrOwner
		}
		for _, known := range paths {
			if nested(known, p) || info.IsDir() && nested(p, known) {
				return nil
			}
		}
		return ErrOwner
	})
}

// The seal-time cursor and signer flag select a fixed file set. A later intent,
// response or approved signer can be added without weakening that earlier set.
func reviewOwnerFiles(root string, r TransferReview) (types.Hash, error) {
	type entry struct {
		name  string
		limit int
	}
	files := []entry{
		{"config", MaximumConfigBytes},
		{"descriptor", wire.MaximumDescriptorBytes},
		{"identity", 1024},
		{"inventory", store.MaximumScheduledPruneInventoryBytes},
		{"key", ed25519.PrivateKeySize},
		{"lock", 0},
		{"transport-key", ed25519.PrivateKeySize},
	}
	if r.SignerInstalled {
		files = append(files, entry{signerFile, signerRecordBytes})
	}
	if r.Position.Sequence >= 1 {
		files = append(files, entry{"events/intent", wire.RequestBytes})
	}
	if r.Position.Sequence == 2 {
		files = append(files, entry{"events/result", wire.MaximumResponseBytes})
	}
	e := codec.NewEncoder(1024)
	for _, file := range files {
		path, logical := filepath.Join(root, file.name), filepath.Join(r.Source, file.name)
		stamp, err := custodygateway.PlacementIDAt(path, logical, false)
		if err != nil {
			return types.Hash{}, err
		}
		raw, err := privateRead(path, file.limit)
		if err != nil {
			return types.Hash{}, err
		}
		digest := sha256.Sum256(raw)
		clear(raw)
		after, err := custodygateway.PlacementIDAt(path, logical, false)
		if err != nil || after != stamp {
			return types.Hash{}, errors.Join(ErrOwner, err)
		}
		e.BytesField([]byte(file.name))
		e.Fixed(stamp[:])
		e.Fixed(digest[:])
	}
	return types.DomainHash(domain+"transfer/owner-files/v0", e.Bytes()), nil
}

func (r TransferReview) checkOwnerFiles(root string) error {
	actual, err := reviewOwnerFiles(root, r)
	if err != nil || actual != r.OwnerFilesID {
		return errors.Join(ErrOwner, err)
	}
	return nil
}

// Both names can be absent at review time. Reserve equivalent spellings in
// the same physical parent so publishing the report cannot collide with the
// transferred directory on a case- or normalization-insensitive filesystem.
func checkTransferReportName(report, unused string) error {
	fold := func(path string) string {
		return norm.NFD.String(cases.Fold().String(norm.NFD.String(filepath.Base(path))))
	}
	if fold(report) != fold(unused) {
		return nil
	}
	a, err := os.Stat(filepath.Dir(report))
	if err != nil {
		return err
	}
	b, err := os.Stat(filepath.Dir(unused))
	if err != nil {
		return err
	}
	if os.SameFile(a, b) {
		return ErrOwner
	}
	return nil
}

func prepareTransfer(ctx context.Context, o *Owner, r TransferReview, report string, inputs []string) (review TransferReview, runtime *store.ScheduledPruneEffectService, returnErr error) {
	src, dst := r.containers()
	container, other := src, dst
	if o.root == r.Destination {
		container, other = dst, src
	}
	if err := checkTransferReportName(report, other); err != nil {
		return review, nil, err
	}
	if err := o.loadEvents(); err != nil {
		return review, nil, err
	}
	if r.Position != o.position {
		return review, nil, ErrPosition
	}
	if err := o.check(); err != nil {
		return review, nil, err
	}
	if err := o.checkTransferredRuntime(); err != nil {
		return review, nil, err
	}
	protected := append(originalPaths(o.config), o.root)
	if r.Bundle != (TransferBundle{}) {
		if err := checkTransferBundle(ctx, o, container); err != nil {
			return review, nil, err
		}
		protected = append(protected, container)
	} else if err := validatePlacement(ctx, o.root, o.config); err != nil {
		return review, nil, err
	}
	// The unused destination (or the old source on retry) must lie outside
	// every original. This also rejects aliases on case-insensitive volumes.
	for _, p := range append(slices.Clone(inputs), report) {
		if nested(other, p) || nested(p, other) {
			return review, nil, ErrOwner
		}
	}
	if err := checkExternalPaths(protected, report, append(slices.Clone(inputs), other)); err != nil {
		return review, nil, err
	}
	var err error
	r.SourceParentID, err = nativeDirectoryID(filepath.Dir(src))
	if err != nil {
		return review, nil, err
	}
	r.DestinationParentID, err = nativeDirectoryID(filepath.Dir(dst))
	if err != nil {
		return review, nil, err
	}
	sourceParent, err := os.Stat(filepath.Dir(container))
	if err != nil {
		return review, nil, err
	}
	destParent, err := os.Stat(filepath.Dir(other))
	if err != nil {
		return review, nil, err
	}
	item, err := os.Stat(container)
	if err != nil {
		return review, nil, err
	}
	dev := item.Sys().(*syscall.Stat_t).Dev
	if sourceParent.Sys().(*syscall.Stat_t).Dev != dev || destParent.Sys().(*syscall.Stat_t).Dev != dev {
		return review, nil, syscall.EXDEV
	}
	mount, err := transferMountID(container)
	if err != nil {
		return review, nil, err
	}
	for _, parent := range []string{filepath.Dir(src), filepath.Dir(dst)} {
		location, e := transferMountID(parent)
		if e != nil {
			return review, nil, e
		}
		if location != mount {
			return review, nil, syscall.EXDEV
		}
	}
	r.ContainerID, err = custodygateway.PlacementIDAt(container, src, true)
	if err != nil {
		return review, nil, err
	}
	r.SignerInstalled = o.succession != nil
	r.OwnerFilesID, err = reviewOwnerFiles(o.root, r)
	if err != nil {
		return review, nil, err
	}
	r.RootID, r.InventoryID = o.identity.RootID, o.descriptor.Binding.InventoryID
	s, err := store.OpenScheduledPruneEffectService(ctx, o.config.Runtime)
	if err != nil {
		return review, nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, s.Close())
		}
	}()
	v, err := s.Review(ctx)
	if err != nil {
		return review, nil, err
	}
	if v.Executor.Protection == nil || v.Executor.Protection.Pending != nil {
		return review, nil, ErrHeld
	}
	v, err = o.originalReview(v)
	if err != nil {
		return review, nil, err
	}
	if v.ScopeID != o.descriptor.ScopeID || v.InventoryID != r.InventoryID {
		return review, nil, ErrPosition
	}
	r.ScopeID, r.RuntimeReviewID = v.ScopeID, v.ReviewID
	for _, part := range []transferScope{transferExecutor, transferSettlement, transferRuntime} {
		pins, err := o.transferPlacements(part)
		if err != nil {
			return review, nil, err
		}
		*r.placementID(part) = pins
	}
	if _, err = r.ID(); err != nil {
		return review, nil, err
	}
	return r, s, nil
}

func retainTransfer(root string, r TransferReview, hooks ownerHooks, apply bool) error {
	h, err := r.ID()
	if err != nil {
		return err
	}
	name, err := findTransfer(root)
	if err != nil {
		return err
	}
	want := transferPrefix + h.String()
	if name != "" && name != want {
		return ErrPosition
	}
	path := filepath.Join(root, want)
	missing, err := absent(path)
	if err != nil {
		return err
	}
	if missing {
		if root != r.Source {
			return ErrHeld
		}
		if !apply {
			return nil
		}
	}
	raw, err := r.signedBytes(root)
	if err != nil {
		return err
	}
	if missing {
		return publishWithHooks(path, raw, hooks, "transfer-record")
	}
	id, err := custodygateway.PlacementID(path, false)
	if err != nil {
		return err
	}
	got, err := privateRead(path, maximumTransferBytes)
	if err != nil || !bytes.HasPrefix(raw, got) || root == r.Destination && !bytes.Equal(raw, got) {
		return errors.Join(ErrHeld, err)
	}
	if !apply || root == r.Destination {
		return nil
	}
	return appendOriginal(path, retainedPrefix{true, got, id}, raw, hooks, "transfer-record")
}

// ReviewTransfer compares original state under all current owners. It creates
// no marker. Transfer repeats this review under the same locks as the rename.
func ReviewTransfer(ctx context.Context, source, target string, did types.Hash, pin wire.Position, bundle TransferBundle, report string, inputs ...string) (TransferReview, error) {
	return runTransfer(ctx, source, target, did, pin, types.Hash{}, bundle, report, inputs, ownerHooks{}, false)
}

func Transfer(ctx context.Context, source, target string, did types.Hash, pin wire.Position, expected types.Hash, bundle TransferBundle, report string, inputs ...string) (TransferReview, error) {
	return transfer(ctx, source, target, did, pin, expected, bundle, report, inputs, ownerHooks{})
}

func transfer(ctx context.Context, source, target string, did types.Hash, pin wire.Position, expected types.Hash, bundle TransferBundle, report string, inputs []string, hooks ownerHooks) (TransferReview, error) {
	if expected.IsZero() {
		return TransferReview{}, ErrPosition
	}
	return runTransfer(ctx, source, target, did, pin, expected, bundle, report, inputs, hooks, true)
}

func runTransfer(ctx context.Context, source, target string, did types.Hash, pin wire.Position, expected types.Hash, bundle TransferBundle, report string, inputs []string, hooks ownerHooks, apply bool) (result TransferReview, returnErr error) {
	req := TransferReview{Source: source, Destination: target, DescriptorID: did, Position: pin, Bundle: bundle}
	if ctx == nil || !pin.Valid() {
		return result, ErrPosition
	}
	current, err := transferLocation(req)
	if err != nil {
		return result, err
	}
	o, err := openConfiguredAt(ctx, current, did, &req)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, o.Close()) }()
	r, runtime, err := prepareTransfer(ctx, o, req, report, inputs)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, runtime.Close()) }()
	id, err := r.ID()
	if err != nil || apply && id != expected {
		return result, errors.Join(ErrPosition, err)
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if apply && current == source && bundle != (TransferBundle{}) {
		if err = runtime.QuiesceForTransfer(); err != nil {
			return result, err
		}
	}
	if err = hooks.reach("transfer-before-record"); err != nil {
		return result, err
	}
	if err = retainTransfer(current, r, hooks, apply); err != nil {
		return result, err
	}
	if !apply {
		return r, nil
	}
	if err = moveTransfer(ctx, o, r, hooks); err != nil {
		return result, err
	}
	if current == source {
		// The original owner flock spans both runtimes. All path-writing
		// engines were drained before moving the complete container.
		if err = runtime.Close(); err != nil {
			return result, err
		}
		dest, err := openConfiguredWithLock(ctx, target, did, &req, o.lock)
		if err != nil {
			return result, err
		}
		defer func() { returnErr = errors.Join(returnErr, dest.Close()) }()
		checked, next, err := prepareTransfer(ctx, dest, req, report, inputs)
		if err != nil {
			return result, err
		}
		defer func() { returnErr = errors.Join(returnErr, next.Close()) }()
		if checked != r {
			return result, ErrPosition
		}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	path := filepath.Join(target, transferCommitted)
	missing, err := absent(path)
	if err != nil {
		return result, err
	}
	if missing {
		err = publishWithHooks(path, nil, hooks, "transfer-committed")
	} else {
		if _, err = privateRead(path, 0); err == nil {
			err = syncDirectory(target)
		}
	}
	if err != nil {
		return result, err
	}
	return r, nil
}

func moveTransfer(ctx context.Context, o *Owner, r TransferReview, h ownerHooks) (returnErr error) {
	src, dst := r.containers()
	a, err := os.Open(filepath.Dir(src))
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, a.Close()) }()
	b, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, b.Close()) }()
	for _, p := range []struct {
		f    *os.File
		path string
		id   types.Hash
	}{{a, filepath.Dir(src), r.SourceParentID}, {b, filepath.Dir(dst), r.DestinationParentID}} {
		pinned, err := nativeDirectoryID(p.path)
		if err != nil || pinned != p.id {
			return errors.Join(ErrPosition, err)
		}
		opened, err := p.f.Stat()
		if err != nil {
			return err
		}
		actual, err := os.Lstat(p.path)
		if err != nil || !os.SameFile(actual, opened) {
			return errors.Join(ErrPosition, err)
		}
	}
	if o.root == r.Source {
		if err = h.reach("transfer-before-rename"); err != nil {
			return err
		}
		if err = o.check(); err != nil {
			return err
		}
		if err := r.checkOwnerFiles(o.root); err != nil {
			return err
		}
		placements, err := o.transferPlacements(transferRuntime)
		if err != nil || placements != r.RuntimePlacementsID {
			return errors.Join(ErrPosition, err)
		}
		if r.Bundle != (TransferBundle{}) {
			if err = checkTransferBundle(ctx, o, src); err != nil {
				return err
			}
		}
		id, _ := r.ID()
		got, err := privateRead(filepath.Join(r.Source, transferPrefix+id.String()), maximumTransferBytes)
		if err != nil {
			return err
		}
		want, err := r.signedBytes(r.Source)
		if err != nil || !bytes.Equal(got, want) {
			return errors.Join(ErrHeld, err)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		pinned, err := custodygateway.PlacementID(src, true)
		if err != nil || pinned != r.ContainerID {
			return errors.Join(ErrPosition, err)
		}
		if err = renameTransfer(int(a.Fd()), filepath.Base(src), int(b.Fd()), filepath.Base(dst)); err != nil {
			return err
		}
		if err = h.reach("transfer-renamed"); err != nil {
			return err
		}
	}
	if err = b.Sync(); err != nil {
		return err
	}
	if err = h.reach("transfer-destination-synced"); err != nil {
		return err
	}
	if err = a.Sync(); err != nil {
		return err
	}
	if err = h.reach("transfer-source-synced"); err != nil {
		return err
	}
	where, err := transferLocation(r)
	if err != nil || where != r.Destination {
		return errors.Join(ErrPosition, err)
	}
	return nil
}
