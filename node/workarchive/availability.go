package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const (
	ReplicaReceiptVersion0         uint16 = 0
	AvailabilityBundleVersion0     uint16 = 0
	MinimumReplicas                       = 2
	MaximumReplicas                       = 64
	MaximumReplicaReceiptBytes            = 512
	MaximumAvailabilityBundleBytes        = 64 * 1024
	MaximumReplicaTermSeconds      uint64 = 10 * 365 * 24 * 60 * 60
)

const (
	replicaReceiptSignatureDomain = "OMESH/workgraph/archive/replica-receipt/signature/v0"
	replicaReceiptIDDomain        = "OMESH/workgraph/archive/replica-receipt/id/v0"
	availabilityBundleIDDomain    = "OMESH/workgraph/archive/availability-bundle/id/v0"
)

var (
	ErrReplicaReceipt = errors.New("invalid WorkGraph archive replica receipt")
	ErrReplicaPolicy  = errors.New("invalid WorkGraph archive replica policy")
	ErrAvailability   = errors.New("insufficient WorkGraph archive replica availability")
)

var (
	replicaReceiptMagic     = [8]byte{'O', 'M', 'W', 'A', 'R', 'R', 'C', 'P'}
	availabilityBundleMagic = [8]byte{'O', 'M', 'W', 'A', 'R', 'A', 'V', 'L'}
)

// ReplicaReceipt is a time-bounded operator claim that one exact archive was
// fully replayed and is assigned to one replica location. LocationID is an
// opaque public commitment to a failure domain; policy still has to decide
// whether the trusted replica keys are independently operated.
type ReplicaReceipt struct {
	Version          uint16
	Binding          Binding
	StatementID      types.Hash
	ManifestID       types.Hash
	AnchorID         types.Hash
	LocationID       types.Hash
	StoredAt         uint64
	RetainUntil      uint64
	ReplicaPublicKey [ed25519.PublicKeySize]byte
	Signature        [ed25519.SignatureSize]byte
}

type ReplicaPolicy struct {
	TrustedReplicas      [][ed25519.PublicKeySize]byte
	RequiredReplicas     uint16
	MaximumReceiptAge    uint64
	MinimumRemainingTerm uint64
}

// AvailabilityBundle is the canonical sorted receipt set used as the durable
// identifier in a local canonical-floor transition.
type AvailabilityBundle struct {
	Version     uint16
	StatementID types.Hash
	ManifestID  types.Hash
	AnchorID    types.Hash
	Receipts    []ReplicaReceipt
}

type Replica struct {
	Directory string
	Receipt   ReplicaReceipt
}

type CanonicalPruneResult struct {
	Bundle AvailabilityBundle
	Report workchain.CanonicalPruneReport
}

// CreateReplicaReceipt performs a complete consensus replay of directory
// before signing its exact statement/manifest assignment.
func CreateReplicaReceipt(
	directory string,
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
	privateKey ed25519.PrivateKey,
	locationID types.Hash,
	storedAt uint64,
	retainUntil uint64,
) (ReplicaReceipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize || locationID.IsZero() || storedAt == 0 ||
		retainUntil <= storedAt || retainUntil-storedAt > MaximumReplicaTermSeconds {
		return ReplicaReceipt{}, ErrReplicaReceipt
	}
	manifest, err := VerifyArchiveDirectory(
		directory, checkpoint, checkpointPolicy, base, parameters, limits,
	)
	if err != nil {
		return ReplicaReceipt{}, err
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return ReplicaReceipt{}, err
	}
	statementID, err := checkpoint.Statement.ID()
	if err != nil {
		return ReplicaReceipt{}, err
	}
	receipt := ReplicaReceipt{
		Version: ReplicaReceiptVersion0, Binding: manifest.Binding,
		StatementID: statementID, ManifestID: manifestID, AnchorID: manifest.Anchor.ID,
		LocationID: locationID, StoredAt: storedAt, RetainUntil: retainUntil,
	}
	copy(receipt.ReplicaPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	message, err := receipt.signatureMessage()
	if err != nil {
		return ReplicaReceipt{}, err
	}
	copy(receipt.Signature[:], ed25519.Sign(privateKey, message))
	return receipt, nil
}

func (receipt ReplicaReceipt) CanonicalBytes() ([]byte, error) {
	if receipt.verifySignature() != nil {
		return nil, ErrReplicaReceipt
	}
	unsigned, err := receipt.unsignedBytes()
	if err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(len(unsigned) + ed25519.SignatureSize)
	encoder.Fixed(unsigned)
	encoder.Fixed(receipt.Signature[:])
	encoded := encoder.Bytes()
	if len(encoded) > MaximumReplicaReceiptBytes {
		return nil, ErrReplicaReceipt
	}
	return encoded, nil
}

func DecodeReplicaReceipt(input []byte) (ReplicaReceipt, error) {
	if len(input) == 0 || len(input) > MaximumReplicaReceiptBytes {
		return ReplicaReceipt{}, ErrReplicaReceipt
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(replicaReceiptMagic))
	if err != nil || !bytes.Equal(magic, replicaReceiptMagic[:]) {
		return ReplicaReceipt{}, ErrReplicaReceipt
	}
	var receipt ReplicaReceipt
	if receipt.Version, err = decoder.U16(); err != nil {
		return ReplicaReceipt{}, err
	}
	if receipt.Binding, err = decodeBinding(decoder); err != nil {
		return ReplicaReceipt{}, err
	}
	for _, destination := range []*types.Hash{
		&receipt.StatementID, &receipt.ManifestID, &receipt.AnchorID, &receipt.LocationID,
	} {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return ReplicaReceipt{}, decodeErr
		}
		copy(destination[:], value)
	}
	if receipt.StoredAt, err = decoder.U64(); err != nil {
		return ReplicaReceipt{}, err
	}
	if receipt.RetainUntil, err = decoder.U64(); err != nil {
		return ReplicaReceipt{}, err
	}
	if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
		return ReplicaReceipt{}, decodeErr
	} else {
		copy(receipt.ReplicaPublicKey[:], value)
	}
	if value, decodeErr := decoder.Fixed(ed25519.SignatureSize); decodeErr != nil {
		return ReplicaReceipt{}, decodeErr
	} else {
		copy(receipt.Signature[:], value)
	}
	if err := decoder.Finish(); err != nil || receipt.verifySignature() != nil {
		return ReplicaReceipt{}, ErrReplicaReceipt
	}
	return receipt, nil
}

func (receipt ReplicaReceipt) ID() (types.Hash, error) {
	encoded, err := receipt.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(replicaReceiptIDDomain, encoded), nil
}

func (bundle AvailabilityBundle) CanonicalBytes() ([]byte, error) {
	if bundle.validateShape() != nil {
		return nil, ErrAvailability
	}
	encoder := codec.NewEncoder(128 + len(bundle.Receipts)*MaximumReplicaReceiptBytes)
	encoder.Fixed(availabilityBundleMagic[:])
	encoder.U16(bundle.Version)
	encoder.Fixed(bundle.StatementID[:])
	encoder.Fixed(bundle.ManifestID[:])
	encoder.Fixed(bundle.AnchorID[:])
	encoder.Uvarint(uint64(len(bundle.Receipts)))
	for _, receipt := range bundle.Receipts {
		encoded, err := receipt.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		encoder.BytesField(encoded)
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumAvailabilityBundleBytes {
		return nil, ErrAvailability
	}
	return encoded, nil
}

func DecodeAvailabilityBundle(input []byte) (AvailabilityBundle, error) {
	if len(input) == 0 || len(input) > MaximumAvailabilityBundleBytes {
		return AvailabilityBundle{}, ErrAvailability
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(availabilityBundleMagic))
	if err != nil || !bytes.Equal(magic, availabilityBundleMagic[:]) {
		return AvailabilityBundle{}, ErrAvailability
	}
	var bundle AvailabilityBundle
	if bundle.Version, err = decoder.U16(); err != nil {
		return AvailabilityBundle{}, err
	}
	for _, destination := range []*types.Hash{&bundle.StatementID, &bundle.ManifestID, &bundle.AnchorID} {
		value, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return AvailabilityBundle{}, decodeErr
		}
		copy(destination[:], value)
	}
	count, err := decoder.ListLength(MaximumReplicas)
	if err != nil || count < MinimumReplicas {
		return AvailabilityBundle{}, ErrAvailability
	}
	bundle.Receipts = make([]ReplicaReceipt, count)
	for index := range bundle.Receipts {
		encoded, decodeErr := decoder.BytesField(MaximumReplicaReceiptBytes)
		if decodeErr != nil {
			return AvailabilityBundle{}, decodeErr
		}
		bundle.Receipts[index], err = DecodeReplicaReceipt(encoded)
		if err != nil {
			return AvailabilityBundle{}, err
		}
	}
	if err := decoder.Finish(); err != nil || bundle.validateShape() != nil {
		return AvailabilityBundle{}, ErrAvailability
	}
	return bundle, nil
}

func (bundle AvailabilityBundle) ID() (types.Hash, error) {
	encoded, err := bundle.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(availabilityBundleIDDomain, encoded), nil
}

func (bundle AvailabilityBundle) Verify(
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	replicaPolicy ReplicaPolicy,
	now uint64,
) error {
	if checkpoint.Verify(checkpointPolicy) != nil || replicaPolicy.validate() != nil ||
		bundle.validateShape() != nil || now == 0 ||
		len(bundle.Receipts) < int(replicaPolicy.RequiredReplicas) {
		return ErrAvailability
	}
	statementID, err := checkpoint.Statement.ID()
	if err != nil || bundle.StatementID != statementID ||
		bundle.ManifestID != checkpoint.Statement.ArchiveManifestID ||
		bundle.AnchorID != checkpoint.Statement.Anchor.ID {
		return ErrAvailability
	}
	trusted := make(map[[ed25519.PublicKeySize]byte]struct{}, len(replicaPolicy.TrustedReplicas))
	for _, key := range replicaPolicy.TrustedReplicas {
		trusted[key] = struct{}{}
	}
	locations := make(map[types.Hash]struct{}, len(bundle.Receipts))
	for _, receipt := range bundle.Receipts {
		if _, exists := trusted[receipt.ReplicaPublicKey]; !exists ||
			receipt.Binding != checkpointPolicy.Binding || receipt.StatementID != statementID ||
			receipt.ManifestID != bundle.ManifestID || receipt.AnchorID != bundle.AnchorID ||
			receipt.StoredAt > now || now-receipt.StoredAt > replicaPolicy.MaximumReceiptAge ||
			receipt.RetainUntil <= now ||
			receipt.RetainUntil-now < replicaPolicy.MinimumRemainingTerm || receipt.verifySignature() != nil {
			return ErrAvailability
		}
		if _, exists := locations[receipt.LocationID]; exists {
			return ErrAvailability
		}
		locations[receipt.LocationID] = struct{}{}
	}
	return nil
}

// VerifyReplicaSet replays every distinct directory again at authorization
// time. A receipt alone is never treated as proof that bytes still exist.
func VerifyReplicaSet(
	replicas []Replica,
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	replicaPolicy ReplicaPolicy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
	now uint64,
) (AvailabilityBundle, error) {
	if len(replicas) < MinimumReplicas || len(replicas) > MaximumReplicas {
		return AvailabilityBundle{}, ErrAvailability
	}
	seenPaths := make(map[string]os.FileInfo, len(replicas))
	receipts := make([]ReplicaReceipt, len(replicas))
	for index, replica := range replicas {
		absolute, err := filepath.Abs(replica.Directory)
		if err != nil {
			return AvailabilityBundle{}, err
		}
		absolute = filepath.Clean(absolute)
		info, err := os.Lstat(absolute)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return AvailabilityBundle{}, ErrAvailability
		}
		for path, previous := range seenPaths {
			if path == absolute || os.SameFile(previous, info) {
				return AvailabilityBundle{}, ErrAvailability
			}
		}
		seenPaths[absolute] = info
		manifest, err := VerifyArchiveDirectory(
			absolute, checkpoint, checkpointPolicy, base, parameters, limits,
		)
		if err != nil {
			return AvailabilityBundle{}, err
		}
		manifestID, err := manifest.ID()
		if err != nil || manifestID != replica.Receipt.ManifestID {
			return AvailabilityBundle{}, ErrAvailability
		}
		receipts[index] = replica.Receipt
	}
	sort.Slice(receipts, func(left, right int) bool {
		return bytes.Compare(receipts[left].ReplicaPublicKey[:], receipts[right].ReplicaPublicKey[:]) < 0
	})
	statementID, err := checkpoint.Statement.ID()
	if err != nil {
		return AvailabilityBundle{}, err
	}
	bundle := AvailabilityBundle{
		Version: AvailabilityBundleVersion0, StatementID: statementID,
		ManifestID: checkpoint.Statement.ArchiveManifestID,
		AnchorID:   checkpoint.Statement.Anchor.ID, Receipts: receipts,
	}
	if err := bundle.Verify(checkpoint, checkpointPolicy, replicaPolicy, now); err != nil {
		return AvailabilityBundle{}, err
	}
	return bundle, nil
}

// PruneCanonicalPrefix is the policy-enforcing entry point for destructive
// canonical maintenance. It rechecks selected ancestry and every replica
// immediately before invoking WorkChain's single-batch transition.
func PruneCanonicalPrefix(
	chain *workchain.Store,
	replicas []Replica,
	availabilityPath string,
	checkpoint Checkpoint,
	checkpointPolicy Policy,
	replicaPolicy ReplicaPolicy,
	base workchain.Base,
	parameters workblock.Parameters,
	limits Limits,
	now uint64,
) (CanonicalPruneResult, error) {
	if chain == nil || availabilityPath == "" || VerifyChain(checkpoint, checkpointPolicy, chain) != nil {
		return CanonicalPruneResult{}, ErrChain
	}
	evidenceResolved, err := resolvedArchivePath(availabilityPath)
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	for _, replica := range replicas {
		replicaResolved, pathErr := resolvedArchivePath(replica.Directory)
		if pathErr != nil || pathContains(replicaResolved, evidenceResolved) {
			return CanonicalPruneResult{}, ErrAvailability
		}
	}
	bundle, err := VerifyReplicaSet(
		replicas, checkpoint, checkpointPolicy, replicaPolicy, base, parameters, limits, now,
	)
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	statementID, err := checkpoint.Statement.ID()
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	bundleID, err := bundle.ID()
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	if err := SaveAvailabilityBundleFile(
		availabilityPath, bundle, checkpoint, checkpointPolicy, replicaPolicy, now, bundleID,
	); err != nil {
		return CanonicalPruneResult{}, err
	}
	retainUntil := bundle.Receipts[0].RetainUntil
	for _, receipt := range bundle.Receipts[1:] {
		if receipt.RetainUntil < retainUntil {
			retainUntil = receipt.RetainUntil
		}
	}
	report, err := chain.PruneCanonicalPrefix(workchain.CanonicalFloor{
		Pruned: true, BaseID: checkpoint.Statement.BaseID, Anchor: checkpoint.Statement.Anchor,
		AncestryNodes: checkpoint.Statement.AncestryNodes,
		AncestryRoot:  checkpoint.Statement.AncestryRoot,
		StatementID:   statementID, ManifestID: checkpoint.Statement.ArchiveManifestID,
		AvailabilityID: bundleID, VerifiedAt: now, RetainUntil: retainUntil,
	})
	if err != nil {
		return CanonicalPruneResult{}, err
	}
	return CanonicalPruneResult{Bundle: bundle, Report: report}, nil
}

func pathContains(directory, path string) bool {
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return true
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
}

// resolvedArchivePath resolves every existing path component while preserving
// a possibly absent suffix. This prevents an evidence path whose parent is a
// symlink from writing into a replica after that replica passed replay.
func resolvedArchivePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	cursor := filepath.Clean(absolute)
	suffix := make([]string, 0)
	for {
		if _, statErr := os.Lstat(cursor); statErr == nil {
			resolved, resolveErr := filepath.EvalSymlinks(cursor)
			if resolveErr != nil {
				return "", resolveErr
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", ErrAvailability
		}
		suffix = append(suffix, filepath.Base(cursor))
		cursor = parent
	}
}

func (receipt ReplicaReceipt) unsignedBytes() ([]byte, error) {
	if receipt.verifyShape() != nil {
		return nil, ErrReplicaReceipt
	}
	encoder := codec.NewEncoder(MaximumReplicaReceiptBytes)
	encoder.Fixed(replicaReceiptMagic[:])
	encoder.U16(receipt.Version)
	encodeBinding(encoder, receipt.Binding)
	encoder.Fixed(receipt.StatementID[:])
	encoder.Fixed(receipt.ManifestID[:])
	encoder.Fixed(receipt.AnchorID[:])
	encoder.Fixed(receipt.LocationID[:])
	encoder.U64(receipt.StoredAt)
	encoder.U64(receipt.RetainUntil)
	encoder.Fixed(receipt.ReplicaPublicKey[:])
	return encoder.Bytes(), nil
}

func (receipt ReplicaReceipt) signatureMessage() ([]byte, error) {
	unsigned, err := receipt.unsignedBytes()
	if err != nil {
		return nil, err
	}
	hash := types.DomainHash(replicaReceiptSignatureDomain, unsigned)
	return hash[:], nil
}

func (receipt ReplicaReceipt) verifyShape() error {
	if receipt.Version != ReplicaReceiptVersion0 || receipt.Binding.Validate() != nil ||
		receipt.StatementID.IsZero() || receipt.ManifestID.IsZero() || receipt.AnchorID.IsZero() ||
		receipt.LocationID.IsZero() || receipt.StoredAt == 0 || receipt.RetainUntil <= receipt.StoredAt ||
		receipt.RetainUntil-receipt.StoredAt > MaximumReplicaTermSeconds ||
		types.Hash(receipt.ReplicaPublicKey).IsZero() {
		return ErrReplicaReceipt
	}
	return nil
}

func (receipt ReplicaReceipt) verifySignature() error {
	message, err := receipt.signatureMessage()
	if err != nil || !ed25519.Verify(
		ed25519.PublicKey(receipt.ReplicaPublicKey[:]), message, receipt.Signature[:],
	) {
		return ErrReplicaReceipt
	}
	return nil
}

func (bundle AvailabilityBundle) validateShape() error {
	if bundle.Version != AvailabilityBundleVersion0 || bundle.StatementID.IsZero() ||
		bundle.ManifestID.IsZero() || bundle.AnchorID.IsZero() ||
		len(bundle.Receipts) < MinimumReplicas || len(bundle.Receipts) > MaximumReplicas {
		return ErrAvailability
	}
	for index, receipt := range bundle.Receipts {
		if receipt.verifySignature() != nil || receipt.StatementID != bundle.StatementID ||
			receipt.ManifestID != bundle.ManifestID || receipt.AnchorID != bundle.AnchorID ||
			(index > 0 && bytes.Compare(
				bundle.Receipts[index-1].ReplicaPublicKey[:], receipt.ReplicaPublicKey[:],
			) >= 0) {
			return ErrAvailability
		}
	}
	return nil
}

func (policy ReplicaPolicy) validate() error {
	if len(policy.TrustedReplicas) < MinimumReplicas || len(policy.TrustedReplicas) > MaximumReplicas ||
		policy.RequiredReplicas < MinimumReplicas ||
		int(policy.RequiredReplicas) > len(policy.TrustedReplicas) ||
		policy.MaximumReceiptAge == 0 || policy.MaximumReceiptAge > MaximumReplicaTermSeconds ||
		policy.MinimumRemainingTerm == 0 || policy.MinimumRemainingTerm > MaximumReplicaTermSeconds {
		return ErrReplicaPolicy
	}
	for index, key := range policy.TrustedReplicas {
		if types.Hash(key).IsZero() || (index > 0 && bytes.Compare(policy.TrustedReplicas[index-1][:], key[:]) >= 0) {
			return ErrReplicaPolicy
		}
	}
	return nil
}
