package workarchive

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

var ErrRadixMigration = errors.New("archive radix migration requires the exact retained prefix and original attestor policy")

// PrepareRadixArchiveMigration replays the original v1 archive and proposes a
// schedule-bound successor at the SAME anchor. Existing signatures, receipts,
// retention terms and custody journals remain attached to the original IDs.
// This statement grants no new availability credit and does not retire them.
func PrepareRadixArchiveMigration(path string, previous Checkpoint, policy Policy, base workchain.Base,
	parameters workblock.Parameters, height uint64, limits Limits) (Manifest, Statement, error) {
	if parameters.RadixActivationHeight != 0 || policy.Binding.RadixActivationHeight != 0 ||
		height == 0 || height <= previous.Statement.Anchor.Height || previous.Statement.Sequence == ^uint64(0) {
		return Manifest{}, Statement{}, ErrRadixMigration
	}
	manifest, err := VerifyArchiveDirectory(path, previous, policy, base, parameters, limits)
	if err != nil {
		return Manifest{}, Statement{}, err
	}
	if manifest.Version != ManifestVersion1 {
		return Manifest{}, Statement{}, ErrRadixMigration
	}
	manifest.Version = ManifestVersion2
	manifest.Binding.RadixActivationHeight = height
	previousID, err := previous.Statement.ID()
	if err != nil {
		return Manifest{}, Statement{}, err
	}
	statement, err := manifest.ArchiveStatement(previous.Statement.Sequence+1, previousID)
	return manifest, statement, err
}

// VerifyRadixArchiveTransition verifies explicit continuity between the old and
// new envelopes. It deliberately differs from VerifySuccessor: no extra blocks
// or work may be introduced in a representation migration. The original trust
// set and quorum are reused; callers cannot substitute a weaker new policy.
func VerifyRadixArchiveTransition(previousManifest, currentManifest Manifest, previous, current Checkpoint, policy Policy) error {
	if previousManifest.Version != ManifestVersion1 || currentManifest.Version != ManifestVersion2 ||
		previousManifest.VerifyStatement(previous.Statement) != nil || currentManifest.VerifyStatement(current.Statement) != nil ||
		previous.Verify(policy) != nil || current.Statement.RadixActivationHeight <= previous.Statement.Anchor.Height ||
		previous.Statement.Sequence == ^uint64(0) || current.Statement.Sequence != previous.Statement.Sequence+1 {
		return ErrRadixMigration
	}
	previousID, err := previous.Statement.ID()
	if err != nil || current.Statement.PreviousID != previousID {
		return errors.Join(ErrRadixMigration, err)
	}
	nextPolicy := policy
	nextPolicy.Binding.RadixActivationHeight = current.Statement.RadixActivationHeight
	if current.Verify(nextPolicy) != nil {
		return ErrRadixMigration
	}
	expected := previousManifest
	expected.Version = ManifestVersion2
	expected.Binding.RadixActivationHeight = current.Statement.RadixActivationHeight
	a, err := expected.CanonicalBytes()
	if err != nil {
		return err
	}
	b, err := currentManifest.CanonicalBytes()
	if err != nil || !bytes.Equal(a, b) {
		return errors.Join(ErrRadixMigration, err)
	}
	return nil
}

// MigrateRadixArchiveDirectory publishes a separate successor only after a
// quorum signs the exact proposal. Chunk boundaries, bytes and content IDs are
// retained. The source is never changed; an existing destination is refused.
// Callers must retain BOTH checkpoints and all original custody evidence.
func MigrateRadixArchiveDirectory(source, destination string, previous, current Checkpoint, policy Policy,
	base workchain.Base, parameters workblock.Parameters, limits Limits) (Manifest, types.Hash, error) {
	manifest, proposal, err := PrepareRadixArchiveMigration(source, previous, policy, base, parameters,
		current.Statement.RadixActivationHeight, limits)
	if err != nil {
		return Manifest{}, types.Hash{}, err
	}
	want, _ := proposal.CanonicalBytes()
	got, err := current.Statement.CanonicalBytes()
	if err != nil || !bytes.Equal(want, got) {
		return Manifest{}, types.Hash{}, errors.Join(ErrRadixMigration, err)
	}
	original := manifest
	original.Version = ManifestVersion1
	original.Binding.RadixActivationHeight = 0
	if err := VerifyRadixArchiveTransition(original, manifest, previous, current, policy); err != nil {
		return Manifest{}, types.Hash{}, err
	}
	src, err := resolvedArchivePath(source)
	if err != nil {
		return Manifest{}, types.Hash{}, err
	}
	dst, err := resolvedArchivePath(destination)
	if err != nil || pathContains(src, dst) {
		return Manifest{}, types.Hash{}, errors.Join(ErrRadixMigration, err)
	}
	options := ExportOptions{Version: ManifestVersion2, BlocksPerChunk: MaximumChunkBlocks, Limits: limits}
	plan := archivePlan{Anchor: manifest.Anchor, AncestryNodes: manifest.AncestryNodes,
		AncestryRoot: manifest.AncestryRoot, BlockCount: manifest.BlockCount}
	stream := func(yield func(workblock.Block, bool) error) error {
		return streamArchiveBlocks(source, original, limits, yield)
	}
	return publishArchiveDirectory(destination, manifest.Binding, plan, options, stream, nil, nil)
}
