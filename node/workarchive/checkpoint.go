// Package workarchive defines independently attested, non-consensus history
// anchors, content-addressed block archives, replica-custody evidence, and the
// explicit local pruning gate for the experimental WorkGraph chain. Restore
// replays ordinary consensus transitions; pruning is disabled by default and
// never changes the cumulative-work comparison among retained branches.
package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	StatementVersion0      uint16 = 0
	CheckpointVersion0     uint16 = 0
	MinimumAttestors              = 2
	MaximumAttestors              = 64
	MaximumStatementBytes         = 512
	MaximumCheckpointBytes        = 8 * 1024
)

const (
	statementIDDomain        = "OMESH/workgraph/archive/statement/id/v0"
	statementSignatureDomain = "OMESH/workgraph/archive/statement/signature/v0"
)

var (
	ErrStatement   = errors.New("invalid WorkGraph archive statement")
	ErrCheckpoint  = errors.New("invalid WorkGraph archive checkpoint")
	ErrAttestation = errors.New("invalid WorkGraph archive attestation")
	ErrPolicy      = errors.New("invalid WorkGraph archive policy")
	ErrChain       = errors.New("WorkGraph archive checkpoint does not match selected history")
)

var (
	statementMagic  = [8]byte{'O', 'M', 'W', 'A', 'R', 'C', 'H', 'S'}
	checkpointMagic = [8]byte{'O', 'M', 'W', 'A', 'R', 'C', 'H', 'C'}
)

// Binding prevents an attested statement from being replayed across a network,
// genesis, activation boundary, or independently rooted WorkChain tree.
type Binding struct {
	NetworkID        uint32
	GenesisID        types.Hash
	ActivationHeight uint64
	BaseID           types.Hash
}

// Statement commits one selected WorkGraph ancestry and the separately
// published archive manifest intended to restore the pruned prefix later.
// Sequence/PreviousID form a monotonic statement chain without requiring a
// mutable signature set to be part of the predecessor identifier.
type Statement struct {
	Version           uint16
	NetworkID         uint32
	GenesisID         types.Hash
	ActivationHeight  uint64
	BaseID            types.Hash
	Sequence          uint64
	PreviousID        types.Hash
	Anchor            storage.Tip
	AncestryNodes     uint64
	AncestryRoot      types.Hash
	ArchiveManifestID types.Hash
}

type Attestation struct {
	PublicKey [ed25519.PublicKeySize]byte
	Signature [ed25519.SignatureSize]byte
}

// Checkpoint carries a canonical sorted subset of independent signatures over
// one statement. Trust and quorum are local operator policy, not consensus.
type Checkpoint struct {
	Version      uint16
	Statement    Statement
	Attestations []Attestation
}

type Policy struct {
	Binding              Binding
	TrustedAttestors     [][ed25519.PublicKeySize]byte
	RequiredAttestations uint16
}

// Chain is the read-only WorkChain surface needed to prove that an attested
// statement names the current selected ancestry. Implementations must not
// mutate selection while answering these calls.
type Chain interface {
	BaseID() (types.Hash, error)
	TipByID(types.Hash) (storage.Tip, error)
	SelectedAncestryCommitment(types.Hash) (types.Hash, uint64, error)
	IsAncestor(types.Hash, types.Hash) (bool, error)
}

func (binding Binding) Validate() error {
	if binding.NetworkID == 0 || binding.GenesisID.IsZero() || binding.ActivationHeight == 0 ||
		binding.BaseID.IsZero() {
		return ErrPolicy
	}
	return nil
}

func (statement Statement) Validate(binding Binding) error {
	if binding.Validate() != nil || statement.validateShape() != nil ||
		statement.NetworkID != binding.NetworkID || statement.GenesisID != binding.GenesisID ||
		statement.ActivationHeight != binding.ActivationHeight || statement.BaseID != binding.BaseID {
		return ErrStatement
	}
	return nil
}

func (statement Statement) CanonicalBytes() ([]byte, error) {
	if err := statement.validateShape(); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(MaximumStatementBytes)
	encoder.Fixed(statementMagic[:])
	encoder.U16(statement.Version)
	encoder.U32(statement.NetworkID)
	encoder.Fixed(statement.GenesisID[:])
	encoder.U64(statement.ActivationHeight)
	encoder.Fixed(statement.BaseID[:])
	encoder.U64(statement.Sequence)
	encoder.Fixed(statement.PreviousID[:])
	encoder.BytesField(statement.Anchor.CanonicalBytes())
	encoder.U64(statement.AncestryNodes)
	encoder.Fixed(statement.AncestryRoot[:])
	encoder.Fixed(statement.ArchiveManifestID[:])
	encoded := encoder.Bytes()
	if len(encoded) > MaximumStatementBytes {
		return nil, ErrStatement
	}
	return encoded, nil
}

func DecodeStatement(input []byte) (Statement, error) {
	if len(input) == 0 || len(input) > MaximumStatementBytes {
		return Statement{}, ErrStatement
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(statementMagic))
	if err != nil || !bytes.Equal(magic, statementMagic[:]) {
		return Statement{}, ErrStatement
	}
	var statement Statement
	if statement.Version, err = decoder.U16(); err != nil {
		return Statement{}, err
	}
	if statement.NetworkID, err = decoder.U32(); err != nil {
		return Statement{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Statement{}, decodeErr
	} else {
		copy(statement.GenesisID[:], value)
	}
	if statement.ActivationHeight, err = decoder.U64(); err != nil {
		return Statement{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Statement{}, decodeErr
	} else {
		copy(statement.BaseID[:], value)
	}
	if statement.Sequence, err = decoder.U64(); err != nil {
		return Statement{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Statement{}, decodeErr
	} else {
		copy(statement.PreviousID[:], value)
	}
	tipBytes, err := decoder.BytesField(256)
	if err != nil {
		return Statement{}, err
	}
	statement.Anchor, err = storage.DecodeTip(tipBytes)
	if err != nil {
		return Statement{}, err
	}
	if statement.AncestryNodes, err = decoder.U64(); err != nil {
		return Statement{}, err
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Statement{}, decodeErr
	} else {
		copy(statement.AncestryRoot[:], value)
	}
	if value, decodeErr := decoder.Fixed(types.HashSize); decodeErr != nil {
		return Statement{}, decodeErr
	} else {
		copy(statement.ArchiveManifestID[:], value)
	}
	if err := decoder.Finish(); err != nil {
		return Statement{}, err
	}
	if err := statement.validateShape(); err != nil {
		return Statement{}, err
	}
	return statement, nil
}

func (statement Statement) ID() (types.Hash, error) {
	encoded, err := statement.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(statementIDDomain, encoded), nil
}

func Attest(privateKey ed25519.PrivateKey, statement Statement) (Attestation, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Attestation{}, ErrAttestation
	}
	message, err := statement.signatureMessage()
	if err != nil {
		return Attestation{}, err
	}
	var result Attestation
	copy(result.PublicKey[:], privateKey.Public().(ed25519.PublicKey))
	copy(result.Signature[:], ed25519.Sign(privateKey, message))
	return result, nil
}

func NewCheckpoint(statement Statement, attestations []Attestation) (Checkpoint, error) {
	if statement.validateShape() != nil || len(attestations) < MinimumAttestors ||
		len(attestations) > MaximumAttestors {
		return Checkpoint{}, ErrCheckpoint
	}
	checkpoint := Checkpoint{
		Version: CheckpointVersion0, Statement: statement,
		Attestations: append([]Attestation(nil), attestations...),
	}
	sort.Slice(checkpoint.Attestations, func(left, right int) bool {
		return bytes.Compare(
			checkpoint.Attestations[left].PublicKey[:], checkpoint.Attestations[right].PublicKey[:],
		) < 0
	})
	if err := checkpoint.validateAttestations(); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func (checkpoint Checkpoint) Verify(policy Policy) error {
	if checkpoint.Version != CheckpointVersion0 || checkpoint.Statement.Validate(policy.Binding) != nil ||
		policy.validate() != nil || checkpoint.validateAttestations() != nil ||
		len(checkpoint.Attestations) < int(policy.RequiredAttestations) {
		return ErrCheckpoint
	}
	trusted := make(map[[ed25519.PublicKeySize]byte]struct{}, len(policy.TrustedAttestors))
	for _, publicKey := range policy.TrustedAttestors {
		trusted[publicKey] = struct{}{}
	}
	for _, attestation := range checkpoint.Attestations {
		if _, exists := trusted[attestation.PublicKey]; !exists {
			return ErrPolicy
		}
	}
	return nil
}

func (checkpoint Checkpoint) CanonicalBytes() ([]byte, error) {
	if checkpoint.Version != CheckpointVersion0 || checkpoint.validateAttestations() != nil {
		return nil, ErrCheckpoint
	}
	statementBytes, err := checkpoint.Statement.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(len(statementBytes) + len(checkpoint.Attestations)*96 + 32)
	encoder.Fixed(checkpointMagic[:])
	encoder.U16(checkpoint.Version)
	encoder.BytesField(statementBytes)
	encoder.Uvarint(uint64(len(checkpoint.Attestations)))
	for _, attestation := range checkpoint.Attestations {
		encoder.Fixed(attestation.PublicKey[:])
		encoder.Fixed(attestation.Signature[:])
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumCheckpointBytes {
		return nil, ErrCheckpoint
	}
	return encoded, nil
}

func DecodeCheckpoint(input []byte) (Checkpoint, error) {
	if len(input) == 0 || len(input) > MaximumCheckpointBytes {
		return Checkpoint{}, ErrCheckpoint
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(checkpointMagic))
	if err != nil || !bytes.Equal(magic, checkpointMagic[:]) {
		return Checkpoint{}, ErrCheckpoint
	}
	version, err := decoder.U16()
	if err != nil || version != CheckpointVersion0 {
		return Checkpoint{}, ErrCheckpoint
	}
	statementBytes, err := decoder.BytesField(MaximumStatementBytes)
	if err != nil {
		return Checkpoint{}, err
	}
	statement, err := DecodeStatement(statementBytes)
	if err != nil {
		return Checkpoint{}, err
	}
	count, err := decoder.ListLength(MaximumAttestors)
	if err != nil || count < MinimumAttestors {
		return Checkpoint{}, ErrCheckpoint
	}
	attestations := make([]Attestation, count)
	for index := range attestations {
		if value, decodeErr := decoder.Fixed(ed25519.PublicKeySize); decodeErr != nil {
			return Checkpoint{}, decodeErr
		} else {
			copy(attestations[index].PublicKey[:], value)
		}
		if value, decodeErr := decoder.Fixed(ed25519.SignatureSize); decodeErr != nil {
			return Checkpoint{}, decodeErr
		} else {
			copy(attestations[index].Signature[:], value)
		}
	}
	if err := decoder.Finish(); err != nil {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{Version: version, Statement: statement, Attestations: attestations}
	if err := checkpoint.validateAttestations(); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

// VerifyChain proves that the statement names an exact node on the currently
// selected ancestry and commits every parent back to the immutable activation
// base. It remains read-only and does not authorize pruning by itself.
func VerifyChain(checkpoint Checkpoint, policy Policy, chain Chain) error {
	if chain == nil || checkpoint.Verify(policy) != nil {
		return ErrCheckpoint
	}
	baseID, err := chain.BaseID()
	if err != nil || baseID != checkpoint.Statement.BaseID {
		return errors.Join(ErrChain, err)
	}
	tip, err := chain.TipByID(checkpoint.Statement.Anchor.ID)
	if err != nil || !storage.EqualTips(tip, checkpoint.Statement.Anchor) {
		return errors.Join(ErrChain, err)
	}
	root, count, err := chain.SelectedAncestryCommitment(checkpoint.Statement.Anchor.ID)
	if err != nil || root != checkpoint.Statement.AncestryRoot ||
		count != checkpoint.Statement.AncestryNodes {
		return errors.Join(ErrChain, err)
	}
	return nil
}

// VerifySuccessor additionally proves monotonic checkpoint publication and
// that the earlier selected anchor remains an ancestor of the later one.
func VerifySuccessor(previous, current Checkpoint, policy Policy, chain Chain) error {
	if VerifyChain(previous, policy, chain) != nil || VerifyChain(current, policy, chain) != nil ||
		previous.Statement.Sequence == ^uint64(0) ||
		current.Statement.Sequence != previous.Statement.Sequence+1 ||
		current.Statement.Anchor.Height <= previous.Statement.Anchor.Height ||
		!storage.MoreWork(current.Statement.Anchor, previous.Statement.Anchor) {
		return ErrChain
	}
	previousID, err := previous.Statement.ID()
	if err != nil || current.Statement.PreviousID != previousID {
		return errors.Join(ErrChain, err)
	}
	ancestor, err := chain.IsAncestor(
		previous.Statement.Anchor.ID, current.Statement.Anchor.ID,
	)
	if err != nil || !ancestor {
		return errors.Join(ErrChain, err)
	}
	return nil
}

func (statement Statement) validateShape() error {
	if statement.Version != StatementVersion0 || statement.NetworkID == 0 ||
		statement.GenesisID.IsZero() || statement.ActivationHeight == 0 || statement.BaseID.IsZero() ||
		statement.Sequence == 0 || statement.Anchor.Validate() != nil ||
		statement.Anchor.Height < statement.ActivationHeight ||
		statement.AncestryRoot.IsZero() || statement.ArchiveManifestID.IsZero() ||
		(statement.Sequence == 1 && !statement.PreviousID.IsZero()) ||
		(statement.Sequence > 1 && statement.PreviousID.IsZero()) {
		return ErrStatement
	}
	distance := statement.Anchor.Height - statement.ActivationHeight
	if distance > ^uint64(0)-2 || statement.AncestryNodes != distance+2 {
		return ErrStatement
	}
	return nil
}

func (statement Statement) signatureMessage() ([]byte, error) {
	encoded, err := statement.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	hash := types.DomainHash(statementSignatureDomain, encoded)
	return hash[:], nil
}

func (checkpoint Checkpoint) validateAttestations() error {
	if checkpoint.Statement.validateShape() != nil || len(checkpoint.Attestations) < MinimumAttestors ||
		len(checkpoint.Attestations) > MaximumAttestors {
		return ErrCheckpoint
	}
	message, err := checkpoint.Statement.signatureMessage()
	if err != nil {
		return err
	}
	for index, attestation := range checkpoint.Attestations {
		if types.Hash(attestation.PublicKey).IsZero() ||
			(index > 0 && bytes.Compare(
				checkpoint.Attestations[index-1].PublicKey[:], attestation.PublicKey[:],
			) >= 0) ||
			!ed25519.Verify(
				ed25519.PublicKey(attestation.PublicKey[:]), message, attestation.Signature[:],
			) {
			return ErrAttestation
		}
	}
	return nil
}

func (policy Policy) validate() error {
	if policy.Binding.Validate() != nil || len(policy.TrustedAttestors) < MinimumAttestors ||
		len(policy.TrustedAttestors) > MaximumAttestors ||
		policy.RequiredAttestations < MinimumAttestors ||
		int(policy.RequiredAttestations) > len(policy.TrustedAttestors) {
		return ErrPolicy
	}
	for index, publicKey := range policy.TrustedAttestors {
		if types.Hash(publicKey).IsZero() ||
			(index > 0 && bytes.Compare(policy.TrustedAttestors[index-1][:], publicKey[:]) >= 0) {
			return ErrPolicy
		}
	}
	return nil
}
