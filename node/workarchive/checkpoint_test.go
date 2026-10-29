package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestCheckpointRoundTripQuorumAndFile(t *testing.T) {
	statement, keys, policy := checkpointFixture(t)
	checkpoint := signedCheckpoint(t, statement, keys[:2])
	if err := checkpoint.Verify(policy); err != nil {
		t.Fatal(err)
	}
	encoded, err := checkpoint.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckpoint(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := decoded.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("checkpoint encoding is not canonical after round trip")
	}
	statementID, err := statement.ID()
	if err != nil {
		t.Fatal(err)
	}
	const expectedStatementID = "c6c64d117d09ca22d632b58425af4478964b8bed099f2f953deff8575b7d10cf"
	if statementID.String() != expectedStatementID {
		t.Fatalf("statement ID=%s want=%s", statementID, expectedStatementID)
	}

	path := filepath.Join(t.TempDir(), "public", "checkpoint.omwa")
	if err := SaveCheckpointFile(path, checkpoint, policy, statementID); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode=%o want=600", info.Mode().Perm())
	}
	loaded, err := LoadCheckpointFile(path, policy, statementID)
	if err != nil {
		t.Fatal(err)
	}
	loadedBytes, err := loaded.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, loadedBytes) {
		t.Fatal("checkpoint file changed canonical bytes")
	}
	if _, err := LoadCheckpointFile(
		path, policy, types.DomainHash("test/workarchive/wrong-statement"),
	); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("wrong expected statement ID error=%v", err)
	}
}

func TestCheckpointRejectsMutationUntrustedAndInsufficientQuorum(t *testing.T) {
	statement, keys, policy := checkpointFixture(t)
	checkpoint := signedCheckpoint(t, statement, keys[:2])

	mutated := checkpoint
	mutated.Statement.ArchiveManifestID = types.DomainHash("test/workarchive/mutated-manifest")
	if err := mutated.Verify(policy); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("mutated statement error=%v", err)
	}

	requiredThree := policy
	requiredThree.RequiredAttestations = 3
	if err := checkpoint.Verify(requiredThree); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("insufficient quorum error=%v", err)
	}

	untrustedPolicy := policy
	untrustedPolicy.TrustedAttestors = sortedPublicKeys(keys[1:])
	if err := checkpoint.Verify(untrustedPolicy); !errors.Is(err, ErrPolicy) {
		t.Fatalf("untrusted signature error=%v", err)
	}

	invalidPolicy := policy
	invalidPolicy.TrustedAttestors = append(
		[][ed25519.PublicKeySize]byte(nil), invalidPolicy.TrustedAttestors...,
	)
	invalidPolicy.TrustedAttestors[0], invalidPolicy.TrustedAttestors[1] =
		invalidPolicy.TrustedAttestors[1], invalidPolicy.TrustedAttestors[0]
	if err := checkpoint.Verify(invalidPolicy); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("unsorted trust policy error=%v", err)
	}

	duplicate := signedAttestations(t, statement, []ed25519.PrivateKey{keys[0], keys[0]})
	if _, err := NewCheckpoint(statement, duplicate); !errors.Is(err, ErrAttestation) {
		t.Fatalf("duplicate attestor error=%v", err)
	}

	encoded, err := checkpoint.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), encoded...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := DecodeCheckpoint(corrupt); !errors.Is(err, ErrAttestation) {
		t.Fatalf("corrupt signature error=%v", err)
	}
	if _, err := DecodeCheckpoint(append(encoded, 0)); err == nil {
		t.Fatal("checkpoint decoder accepted trailing bytes")
	}
}

func TestStatementRequiresMonotonicPredecessorShape(t *testing.T) {
	statement, _, policy := checkpointFixture(t)
	if err := statement.Validate(policy.Binding); err != nil {
		t.Fatal(err)
	}
	second := statement
	second.Sequence = 2
	if err := second.Validate(policy.Binding); !errors.Is(err, ErrStatement) {
		t.Fatalf("missing predecessor error=%v", err)
	}
	firstWithPredecessor := statement
	firstWithPredecessor.PreviousID = types.DomainHash("test/workarchive/unexpected-predecessor")
	if err := firstWithPredecessor.Validate(policy.Binding); !errors.Is(err, ErrStatement) {
		t.Fatalf("first statement predecessor error=%v", err)
	}
	foreign := policy.Binding
	foreign.NetworkID++
	if err := statement.Validate(foreign); !errors.Is(err, ErrStatement) {
		t.Fatalf("cross-network binding error=%v", err)
	}
	wrongLength := statement
	wrongLength.AncestryNodes++
	if err := wrongLength.Validate(policy.Binding); !errors.Is(err, ErrStatement) {
		t.Fatalf("inconsistent ancestry length error=%v", err)
	}
}

func TestCheckpointAttestorBounds(t *testing.T) {
	statement, _, policy := checkpointFixture(t)
	keys := make([]ed25519.PrivateKey, MaximumAttestors+1)
	for index := range keys {
		keys[index] = ed25519.NewKeyFromSeed(bytes.Repeat(
			[]byte{byte(index + 1)}, ed25519.SeedSize,
		))
	}
	maximum := signedCheckpoint(t, statement, keys[:MaximumAttestors])
	policy.TrustedAttestors = sortedPublicKeys(keys[:MaximumAttestors])
	policy.RequiredAttestations = MaximumAttestors
	if err := maximum.Verify(policy); err != nil {
		t.Fatalf("maximum attestor checkpoint: %v", err)
	}
	encoded, err := maximum.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaximumCheckpointBytes {
		t.Fatalf("maximum checkpoint bytes=%d limit=%d", len(encoded), MaximumCheckpointBytes)
	}
	if _, err := DecodeCheckpoint(encoded); err != nil {
		t.Fatalf("maximum checkpoint decode: %v", err)
	}
	overMaximum := signedAttestations(t, statement, keys)
	if _, err := NewCheckpoint(statement, overMaximum); !errors.Is(err, ErrCheckpoint) {
		t.Fatalf("over-maximum attestor error=%v", err)
	}
	if _, err := Attest(make(ed25519.PrivateKey, ed25519.PrivateKeySize-1), statement); !errors.Is(err, ErrAttestation) {
		t.Fatalf("short private key error=%v", err)
	}
}

func TestCheckpointFileFailureLeavesNoTemporaryArtifact(t *testing.T) {
	statement, keys, policy := checkpointFixture(t)
	checkpoint := signedCheckpoint(t, statement, keys[:2])
	directory := t.TempDir()
	destination := filepath.Join(directory, "occupied")
	if err := os.Mkdir(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveCheckpointFile(
		destination, checkpoint, policy, mustStatementID(t, statement),
	); err == nil {
		t.Fatal("checkpoint save replaced a directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "occupied" || !entries[0].IsDir() {
		t.Fatalf("failed save artifacts=%v", entries)
	}
}

func TestVerifyChainAndSuccessor(t *testing.T) {
	previousStatement, keys, policy := checkpointFixture(t)
	previous := signedCheckpoint(t, previousStatement, keys[:2])
	currentStatement := previousStatement
	currentStatement.Sequence = 2
	currentStatement.PreviousID = mustStatementID(t, previousStatement)
	currentStatement.Anchor = testTip("current-anchor", 6, 9)
	currentStatement.AncestryNodes = 7
	currentStatement.AncestryRoot = types.DomainHash("test/workarchive/current-ancestry")
	currentStatement.ArchiveManifestID = types.DomainHash("test/workarchive/current-manifest")
	current := signedCheckpoint(t, currentStatement, keys[1:])

	chain := &fakeChain{
		baseID: policy.Binding.BaseID,
		tips: map[types.Hash]storage.Tip{
			previousStatement.Anchor.ID: previousStatement.Anchor,
			currentStatement.Anchor.ID:  currentStatement.Anchor,
		},
		commitments: map[types.Hash]ancestryCommitment{
			previousStatement.Anchor.ID: {
				root: previousStatement.AncestryRoot, count: previousStatement.AncestryNodes,
			},
			currentStatement.Anchor.ID: {
				root: currentStatement.AncestryRoot, count: currentStatement.AncestryNodes,
			},
		},
		parents: map[types.Hash]types.Hash{
			currentStatement.Anchor.ID: previousStatement.Anchor.ID,
		},
	}
	if err := VerifyChain(previous, policy, chain); err != nil {
		t.Fatal(err)
	}
	if err := VerifySuccessor(previous, current, policy, chain); err != nil {
		t.Fatal(err)
	}

	wrongRoot := current
	wrongRoot.Statement.AncestryRoot = types.DomainHash("test/workarchive/wrong-root")
	wrongRoot = signedCheckpoint(t, wrongRoot.Statement, keys[1:])
	if err := VerifyChain(wrongRoot, policy, chain); !errors.Is(err, ErrChain) {
		t.Fatalf("wrong ancestry root error=%v", err)
	}

	nonDescendantStatement := currentStatement
	nonDescendantStatement.Anchor = testTip("side-anchor", 7, 10)
	nonDescendantStatement.AncestryRoot = types.DomainHash("test/workarchive/side-ancestry")
	nonDescendantStatement.AncestryNodes = 8
	nonDescendant := signedCheckpoint(t, nonDescendantStatement, keys[1:])
	chain.tips[nonDescendantStatement.Anchor.ID] = nonDescendantStatement.Anchor
	chain.commitments[nonDescendantStatement.Anchor.ID] = ancestryCommitment{
		root: nonDescendantStatement.AncestryRoot, count: nonDescendantStatement.AncestryNodes,
	}
	if err := VerifySuccessor(previous, nonDescendant, policy, chain); !errors.Is(err, ErrChain) {
		t.Fatalf("non-descendant successor error=%v", err)
	}

	delete(chain.commitments, currentStatement.Anchor.ID)
	if err := VerifyChain(current, policy, chain); !errors.Is(err, ErrChain) {
		t.Fatalf("non-selected anchor error=%v", err)
	}
}

func FuzzDecodeStatementNeverPanics(f *testing.F) {
	statement, _, _ := checkpointFixture(f)
	encoded, err := statement.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	statement.Version = StatementVersion1
	statement.RadixActivationHeight = 100
	v1, err := statement.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(v1)
	f.Add([]byte("not-a-statement"))
	f.Fuzz(func(t *testing.T, input []byte) {
		statement, err := DecodeStatement(input)
		if err != nil {
			return
		}
		reencoded, err := statement.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, reencoded) {
			t.Fatal("accepted non-canonical statement")
		}
	})
}

func FuzzDecodeCheckpointNeverPanics(f *testing.F) {
	statement, keys, _ := checkpointFixture(f)
	checkpoint := signedCheckpoint(f, statement, keys[:2])
	encoded, err := checkpoint.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	statement.Version = StatementVersion1
	statement.RadixActivationHeight = 100
	v1 := signedCheckpoint(f, statement, keys[:2])
	v1Bytes, err := v1.CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(v1Bytes)
	f.Add([]byte("not-a-checkpoint"))
	f.Fuzz(func(t *testing.T, input []byte) {
		checkpoint, err := DecodeCheckpoint(input)
		if err != nil {
			return
		}
		reencoded, err := checkpoint.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, reencoded) {
			t.Fatal("accepted non-canonical checkpoint")
		}
	})
}

type ancestryCommitment struct {
	root  types.Hash
	count uint64
}

type fakeChain struct {
	baseID      types.Hash
	tips        map[types.Hash]storage.Tip
	commitments map[types.Hash]ancestryCommitment
	parents     map[types.Hash]types.Hash
}

func (chain *fakeChain) BaseID() (types.Hash, error) {
	return chain.baseID, nil
}

func (chain *fakeChain) TipByID(id types.Hash) (storage.Tip, error) {
	tip, exists := chain.tips[id]
	if !exists {
		return storage.Tip{}, storage.ErrNodeNotFound
	}
	return tip, nil
}

func (chain *fakeChain) SelectedAncestryCommitment(id types.Hash) (types.Hash, uint64, error) {
	commitment, exists := chain.commitments[id]
	if !exists {
		return types.Hash{}, 0, storage.ErrNodeNotFound
	}
	return commitment.root, commitment.count, nil
}

func (chain *fakeChain) IsAncestor(ancestor, descendant types.Hash) (bool, error) {
	for {
		if descendant == ancestor {
			return true, nil
		}
		parent, exists := chain.parents[descendant]
		if !exists {
			return false, nil
		}
		descendant = parent
	}
}

func checkpointFixture(t testing.TB) (Statement, []ed25519.PrivateKey, Policy) {
	t.Helper()
	binding := Binding{
		NetworkID:        909,
		GenesisID:        types.DomainHash("test/workarchive/genesis"),
		ActivationHeight: 1,
		BaseID:           types.DomainHash("test/workarchive/base"),
	}
	statement := Statement{
		Version:           StatementVersion0,
		NetworkID:         binding.NetworkID,
		GenesisID:         binding.GenesisID,
		ActivationHeight:  binding.ActivationHeight,
		BaseID:            binding.BaseID,
		Sequence:          1,
		Anchor:            testTip("previous-anchor", 3, 5),
		AncestryNodes:     4,
		AncestryRoot:      types.DomainHash("test/workarchive/previous-ancestry"),
		ArchiveManifestID: types.DomainHash("test/workarchive/previous-manifest"),
	}
	keys := []ed25519.PrivateKey{
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize)),
	}
	policy := Policy{
		Binding:              binding,
		TrustedAttestors:     sortedPublicKeys(keys),
		RequiredAttestations: 2,
	}
	return statement, keys, policy
}

func testTip(label string, height uint64, cumulativeWork byte) storage.Tip {
	return storage.Tip{
		ID:             types.DomainHash("test/workarchive/tip", []byte(label)),
		Height:         height,
		Timestamp:      1_700_000_000 + height*60,
		Target:         types.DomainHash("test/workarchive/target"),
		StateRoot:      types.DomainHash("test/workarchive/state", []byte(label)),
		CumulativeWork: []byte{cumulativeWork},
	}
}

func signedCheckpoint(
	t testing.TB,
	statement Statement,
	keys []ed25519.PrivateKey,
) Checkpoint {
	t.Helper()
	checkpoint, err := NewCheckpoint(statement, signedAttestations(t, statement, keys))
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func signedAttestations(
	t testing.TB,
	statement Statement,
	keys []ed25519.PrivateKey,
) []Attestation {
	t.Helper()
	result := make([]Attestation, len(keys))
	for index, key := range keys {
		attestation, err := Attest(key, statement)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = attestation
	}
	return result
}

func sortedPublicKeys(keys []ed25519.PrivateKey) [][ed25519.PublicKeySize]byte {
	result := make([][ed25519.PublicKeySize]byte, len(keys))
	for index, key := range keys {
		copy(result[index][:], key.Public().(ed25519.PublicKey))
	}
	sort.Slice(result, func(left, right int) bool {
		return bytes.Compare(result[left][:], result[right][:]) < 0
	})
	return result
}

func mustStatementID(t testing.TB, statement Statement) types.Hash {
	t.Helper()
	id, err := statement.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (chain *fakeChain) ArchiveScheduleCompatible(height uint64) bool {
	return chain != nil && height == 0
}
