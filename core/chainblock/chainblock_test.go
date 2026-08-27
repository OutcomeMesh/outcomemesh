package chainblock

import (
	"bytes"
	"errors"
	"testing"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func TestBlockAndHeaderUnionsPreserveCanonicalEncodings(t *testing.T) {
	t.Parallel()

	legacySource := testLegacyBlock(t)
	workSource := testWorkBlock(t)
	legacy, err := Legacy(legacySource)
	if err != nil {
		t.Fatal(err)
	}
	work, err := Work(workSource)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []Block{legacy, work} {
		decoded, err := DecodeAny(candidate.CanonicalBytes())
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Version() != candidate.Version() || decoded.Height() != candidate.Height() ||
			decoded.ParentID() != candidate.ParentID() || !bytes.Equal(decoded.CanonicalBytes(), candidate.CanonicalBytes()) {
			t.Fatal("block union changed its version-specific representation")
		}
		header := candidate.Header()
		decodedHeader, err := DecodeHeaderAny(header.CanonicalBytes())
		if err != nil {
			t.Fatal(err)
		}
		if decodedHeader.Version() != header.Version() || decodedHeader.Height() != header.Height() ||
			decodedHeader.ParentID() != header.ParentID() || !bytes.Equal(decodedHeader.CanonicalBytes(), header.CanonicalBytes()) {
			t.Fatal("header union changed its version-specific representation")
		}
	}

	before := work.CanonicalBytes()
	workSource.Header.Seal.Parents[0] = types.DomainHash("test/chainblock/mutated-parent")
	if !bytes.Equal(before, work.CanonicalBytes()) {
		t.Fatal("union retained a caller-owned WorkSeal parent slice")
	}
}

func TestActivationBoundaryAppliesToBothUnions(t *testing.T) {
	t.Parallel()

	legacy, err := Legacy(testLegacyBlock(t))
	if err != nil {
		t.Fatal(err)
	}
	work, err := Work(testWorkBlock(t))
	if err != nil {
		t.Fatal(err)
	}
	activationHeight := work.Height()
	if legacy.Height()+1 != activationHeight {
		t.Fatal("invalid test boundary")
	}
	for _, validate := range []func(uint64) error{legacy.Validate, legacy.Header().Validate} {
		if err := validate(activationHeight); err != nil {
			t.Fatal(err)
		}
		if err := validate(legacy.Height()); !errors.Is(err, ErrBoundary) {
			t.Fatalf("legacy boundary error = %v", err)
		}
	}
	for _, validate := range []func(uint64) error{work.Validate, work.Header().Validate} {
		if err := validate(activationHeight); err != nil {
			t.Fatal(err)
		}
		if err := validate(activationHeight + 1); !errors.Is(err, ErrBoundary) {
			t.Fatalf("work boundary error = %v", err)
		}
	}
	if _, err := Decode(legacy.CanonicalBytes(), legacy.Height()); !errors.Is(err, ErrBoundary) {
		t.Fatalf("decoded legacy boundary error = %v", err)
	}
	if _, err := DecodeHeader(work.Header().CanonicalBytes(), activationHeight+1); !errors.Is(err, ErrBoundary) {
		t.Fatalf("decoded work header boundary error = %v", err)
	}
}

func TestDecodersRejectUnknownVersionsAndTrailingBytes(t *testing.T) {
	t.Parallel()

	if _, err := DecodeAny([]byte{0xff, 0xff}); !errors.Is(err, ErrEncoding) {
		t.Fatalf("unknown block version error = %v", err)
	}
	if _, err := DecodeHeaderAny([]byte{0xff, 0xff}); !errors.Is(err, ErrEncoding) {
		t.Fatalf("unknown header version error = %v", err)
	}
	legacy := testLegacyBlock(t)
	if _, err := DecodeAny(append(legacy.CanonicalBytes(), 0)); err == nil {
		t.Fatal("block decoder accepted trailing bytes")
	}
	if _, err := DecodeHeaderAny(append(legacy.Header.CanonicalBytes(), 0)); err == nil {
		t.Fatal("header decoder accepted trailing bytes")
	}
}

func FuzzDecodeAnyNeverPanics(f *testing.F) {
	legacy, err := Legacy(testLegacyBlock(f))
	if err != nil {
		f.Fatal(err)
	}
	work, err := Work(testWorkBlock(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(legacy.CanonicalBytes())
	f.Add(work.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		if decoded, err := DecodeAny(input); err == nil {
			if err := decoded.ValidateBasic(); err != nil || !bytes.Equal(input, decoded.CanonicalBytes()) {
				t.Fatal("accepted block was not canonical")
			}
		}
		if decoded, err := DecodeHeaderAny(input); err == nil {
			if err := decoded.ValidateBasic(); err != nil || !bytes.Equal(input, decoded.CanonicalBytes()) {
				t.Fatal("accepted header was not canonical")
			}
		}
	})
}

func testLegacyBlock(t testing.TB) legacyblock.Block {
	t.Helper()
	txRoot, err := legacyblock.TransactionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	result := legacyblock.Block{Header: legacyblock.Header{
		Version: legacyblock.Version0, NetworkID: 37, Height: 4,
		Parent: types.DomainHash("test/chainblock/legacy-parent"), Timestamp: 1_700_000_000,
		Target: target, TxRoot: txRoot,
		ReceiptRoot: types.DomainHash("test/chainblock/legacy-receipts"),
		StateRoot:   types.DomainHash("test/chainblock/legacy-state"),
		Miner:       types.Address(types.DomainHash("test/chainblock/legacy-miner")),
	}}
	if err := result.ValidateBasic(); err != nil {
		t.Fatal(err)
	}
	return result
}

func testWorkBlock(t testing.TB) workblock.Block {
	t.Helper()
	txRoot, err := legacyblock.TransactionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiptRoot, err := legacyblock.ReceiptRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := workgraph.NewFeeQueue(3)
	if err != nil {
		t.Fatal(err)
	}
	queueRoot, err := queue.Root()
	if err != nil {
		t.Fatal(err)
	}
	previousRoot := workgraph.EmptyRoot()
	payloadRoot, err := workgraph.PayloadCommitmentV1(
		txRoot, receiptRoot, state.Empty().Root(), previousRoot, queueRoot, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	inclusionRoot, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	result := workblock.Block{Header: workblock.Header{
		Version: workblock.Version1,
		Seal: workgraph.Share{
			Version: workgraph.Version0, NetworkID: 37, Height: 5,
			AnchorParent: types.DomainHash("test/chainblock/work-parent"), Timestamp: 1_700_000_060,
			Target: target, PayloadRoot: payloadRoot,
			Miner: types.Address(types.DomainHash("test/chainblock/work-miner")), InclusionRoot: inclusionRoot,
			Parents: []types.Hash{types.DomainHash("test/chainblock/work-share-parent")},
		},
		TxRoot: txRoot, ReceiptRoot: receiptRoot, StateRoot: state.Empty().Root(),
		PreviousWorkRoot: previousRoot, FeeQueueRoot: queueRoot,
	}}
	if err := result.ValidateBasic(); err != nil {
		t.Fatal(err)
	}
	return result
}
