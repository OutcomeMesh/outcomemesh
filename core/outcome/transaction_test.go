package outcome

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/guardvm"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestProtocolV0GoldenVector(t *testing.T) {
	t.Parallel()

	transaction, _ := testSignedTransaction(t)
	const canonicalHex = "00000000000701000000000000000000000000000000000000000000000000000000000000000100000000000000000200000000000000000000000000000000000000000000000000000000000000022f4f0bcd1bea178c030f78e4f4da18c7031210a7e50102f4e17a94b7fb339bb30000000000000064000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b2cd65f2baa9c0377a94c8399de6abdba8e3ee561e96d3b4d83a0f9d508f27e42f4f0bcd1bea178c030f78e4f4da18c7031210a7e50102f4e17a94b7fb339bb3000000000000037f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000504010000000000000005090e0f00000000000000050000000000000064000000000000000000000000000000000000000000000000000000000000000903a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b86b79f3f7da7eac02d758c2b6b3e57e866b2de3721ae3bb5ba17ede517f6d5164eda26b343d96ba8de2ff0bbdfacdb763b3eaf9b144980e87913b81e6ddcbad0a"
	wantCanonical, err := hex.DecodeString(canonicalHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := transaction.CanonicalBytes(); string(got) != string(wantCanonical) {
		t.Fatalf("canonical transaction changed:\n got %x\nwant %x", got, wantCanonical)
	}

	id, err := transaction.ID()
	if err != nil {
		t.Fatal(err)
	}
	const wantID = "ba52e389b007e9d38cb3313aceb215d8a3c9d3671b5825567dcf1dc7b6bf4fcd"
	if id.String() != wantID {
		t.Fatalf("transaction ID changed: got %s want %s", id, wantID)
	}
}

func TestSignedTransactionCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	transaction, _ := testSignedTransaction(t)
	encoded := transaction.CanonicalBytes()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoded.VerifySignature(); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}

	id, err := transaction.ID()
	if err != nil {
		t.Fatalf("ID() error = %v", err)
	}
	decodedID, err := decoded.ID()
	if err != nil {
		t.Fatalf("decoded ID() error = %v", err)
	}
	if decodedID != id {
		t.Fatalf("decoded id = %s, want %s", decodedID, id)
	}
	if string(decoded.CanonicalBytes()) != string(encoded) {
		t.Fatal("transaction did not preserve canonical encoding")
	}
}

func TestSignatureCoversOutcome(t *testing.T) {
	t.Parallel()

	transaction, _ := testSignedTransaction(t)
	transaction.Outputs[0].Amount++
	if err := transaction.VerifySignature(); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestOutputIdentifiersAreDeterministicAndDistinct(t *testing.T) {
	t.Parallel()

	transaction, _ := testSignedTransaction(t)
	first, err := transaction.DeriveOutputID(0)
	if err != nil {
		t.Fatalf("DeriveOutputID(0) error = %v", err)
	}
	second, err := transaction.DeriveOutputID(1)
	if err != nil {
		t.Fatalf("DeriveOutputID(1) error = %v", err)
	}
	if first == second {
		t.Fatal("different output indexes produced the same resource ID")
	}
	repeated, err := transaction.DeriveOutputID(0)
	if err != nil || repeated != first {
		t.Fatalf("repeated id = %s, %v; want %s", repeated, err, first)
	}
	if _, err := transaction.DeriveOutputID(2); !errors.Is(err, ErrOutputIndex) {
		t.Fatalf("error = %v, want %v", err, ErrOutputIndex)
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	transaction, _ := testSignedTransaction(t)
	encoded := append(transaction.CanonicalBytes(), 0)
	_, err := Decode(encoded)
	if !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("error = %v, want %v", err, codec.ErrTrailingBytes)
	}
}

func FuzzDecodeTransactionNeverPanics(f *testing.F) {
	transaction, _ := testSignedTransaction(f)
	f.Add(transaction.CanonicalBytes())
	f.Add([]byte{})
	f.Add([]byte{0, 0, 1})

	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Decode(input)
	})
}

type testHelper interface {
	Helper()
	Fatalf(string, ...any)
}

func testSignedTransaction(t testHelper) (Transaction, ed25519.PrivateKey) {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("AddressFromPublicKey() error = %v", err)
	}

	var inputID types.ResourceID
	inputID[31] = 1
	var recipient types.Address
	recipient[31] = 2
	asset := types.NativeAssetID()

	transaction := Transaction{
		Version:   Version0,
		NetworkID: 7,
		Inputs:    []resource.Ref{{ID: inputID, Version: resource.Version0}},
		Outputs: []resource.Output{
			{Owner: recipient, Asset: asset, Amount: 100},
			{Owner: owner, Asset: asset, Amount: 895},
		},
		Guard: guardvm.Program{
			Version: guardvm.Version0,
			Instructions: []guardvm.Instruction{
				{Op: guardvm.OpLoadFee},
				{Op: guardvm.OpPushU64, Value: 5},
				{Op: guardvm.OpLessOrEqualU64},
				{Op: guardvm.OpRequire},
				{Op: guardvm.OpHalt},
			},
		},
		Fee:        5,
		ValidUntil: 100,
	}
	transaction.Nonce[31] = 9
	if err := transaction.Sign(privateKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return transaction, privateKey
}
