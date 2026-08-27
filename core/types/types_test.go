package types

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

func TestDomainHashIsSeparated(t *testing.T) {
	t.Parallel()

	payload := []byte("same payload")
	left := DomainHash("OMESH/test/left", payload)
	right := DomainHash("OMESH/test/right", payload)
	if left == right {
		t.Fatal("different domains produced the same hash")
	}
}

func TestAddressFromPublicKeyVector(t *testing.T) {
	t.Parallel()

	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	address, err := AddressFromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("AddressFromPublicKey() error = %v", err)
	}

	const expected = "a367674394b42ec65a6d3d28304a126142007a5add9ef688793d192d5df5b97c"
	if address.String() != expected {
		t.Fatalf("address = %s, want %s", address, expected)
	}

	decoded, err := hex.DecodeString(address.String())
	if err != nil || len(decoded) != AddressSize {
		t.Fatalf("invalid address string: decoded=%x err=%v", decoded, err)
	}
}

func TestAddressRejectsInvalidPublicKey(t *testing.T) {
	t.Parallel()

	_, err := AddressFromPublicKey(ed25519.PublicKey{1, 2, 3})
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidPublicKey)
	}
}

func TestAmountArithmetic(t *testing.T) {
	t.Parallel()

	if got, err := AddAmount(20, 22); err != nil || got != 42 {
		t.Fatalf("AddAmount() = %d, %v", got, err)
	}
	if _, err := AddAmount(math.MaxUint64, 1); !errors.Is(err, ErrAmountOverflow) {
		t.Fatalf("overflow error = %v", err)
	}
	if got, err := SubAmount(50, 8); err != nil || got != 42 {
		t.Fatalf("SubAmount() = %d, %v", got, err)
	}
	if _, err := SubAmount(0, 1); !errors.Is(err, ErrAmountUnderflow) {
		t.Fatalf("underflow error = %v", err)
	}
}
