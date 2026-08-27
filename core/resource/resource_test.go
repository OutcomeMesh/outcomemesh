package resource

import (
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestResourceCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	value := testResource()
	encoded := value.CanonicalBytes()
	decoder := codec.NewDecoder(encoded)
	decoded, err := Decode(decoder)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if decoded != value {
		t.Fatalf("decoded = %#v, want %#v", decoded, value)
	}
}

func TestResourceValidation(t *testing.T) {
	t.Parallel()

	value := testResource()
	value.Amount = 0
	if err := value.Validate(); !errors.Is(err, ErrZeroAmount) {
		t.Fatalf("error = %v, want %v", err, ErrZeroAmount)
	}

	value = testResource()
	value.Version = 1
	if err := value.Validate(); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add(testResource().CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoder := codec.NewDecoder(input)
		_, _ = Decode(decoder)
	})
}

func testResource() Resource {
	var id types.ResourceID
	id[31] = 1
	var owner types.Address
	owner[31] = 2
	var asset types.AssetID
	asset[31] = 3
	var policy types.Hash
	policy[31] = 4
	var payload types.Hash
	payload[31] = 5

	return Resource{
		ID:          id,
		Version:     Version0,
		Owner:       owner,
		Asset:       asset,
		Amount:      42,
		PolicyHash:  policy,
		PayloadHash: payload,
	}
}
