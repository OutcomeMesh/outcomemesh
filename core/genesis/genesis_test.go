package genesis

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func testDocument() Document {
	owner := types.Address(types.DomainHash("test/genesis/owner"))
	return Document{
		Version:      Version0,
		NetworkID:    11,
		Timestamp:    1_700_000_000,
		Target:       types.Hash{0x00, 0xff, 0xff, 0xff},
		BlockSubsidy: 50,
		Allocations: []resource.Resource{{
			ID:      types.ResourceID(types.DomainHash("test/genesis/allocation")),
			Version: resource.Version0,
			Owner:   owner,
			Asset:   types.NativeAssetID(),
			Amount:  1_000,
		}},
	}
}

func TestDecodeRejectsImpossibleAllocationCountBeforeAllocation(t *testing.T) {
	t.Parallel()

	document := testDocument()
	encoder := codec.NewEncoder(64)
	encoder.U16(document.Version)
	encoder.U32(document.NetworkID)
	encoder.U64(document.Timestamp)
	encoder.Fixed(document.Target[:])
	encoder.U64(document.BlockSubsidy)
	encoder.Uvarint(MaxAllocations)
	if _, err := Decode(encoder.Bytes()); !errors.Is(err, codec.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want early EOF rejection", err)
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	document := testDocument()
	decoded, err := Decode(document.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.CanonicalBytes()) != string(document.CanonicalBytes()) {
		t.Fatal("genesis encoding changed during round trip")
	}
	if decoded.Allocations[0] != document.Allocations[0] {
		t.Fatal("genesis allocation changed during round trip")
	}
	if _, err := document.ID(); err != nil {
		t.Fatal(err)
	}
	if _, err := document.StateRoot(); err != nil {
		t.Fatal(err)
	}
	const canonicalHex = "00000000000b000000006553f10000ffffff00000000000000000000000000000000000000000000000000000000000000000000003201acd69fcdbfcac6605db8407602e6df47c6fdfaa7425d54528584a75ec8d52ccd0000000000000000223208fdaecf845f6173f99e779d5a3c7d6639e9d719b54febec14ff5693d9f62f4f0bcd1bea178c030f78e4f4da18c7031210a7e50102f4e17a94b7fb339bb300000000000003e8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	if got := hex.EncodeToString(document.CanonicalBytes()); got != canonicalHex {
		t.Fatalf("canonical genesis changed:\n got %s\nwant %s", got, canonicalHex)
	}
	id, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id.String(), "9bbaa98da32d9a9f1e0cc744a44b2d44fcd0c50fdd9dfa517c985b73fead5e96"; got != want {
		t.Fatalf("genesis ID changed: got %s want %s", got, want)
	}
	root, err := document.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := root.String(), "bd9d2b89a375c129542bd83d4fd852203c966dedb3f12bff8a174e2abc27a755"; got != want {
		t.Fatalf("genesis state root changed: got %s want %s", got, want)
	}
}

func TestRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Document)
		want   error
	}{
		{name: "network", mutate: func(document *Document) { document.NetworkID = 0 }, want: ErrNetworkID},
		{name: "timestamp", mutate: func(document *Document) { document.Timestamp = 0 }, want: ErrTimestamp},
		{name: "target", mutate: func(document *Document) { document.Target = types.Hash{} }, want: ErrTarget},
		{name: "subsidy", mutate: func(document *Document) { document.BlockSubsidy = 0 }, want: ErrBlockSubsidy},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			document := testDocument()
			test.mutate(&document)
			if err := document.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add(testDocument().CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Decode(input)
	})
}
