package workblock

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

func radixGolden(t testing.TB) (Block, Result, Position, Parameters) {
	t.Helper()
	p := testParameters()
	p.RadixActivationHeight = 1
	pos := Position{Height: 1, ParentID: types.DomainHash("test/workblock/golden-parent"), ParentTimestamp: p.DifficultyAnchorTimestamp, MedianTimePast: p.DifficultyAnchorTimestamp, Timestamp: 1_700_000_000, Target: p.DifficultyAnchorTarget}
	payload, e := PreparePayload(state.Empty(), pos, nil, nil, p)
	if e != nil {
		t.Fatal(e)
	}
	inc, _ := workgraph.InclusionRoot(nil)
	template, e := payload.SealTemplate(testAddress("golden-anchor"), inc, nil)
	if e != nil {
		t.Fatal(e)
	}
	seal, _, e := workgraph.MineAnchor(context.Background(), template, 0)
	if e != nil {
		t.Fatal(e)
	}
	b, r, e := payload.Finalize(seal, nil)
	if e != nil {
		t.Fatal(e)
	}
	return b, r, pos, p
}
func TestRadixWorkBlockVersionAndDomainBinding(t *testing.T) {
	b, r, pos, p := radixGolden(t)
	if b.Header.Version != Version3 || r.State.CommitmentVersion() != state.CommitmentRadixV1 {
		t.Fatal("version")
	}
	raw := b.CanonicalBytes()
	decoded, e := Decode(raw)
	if e != nil || !bytes.Equal(decoded.CanonicalBytes(), raw) {
		t.Fatal("roundtrip", e)
	}
	if _, e = ValidateAndExecute(state.Empty(), pos, nil, b, p); e != nil {
		t.Fatal(e)
	}
	flip := b
	flip.Header.Version = Version1
	if _, e = Decode(flip.CanonicalBytes()); e == nil {
		t.Fatal("seal reused across versions")
	}
	if _, e = ValidateAndExecute(state.Empty(), pos, nil, flip, p); e == nil {
		t.Fatal("accepted v1 at radix activation")
	}
	old := p
	old.RadixActivationHeight = 0
	if _, e = ValidateAndExecute(state.Empty(), pos, nil, b, old); e == nil {
		t.Fatal("v3 without schedule")
	}
	early := p
	early.RadixActivationHeight = 2
	if e = ValidateHeaderAt(pos, b.Header, early, pos.Timestamp); e == nil {
		t.Fatal("early v3 header")
	}
	already, _ := state.EmptyVersion(state.CommitmentRadixV1)
	if _, e = PreparePayload(already, pos, nil, nil, p); e != nil {
		t.Fatal("v2 base cannot enter v3", e)
	}
	p.RadixActivationHeight = 2
	if _, e = stateForHeight(already, 2, p); e == nil {
		t.Fatal("already converted internal boundary")
	}
	if _, e = stateForHeight(state.Empty(), 3, p); e == nil {
		t.Fatal("late conversion")
	}
	if _, e = stateForHeight(already, 1, p); e == nil {
		t.Fatal("early conversion")
	}
}
func TestRadixTransitionPreservesResourcesAndParent(t *testing.T) {
	p := testParameters()
	p.RadixActivationHeight = 2
	resources := []resource.Resource{{ID: types.ResourceID(types.DomainHash("test/radix-work/resource")), Version: resource.Version0, Owner: testAddress("owner"), Asset: types.NativeAssetID(), Amount: 100, SpendAfter: 20}}
	before, e := state.New(resources)
	if e != nil {
		t.Fatal(e)
	}
	old := before.Root()
	after, e := stateForHeight(before, 2, p)
	if e != nil {
		t.Fatal(e)
	}
	if before.Root() != old || before.CommitmentVersion() != state.CommitmentV0 {
		t.Fatal("mutated predecessor")
	}
	want, _ := state.NewVersion(resources, state.CommitmentRadixV1)
	if after.Root() != want.Root() || after.Root() == old || after.Len() != before.Len() {
		t.Fatal("conversion changed resources")
	}
	for _, v := range after.Resources() {
		if !bytes.Equal(v.CanonicalBytes(), resources[0].CanonicalBytes()) {
			t.Fatal("resource changed")
		}
	}
	next, e := stateForHeight(after, 3, p)
	if e != nil || next != after {
		t.Fatal("rebuilt already-radix state", e)
	}
}
func TestGoldenVersion3BlockVector(t *testing.T) {
	b, r, _, _ := radixGolden(t)
	if r.BlockID.String() != "0041e1b81fcf70c9e90d09111fb3faf5077c1f570d2c74732028ff0ce64e330c" {
		t.Fatal("block ID", r.BlockID)
	}
	const want = "000300000000004d0000000000000001c03ea83b20b7f068ecf378fe3dde1662213fb410c87757e466b0314b05a0c14a000000006553f100007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff407d668ae524a7f74b0e9eba82c12562eb03e8bb158927abd0bdf6cd10a69d78ace6904f805047b8675a3129f84d0916fa60cfc9516bfca85033202e1a3852a7052626f83be9e4801476397dd982d7deebdc46ea2557d9dbfb3bd366d4bf6c4c000000000000000904c1265c23e8244ab55cbcaba33ab962f964a57ca1a5efa845230bfe4543825da86672452e301a6893e2060f6cfa5f57379e4496a03b4d78aff11ae014e60852a8eda3c66a2a850ff6a9f70fe1d238e12563b3e6bfde86db03f2dfab1c890802e531199c8b262bb18f7820ba0f7c1156b81940f52cebb9c205c946f2e7b57ca020d44be30322640c368aff4cf516cd220bf70227f9f1558f65166116387cdd61ae00000000000000000000"
	if got := hex.EncodeToString(b.CanonicalBytes()); got != want {
		t.Fatalf("block=%s\nid=%s\nroot=%s", got, r.BlockID, r.State.Root())
	}
}
func FuzzRadixWorkBlock(f *testing.F) {
	b, _, _, _ := radixGolden(f)
	f.Add(b.CanonicalBytes())
	f.Add(b.Header.CanonicalBytes())
	f.Add([]byte{0, 3})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if b, e := Decode(raw); e == nil && !bytes.Equal(raw, b.CanonicalBytes()) {
			t.Fatal("block canonicality")
		}
		if h, e := DecodeHeader(raw); e == nil && !bytes.Equal(raw, h.CanonicalBytes()) {
			t.Fatal("header canonicality")
		}
	})
}
