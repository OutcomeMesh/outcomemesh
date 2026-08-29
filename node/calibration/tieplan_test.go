package calibration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestTiePlanCanonicalRoundTripBindingAndGoldenID(t *testing.T) {
	plan, binding := testTiePlan(t)
	if err := plan.Verify(binding); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTiePlan(plan.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.CanonicalBytes(), plan.CanonicalBytes()) {
		t.Fatal("tie plan changed during canonical round trip")
	}
	identifier, err := decoded.ID()
	if err != nil {
		t.Fatal(err)
	}
	const wantID = "6eef06dab78e377167086422f36497d238924aa42c7eee6f8dc9f85f0b6443e2"
	if identifier.String() != wantID {
		t.Fatalf("tie plan ID = %s, want %s", identifier, wantID)
	}
}

func TestTiePlanRejectsMutationWrongBindingAndBadSchedule(t *testing.T) {
	plan, binding := testTiePlan(t)
	mutated := plan
	mutated.Slots = append([]TiePlanSlot(nil), plan.Slots...)
	mutated.Slots[0].StartedAt++
	if err := mutated.Validate(); !errors.Is(err, ErrSignature) {
		t.Fatalf("mutated plan error = %v, want ErrSignature", err)
	}
	foreign := binding
	foreign.CoordinatorPublicKey[0] ^= 1
	if err := plan.Verify(foreign); !errors.Is(err, ErrBinding) {
		t.Fatalf("foreign binding error = %v, want ErrBinding", err)
	}

	base := unsignedTiePlan()
	base.Slots[1].StartedAt = base.Slots[0].EndedAt - 1
	if _, err := SignTiePlan(testTieCoordinatorKey(), base); !errors.Is(err, ErrTiePlan) {
		t.Fatalf("overlapping slot error = %v, want ErrTiePlan", err)
	}
	base = unsignedTiePlan()
	base.MaximumPairDelaySeconds = base.Slots[0].EndedAt - base.Slots[0].StartedAt + 1
	if _, err := SignTiePlan(testTieCoordinatorKey(), base); !errors.Is(err, ErrTiePlan) {
		t.Fatalf("long pair delay error = %v, want ErrTiePlan", err)
	}
	base = unsignedTiePlan()
	base.ControlMiner = base.TestedMiner
	if _, err := SignTiePlan(testTieCoordinatorKey(), base); !errors.Is(err, ErrTiePlan) {
		t.Fatalf("same miner roles error = %v, want ErrTiePlan", err)
	}
	base = unsignedTiePlan()
	base.Slots[0].FirstRole = TieRoleUnspecified
	if _, err := SignTiePlan(testTieCoordinatorKey(), base); !errors.Is(err, ErrTiePlan) {
		t.Fatalf("missing first role error = %v, want ErrTiePlan", err)
	}
	base = unsignedTiePlan()
	copy(base.ObserverPublicKey[:], testTieCoordinatorKey().Public().(ed25519.PublicKey))
	if _, err := SignTiePlan(testTieCoordinatorKey(), base); !errors.Is(err, ErrPublicKey) {
		t.Fatalf("same coordinator and observer error = %v, want ErrPublicKey", err)
	}
}

func TestTiePlanFileAndDecoderBounds(t *testing.T) {
	plan, binding := testTiePlan(t)
	path := filepath.Join(t.TempDir(), "nested", "tie-plan.omtp")
	if err := SaveTiePlanFile(path, plan, binding); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTiePlanFile(path, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.CanonicalBytes(), plan.CanonicalBytes()) {
		t.Fatal("tie plan changed during file round trip")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("tie plan permissions = %o, want 600", info.Mode().Perm())
	}
	encoded := plan.CanonicalBytes()
	if _, err := DecodeTiePlan(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("truncated tie plan was accepted")
	}
	if _, err := DecodeTiePlan(append(encoded, 0)); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing tie plan error = %v", err)
	}
	if _, err := DecodeTiePlan(make([]byte, MaximumTiePlanBytes+1)); !errors.Is(err, ErrTiePlanLimit) {
		t.Fatalf("oversize tie plan error = %v", err)
	}
}

func FuzzDecodeTiePlanNeverPanics(f *testing.F) {
	plan, _ := testTiePlan(f)
	f.Add(plan.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		plan, err := DecodeTiePlan(input)
		if err == nil {
			_ = plan.Validate()
		}
	})
}

func testTiePlan(t testing.TB) (TiePlan, TiePlanBinding) {
	t.Helper()
	plan, err := SignTiePlan(testTieCoordinatorKey(), unsignedTiePlan())
	if err != nil {
		t.Fatal(err)
	}
	return plan, plan.Binding()
}

func unsignedTiePlan() TiePlan {
	observer := testTieObserverKey()
	plan := TiePlan{
		Version: TiePlanVersion1, NetworkID: 91,
		GenesisID: types.DomainHash("test/calibration/tie/genesis"), ActivationHeight: 25,
		TestedMiner:             types.Address(types.DomainHash("test/calibration/tie/tested-miner")),
		ControlMiner:            types.Address(types.DomainHash("test/calibration/tie/control-miner")),
		MaximumPairDelaySeconds: 5,
		Slots: []TiePlanSlot{
			{StartedAt: testStartedAt, EndedAt: testStartedAt + 60, FirstRole: TieRoleTested},
			{StartedAt: testStartedAt + 120, EndedAt: testStartedAt + 180, FirstRole: TieRoleTested},
			{StartedAt: testStartedAt + 240, EndedAt: testStartedAt + 300, FirstRole: TieRoleTested},
		},
	}
	copy(plan.ObserverPublicKey[:], observer.Public().(ed25519.PublicKey))
	return plan
}

func testTieCoordinatorKey() ed25519.PrivateKey {
	seed := types.DomainHash("test/calibration/tie/coordinator-key/v0")
	return ed25519.NewKeyFromSeed(seed[:])
}

func testTieObserverKey() ed25519.PrivateKey {
	seed := types.DomainHash("test/calibration/tie/observer-key/v0")
	return ed25519.NewKeyFromSeed(seed[:])
}
