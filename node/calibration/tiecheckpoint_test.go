package calibration

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestTiePairCheckpointCanonicalRoundTripAndGoldenID(t *testing.T) {
	plan, binding := testTiePlan(t)
	planID, _ := plan.ID()
	pairID := types.DomainHash("test/calibration/tie-pair-checkpoint/pair")
	checkpoint, err := SignTiePairCheckpoint(
		testTieCoordinatorKey(), plan, binding, planID, 2, pairID,
	)
	if err != nil {
		t.Fatal(err)
	}
	identifier, err := checkpoint.ID(plan, binding, planID)
	if err != nil {
		t.Fatal(err)
	}
	const wantID = "6362bc179bfdadb87e7719fe545c7ce44bf77158f6b270030320b985b1da6064"
	if identifier.String() != wantID {
		t.Fatalf("checkpoint ID=%s want=%s", identifier, wantID)
	}
	encoded := checkpoint.CanonicalBytes()
	if len(encoded) != TiePairCheckpointBytes {
		t.Fatalf("encoded bytes=%d want=%d", len(encoded), TiePairCheckpointBytes)
	}
	decoded, err := DecodeTiePairCheckpoint(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != checkpoint || decoded.Verify(plan, binding, planID) != nil {
		t.Fatalf("decoded=%+v checkpoint=%+v", decoded, checkpoint)
	}

	path := filepath.Join(t.TempDir(), "pair.omtcp")
	savedID, err := SaveTiePairCheckpointFile(path, checkpoint, plan, binding, planID)
	if err != nil || savedID != identifier {
		t.Fatalf("saved ID=%s err=%v", savedID, err)
	}
	loaded, err := LoadTiePairCheckpointFile(path, plan, binding, planID, identifier)
	if err != nil || loaded != checkpoint {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
}

func TestTiePairCheckpointRejectsMutationWrongPublicationAndPlan(t *testing.T) {
	plan, binding := testTiePlan(t)
	planID, _ := plan.ID()
	checkpoint, err := SignTiePairCheckpoint(
		testTieCoordinatorKey(), plan, binding, planID, 1,
		types.DomainHash("test/calibration/tie-pair-checkpoint/mutation"),
	)
	if err != nil {
		t.Fatal(err)
	}
	identifier, _ := checkpoint.ID(plan, binding, planID)

	mutated := checkpoint
	mutated.PairID[0] ^= 1
	if err := mutated.Verify(plan, binding, planID); !errors.Is(err, ErrSignature) {
		t.Fatalf("mutated checkpoint error=%v", err)
	}
	if _, err := SignTiePairCheckpoint(
		testTieObserverKey(), plan, binding, planID, 1, checkpoint.PairID,
	); !errors.Is(err, ErrTiePairCheckpoint) {
		t.Fatalf("wrong coordinator key error=%v", err)
	}
	if _, err := SignTiePairCheckpoint(
		testTieCoordinatorKey(), plan, binding, planID, uint64(len(plan.Slots))+1, checkpoint.PairID,
	); !errors.Is(err, ErrTiePairCheckpoint) {
		t.Fatalf("out-of-plan sequence error=%v", err)
	}

	path := filepath.Join(t.TempDir(), "pair.omtcp")
	if _, err := SaveTiePairCheckpointFile(path, checkpoint, plan, binding, planID); err != nil {
		t.Fatal(err)
	}
	wrongPublication := identifier
	wrongPublication[0] ^= 1
	if _, err := LoadTiePairCheckpointFile(path, plan, binding, planID, wrongPublication); !errors.Is(err, ErrTiePairCheckpoint) {
		t.Fatalf("wrong published ID error=%v", err)
	}
	wrongPlanID := planID
	wrongPlanID[0] ^= 1
	if err := checkpoint.Verify(plan, binding, wrongPlanID); !errors.Is(err, ErrTiePairCheckpoint) {
		t.Fatalf("wrong plan ID error=%v", err)
	}
}

func TestTiePairCheckpointDecoderRequiresExactBound(t *testing.T) {
	plan, binding := testTiePlan(t)
	planID, _ := plan.ID()
	checkpoint, err := SignTiePairCheckpoint(
		testTieCoordinatorKey(), plan, binding, planID, 1,
		types.DomainHash("test/calibration/tie-pair-checkpoint/decoder"),
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded := checkpoint.CanonicalBytes()
	for _, input := range [][]byte{nil, encoded[:len(encoded)-1], append(encoded, 0)} {
		if _, err := DecodeTiePairCheckpoint(input); !errors.Is(err, ErrTiePairCheckpoint) {
			t.Fatalf("input bytes=%d error=%v", len(input), err)
		}
	}
}

func FuzzDecodeTiePairCheckpointNeverPanics(f *testing.F) {
	plan, binding := testTiePlan(f)
	planID, _ := plan.ID()
	checkpoint, err := SignTiePairCheckpoint(
		testTieCoordinatorKey(), plan, binding, planID, 1,
		types.DomainHash("test/calibration/tie-pair-checkpoint/fuzz"),
	)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(checkpoint.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeTiePairCheckpoint(input)
	})
}
