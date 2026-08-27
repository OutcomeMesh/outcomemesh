package difficulty

import (
	"errors"
	"math/big"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	testSpacing  = uint64(60)
	testHalfLife = uint64(7_200)
	testAnchor   = uint64(1_700_000_000)
)

func TestASERTExactScheduleKeepsTarget(t *testing.T) {
	t.Parallel()

	anchor := targetFromInteger(new(big.Int).Lsh(big.NewInt(1), 240))
	for _, height := range []uint64{1, 2, 100, 10_000} {
		got, err := ASERT(anchor, testAnchor, height, testAnchor+height*testSpacing, testSpacing, testHalfLife)
		if err != nil {
			t.Fatal(err)
		}
		if got != anchor {
			t.Fatalf("height %d: got %s want %s", height, got, anchor)
		}
	}
}

func TestASERTHalfLifeChangesTargetByPowerOfTwo(t *testing.T) {
	t.Parallel()

	anchorInteger := new(big.Int).Lsh(big.NewInt(1), 240)
	anchor := targetFromInteger(anchorInteger)
	height := uint64(100)
	onSchedule := testAnchor + height*testSpacing

	harder, err := ASERT(anchor, testAnchor, height, onSchedule-testHalfLife, testSpacing, testHalfLife)
	if err != nil {
		t.Fatal(err)
	}
	wantHarder := targetFromInteger(new(big.Int).Rsh(new(big.Int).Set(anchorInteger), 1))
	if harder != wantHarder {
		t.Fatalf("one half-life early: got %s want %s", harder, wantHarder)
	}

	// The anchor is also the pow limit, so a late schedule clamps at anchor.
	easier, err := ASERT(anchor, testAnchor, height, onSchedule+testHalfLife, testSpacing, testHalfLife)
	if err != nil {
		t.Fatal(err)
	}
	if easier != anchor {
		t.Fatalf("one half-life late: got %s want pow limit %s", easier, anchor)
	}
}

func TestASERTGoldenFractionalVectors(t *testing.T) {
	t.Parallel()

	anchor := targetFromInteger(new(big.Int).Lsh(big.NewInt(1), 240))
	height := uint64(100)
	scheduled := testAnchor + height*testSpacing
	vectors := []struct {
		offset int64
		want   string
	}{
		{offset: -3_600, want: "0000b50100000000000000000000000000000000000000000000000000000000"},
		{offset: -61, want: "0000fe8100000000000000000000000000000000000000000000000000000000"},
		{offset: -1, want: "0000fff900000000000000000000000000000000000000000000000000000000"},
		{offset: 1, want: "0001000000000000000000000000000000000000000000000000000000000000"},
		{offset: 61, want: "0001000000000000000000000000000000000000000000000000000000000000"},
		{offset: 3_600, want: "0001000000000000000000000000000000000000000000000000000000000000"},
	}
	for _, vector := range vectors {
		timestamp := uint64(int64(scheduled) + vector.offset)
		target, err := ASERT(anchor, testAnchor, height, timestamp, testSpacing, testHalfLife)
		if err != nil {
			t.Fatal(err)
		}
		if target.String() != vector.want {
			t.Fatalf("offset %d: got %s want %s", vector.offset, target, vector.want)
		}
	}
}

func TestASERTRejectsInvalidParameters(t *testing.T) {
	t.Parallel()

	anchor := targetFromInteger(big.NewInt(1_000_000))
	if _, err := ASERT(types.Hash{}, testAnchor, 1, testAnchor+1, testSpacing, testHalfLife); !errors.Is(err, ErrAnchorTarget) {
		t.Fatalf("got %v, want anchor error", err)
	}
	if _, err := ASERT(anchor, testAnchor, 1, testAnchor+1, 0, testHalfLife); !errors.Is(err, ErrTargetSpacing) {
		t.Fatalf("got %v, want spacing error", err)
	}
	if _, err := ASERT(anchor, testAnchor, 1, testAnchor+1, testSpacing, 0); !errors.Is(err, ErrHalfLife) {
		t.Fatalf("got %v, want half-life error", err)
	}
}

func TestASERTExtremesClampWithoutHugeShift(t *testing.T) {
	t.Parallel()

	anchor := targetFromInteger(new(big.Int).Lsh(big.NewInt(1), 240))
	easiest, err := ASERT(anchor, 1, 1, ^uint64(0), testSpacing, 1)
	if err != nil {
		t.Fatal(err)
	}
	if easiest != anchor {
		t.Fatalf("late extreme: got %s want %s", easiest, anchor)
	}
	hardest, err := ASERT(anchor, ^uint64(0), ^uint64(0), 1, ^uint64(0), 1)
	if err != nil {
		t.Fatal(err)
	}
	if hardest != integerTarget(1) {
		t.Fatalf("early extreme: got %s want 1", hardest)
	}
}

func FuzzASERTNeverPanics(f *testing.F) {
	anchorSeed := types.DomainHash("test/asert/anchor")
	f.Add(anchorSeed[:], testAnchor, uint64(1), testAnchor+testSpacing, testSpacing, testHalfLife)
	f.Add([]byte{}, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, anchorBytes []byte, anchorTimestamp, height, timestamp, spacing, halfLife uint64) {
		var anchor types.Hash
		copy(anchor[:], anchorBytes)
		_, _ = ASERT(anchor, anchorTimestamp, height, timestamp, spacing, halfLife)
	})
}

func targetFromInteger(value *big.Int) types.Hash {
	return hashTarget(value)
}
