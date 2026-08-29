package calibration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestTieReceiptCanonicalRoundTripAndGoldenTail(t *testing.T) {
	plan, _ := testTiePlan(t)
	receipts := testTieReceipts(t, plan)
	for _, receipt := range receipts {
		if err := receipt.Validate(plan); err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeTieTrialReceipt(receipt.CanonicalBytes())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.CanonicalBytes(), receipt.CanonicalBytes()) {
			t.Fatal("tie receipt changed during canonical round trip")
		}
	}
	adopted, err := receipts[0].Adopted()
	if err != nil || !adopted {
		t.Fatalf("first receipt adoption = %v, %v", adopted, err)
	}
	if _, err := receipts[1].Adopted(); !errors.Is(err, ErrTieReceipt) {
		t.Fatalf("no-pair adoption error = %v, want ErrTieReceipt", err)
	}
	tail, err := receipts[len(receipts)-1].ID(plan)
	if err != nil {
		t.Fatal(err)
	}
	const wantTail = "10d385b8140946ffe21871735fe18067b81582d937ed1f8f68bf0bd71740340a"
	if tail.String() != wantTail {
		t.Fatalf("tie receipt tail = %s, want %s", tail, wantTail)
	}
}

func TestTieReceiptRejectsMutationInvalidRoleTimeAndNoPairData(t *testing.T) {
	plan, _ := testTiePlan(t)
	receipts := testTieReceipts(t, plan)
	mutated := receipts[0]
	mutated.SelectedAnchorID = mutated.ControlAnchorID
	if err := mutated.Validate(plan); !errors.Is(err, ErrSignature) {
		t.Fatalf("mutated receipt error = %v, want ErrSignature", err)
	}

	base := unsignedCompletedTieReceipt(1, types.Hash{})
	base.SelectedAnchorID = types.DomainHash("test/calibration/tie/foreign-anchor")
	if _, err := SignTieTrialReceipt(testTieObserverKey(), base, plan); !errors.Is(err, ErrTieReceipt) {
		t.Fatalf("foreign selected anchor error = %v, want ErrTieReceipt", err)
	}
	base = unsignedCompletedTieReceipt(1, types.Hash{})
	base.ControlObservedAt = base.TestedObservedAt + plan.MaximumPairDelaySeconds + 1
	if _, err := SignTieTrialReceipt(testTieObserverKey(), base, plan); !errors.Is(err, ErrTieReceipt) {
		t.Fatalf("late pair error = %v, want ErrTieReceipt", err)
	}
	base = unsignedCompletedTieReceipt(1, types.Hash{})
	base.TestedObservedAt = plan.Slots[0].EndedAt
	if _, err := SignTieTrialReceipt(testTieObserverKey(), base, plan); !errors.Is(err, ErrTieReceipt) {
		t.Fatalf("outside slot error = %v, want ErrTieReceipt", err)
	}
	base = unsignedCompletedTieReceipt(1, types.Hash{})
	base.FirstObservedAnchorID = base.ControlAnchorID
	if _, err := SignTieTrialReceipt(testTieObserverKey(), base, plan); !errors.Is(err, ErrTieReceipt) {
		t.Fatalf("wrong first role error = %v, want ErrTieReceipt", err)
	}
	noPair := TieTrialReceipt{Version: TieReceiptVersion1, Sequence: 1, Status: TieTrialNoPair, Height: 1}
	if _, err := SignTieTrialReceipt(testTieObserverKey(), noPair, plan); !errors.Is(err, ErrTieReceipt) {
		t.Fatalf("no-pair data error = %v, want ErrTieReceipt", err)
	}
}

func TestTieReceiptDecoderBounds(t *testing.T) {
	plan, _ := testTiePlan(t)
	encoded := testTieReceipts(t, plan)[0].CanonicalBytes()
	if _, err := DecodeTieTrialReceipt(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("truncated tie receipt was accepted")
	}
	if _, err := DecodeTieTrialReceipt(append(encoded, 0)); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing tie receipt error = %v", err)
	}
	if _, err := DecodeTieTrialReceipt(make([]byte, MaximumTieReceiptBytes+1)); !errors.Is(err, ErrTieReceiptLimit) {
		t.Fatalf("oversize tie receipt error = %v", err)
	}
}

func FuzzDecodeTieTrialReceiptNeverPanics(f *testing.F) {
	plan, _ := testTiePlan(f)
	receipt := testTieReceipts(f, plan)[0]
	f.Add(receipt.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		receipt, err := DecodeTieTrialReceipt(input)
		if err == nil {
			_ = receipt.Validate(plan)
		}
	})
}

func testTieReceipts(t testing.TB, plan TiePlan) []TieTrialReceipt {
	return testTieReceiptsWithKey(t, plan, testTieObserverKey())
}

func testTieReceiptsWithKey(t testing.TB, plan TiePlan, observer ed25519.PrivateKey) []TieTrialReceipt {
	t.Helper()
	first, err := SignTieTrialReceipt(observer, unsignedCompletedTieReceipt(1, types.Hash{}), plan)
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := first.ID(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignTieTrialReceipt(observer, TieTrialReceipt{
		Version: TieReceiptVersion1, Sequence: 2, Status: TieTrialNoPair, PreviousID: firstID,
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := second.ID(plan)
	if err != nil {
		t.Fatal(err)
	}
	thirdUnsigned := unsignedCompletedTieReceipt(3, secondID)
	thirdUnsigned.TestedObservedAt = plan.Slots[2].StartedAt + 3
	thirdUnsigned.ControlObservedAt = plan.Slots[2].StartedAt + 1
	thirdUnsigned.SelectedAnchorID = thirdUnsigned.ControlAnchorID
	third, err := SignTieTrialReceipt(observer, thirdUnsigned, plan)
	if err != nil {
		t.Fatal(err)
	}
	return []TieTrialReceipt{first, second, third}
}

func unsignedCompletedTieReceipt(sequence uint64, previous types.Hash) TieTrialReceipt {
	tested := types.DomainHash("test/calibration/tie/tested-anchor")
	control := types.DomainHash("test/calibration/tie/control-anchor")
	return TieTrialReceipt{
		Version: TieReceiptVersion1, Sequence: sequence, Status: TieTrialCompleted,
		PreviousID: previous, ParentID: types.DomainHash("test/calibration/tie/parent"), Height: 30,
		TestedAnchorID: tested, ControlAnchorID: control,
		TestedObservedAt: testStartedAt + 2, ControlObservedAt: testStartedAt + 4,
		SelectedAnchorID: tested, FirstObservedAnchorID: tested,
	}
}
