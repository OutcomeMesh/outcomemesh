package workgraph

import (
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

func TestFeeQueueDelaysExactlyAndConserves(t *testing.T) {
	t.Parallel()

	queue, err := NewFeeQueue(3)
	if err != nil {
		t.Fatal(err)
	}
	deposits := []uint64{10, 20, 0, 7, 0, 0, 0}
	wantAwards := []uint64{0, 0, 0, 10, 20, 0, 7}
	var deposited uint64
	var awarded uint64
	for index, deposit := range deposits {
		award, next, err := queue.Advance(deposit)
		if err != nil {
			t.Fatalf("advance %d: %v", index, err)
		}
		if award != wantAwards[index] {
			t.Fatalf("advance %d award=%d want=%d", index, award, wantAwards[index])
		}
		deposited += deposit
		awarded += award
		if deposited != awarded+next.Balance() {
			t.Fatalf("advance %d conservation deposited=%d awarded=%d balance=%d",
				index, deposited, awarded, next.Balance())
		}
		queue = next
	}
	if queue.Balance() != 0 {
		t.Fatalf("final balance=%d", queue.Balance())
	}
}

func TestFeeQueueEncodingRoundTripAndDetachedSlots(t *testing.T) {
	t.Parallel()

	queue, _ := NewFeeQueue(3)
	_, queue, _ = queue.Advance(10)
	_, queue, _ = queue.Advance(20)
	_, queue, _ = queue.Advance(0)
	encoded, err := queue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	const wantHex = "000000030000000000000000001e000000000000000a00000000000000140000000000000000"
	if hex.EncodeToString(encoded) != wantHex {
		t.Fatalf("fee queue encoding=%x", encoded)
	}
	decoded, err := DecodeFeeQueue(encoded)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decoded.Root()
	if err != nil {
		t.Fatal(err)
	}
	if root.String() != "9edb244b34d9734c6d82e6bfa3acbc24fd2c175d57d9da64c162fe43a9507539" {
		t.Fatalf("fee queue root=%s", root)
	}
	slots := decoded.Slots()
	slots[0] = 999
	if decoded.Slots()[0] != 10 {
		t.Fatal("fee queue exposed mutable slots")
	}
}

func TestFeeQueueRejectsOverflowWithoutMutation(t *testing.T) {
	t.Parallel()

	queue, _ := NewFeeQueue(2)
	_, queue, _ = queue.Advance(math.MaxUint64)
	before, _ := queue.CanonicalBytes()
	if _, _, err := queue.Advance(1); !errors.Is(err, ErrFeeQueue) {
		t.Fatalf("overflow error=%v", err)
	}
	after, _ := queue.CanonicalBytes()
	if string(before) != string(after) {
		t.Fatal("failed advance mutated fee queue")
	}
}

func TestFeeQueueRejectsInconsistentBalance(t *testing.T) {
	t.Parallel()

	queue, _ := NewFeeQueue(2)
	encoded, _ := queue.CanonicalBytes()
	encoded[13] = 1
	if _, err := DecodeFeeQueue(encoded); !errors.Is(err, ErrFeeQueue) {
		t.Fatalf("inconsistent balance error=%v", err)
	}
}

func FuzzDecodeFeeQueueNeverPanics(f *testing.F) {
	queue, _ := NewFeeQueue(3)
	_, queue, _ = queue.Advance(10)
	encoded, _ := queue.CanonicalBytes()
	f.Add(encoded)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := DecodeFeeQueue(input)
		if err != nil {
			return
		}
		reencoded, err := decoded.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if string(input) != string(reencoded) {
			t.Fatal("accepted non-canonical fee queue")
		}
	})
}
