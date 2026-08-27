package codec

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	encoder := NewEncoder(64)
	encoder.U8(7)
	encoder.U16(0x1020)
	encoder.U32(0x30405060)
	encoder.U64(0x708090a0b0c0d0e0)
	encoder.Uvarint(math.MaxUint64)
	encoder.BytesField([]byte("outcome"))

	decoder := NewDecoder(encoder.Bytes())
	if value, err := decoder.U8(); err != nil || value != 7 {
		t.Fatalf("U8() = %d, %v", value, err)
	}
	if value, err := decoder.U16(); err != nil || value != 0x1020 {
		t.Fatalf("U16() = %d, %v", value, err)
	}
	if value, err := decoder.U32(); err != nil || value != 0x30405060 {
		t.Fatalf("U32() = %d, %v", value, err)
	}
	if value, err := decoder.U64(); err != nil || value != 0x708090a0b0c0d0e0 {
		t.Fatalf("U64() = %d, %v", value, err)
	}
	if value, err := decoder.Uvarint(); err != nil || value != math.MaxUint64 {
		t.Fatalf("Uvarint() = %d, %v", value, err)
	}
	if value, err := decoder.BytesField(32); err != nil || !bytes.Equal(value, []byte("outcome")) {
		t.Fatalf("BytesField() = %q, %v", value, err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
}

func TestDecoderRejectsOverlongUvarint(t *testing.T) {
	t.Parallel()

	decoder := NewDecoder([]byte{0x80, 0x00})
	_, err := decoder.Uvarint()
	if !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("error = %v, want %v", err, ErrNonCanonical)
	}
}

func TestDecoderRejectsLimitsAndTrailingBytes(t *testing.T) {
	t.Parallel()

	encoder := NewEncoder(8)
	encoder.BytesField([]byte("12345"))
	decoder := NewDecoder(encoder.Bytes())
	if _, err := decoder.BytesField(4); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v, want %v", err, ErrLimitExceeded)
	}

	decoder = NewDecoder([]byte{1, 2})
	if _, err := decoder.U8(); err != nil {
		t.Fatalf("U8() error = %v", err)
	}
	if err := decoder.Finish(); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("Finish() error = %v, want %v", err, ErrTrailingBytes)
	}
}

func FuzzUvarintRoundTrip(f *testing.F) {
	seeds := []uint64{0, 1, 127, 128, 255, 256, math.MaxUint32, math.MaxUint64}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value uint64) {
		encoder := NewEncoder(binaryMaxVarintLen64)
		encoder.Uvarint(value)
		decoder := NewDecoder(encoder.Bytes())
		decoded, err := decoder.Uvarint()
		if err != nil {
			t.Fatalf("Uvarint() error = %v", err)
		}
		if decoded != value {
			t.Fatalf("decoded = %d, want %d", decoded, value)
		}
		if err := decoder.Finish(); err != nil {
			t.Fatalf("Finish() error = %v", err)
		}
	})
}

const binaryMaxVarintLen64 = 10

func FuzzDecoderNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x80})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02})

	f.Fuzz(func(t *testing.T, input []byte) {
		decoder := NewDecoder(input)
		_, _ = decoder.Uvarint()
		_, _ = decoder.BytesField(1024)
		_ = decoder.Finish()
	})
}
