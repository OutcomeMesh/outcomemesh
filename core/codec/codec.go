package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var (
	ErrUnexpectedEOF = errors.New("unexpected end of canonical input")
	ErrNonCanonical  = errors.New("non-canonical encoding")
	ErrLimitExceeded = errors.New("canonical value exceeds limit")
	ErrTrailingBytes = errors.New("trailing bytes after canonical object")
)

type Encoder struct {
	buffer []byte
}

func NewEncoder(capacity int) *Encoder {
	if capacity < 0 {
		capacity = 0
	}
	return &Encoder{buffer: make([]byte, 0, capacity)}
}

func (encoder *Encoder) U8(value uint8) {
	encoder.buffer = append(encoder.buffer, value)
}

func (encoder *Encoder) U16(value uint16) {
	start := len(encoder.buffer)
	encoder.buffer = append(encoder.buffer, 0, 0)
	binary.BigEndian.PutUint16(encoder.buffer[start:], value)
}

func (encoder *Encoder) U32(value uint32) {
	start := len(encoder.buffer)
	encoder.buffer = append(encoder.buffer, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(encoder.buffer[start:], value)
}

func (encoder *Encoder) U64(value uint64) {
	start := len(encoder.buffer)
	encoder.buffer = append(encoder.buffer, make([]byte, 8)...)
	binary.BigEndian.PutUint64(encoder.buffer[start:], value)
}

func (encoder *Encoder) Uvarint(value uint64) {
	var scratch [binary.MaxVarintLen64]byte
	count := binary.PutUvarint(scratch[:], value)
	encoder.buffer = append(encoder.buffer, scratch[:count]...)
}

func (encoder *Encoder) Fixed(value []byte) {
	encoder.buffer = append(encoder.buffer, value...)
}

func (encoder *Encoder) BytesField(value []byte) {
	encoder.Uvarint(uint64(len(value)))
	encoder.Fixed(value)
}

func (encoder *Encoder) Bytes() []byte {
	result := make([]byte, len(encoder.buffer))
	copy(result, encoder.buffer)
	return result
}

func (encoder *Encoder) Len() int {
	return len(encoder.buffer)
}

type Decoder struct {
	input  []byte
	offset int
}

func NewDecoder(input []byte) *Decoder {
	return &Decoder{input: input}
}

func (decoder *Decoder) Remaining() int {
	return len(decoder.input) - decoder.offset
}

func (decoder *Decoder) U8() (uint8, error) {
	value, err := decoder.Fixed(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (decoder *Decoder) U16() (uint16, error) {
	value, err := decoder.Fixed(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}

func (decoder *Decoder) U32() (uint32, error) {
	value, err := decoder.Fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}

func (decoder *Decoder) U64() (uint64, error) {
	value, err := decoder.Fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}

func (decoder *Decoder) Uvarint() (uint64, error) {
	if decoder.Remaining() == 0 {
		return 0, ErrUnexpectedEOF
	}

	value, count := binary.Uvarint(decoder.input[decoder.offset:])
	if count == 0 {
		return 0, ErrUnexpectedEOF
	}
	if count < 0 {
		return 0, fmt.Errorf("%w: unsigned varint overflow", ErrNonCanonical)
	}

	var canonical [binary.MaxVarintLen64]byte
	canonicalCount := binary.PutUvarint(canonical[:], value)
	if canonicalCount != count {
		return 0, fmt.Errorf("%w: overlong unsigned varint", ErrNonCanonical)
	}
	for index := 0; index < count; index++ {
		if canonical[index] != decoder.input[decoder.offset+index] {
			return 0, fmt.Errorf("%w: invalid unsigned varint", ErrNonCanonical)
		}
	}

	decoder.offset += count
	return value, nil
}

func (decoder *Decoder) Fixed(length int) ([]byte, error) {
	if length < 0 || length > decoder.Remaining() {
		return nil, ErrUnexpectedEOF
	}

	start := decoder.offset
	decoder.offset += length
	return decoder.input[start:decoder.offset], nil
}

func (decoder *Decoder) BytesField(limit uint64) ([]byte, error) {
	length, err := decoder.Uvarint()
	if err != nil {
		return nil, err
	}
	if length > limit || length > uint64(math.MaxInt) {
		return nil, ErrLimitExceeded
	}

	value, err := decoder.Fixed(int(length))
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

func (decoder *Decoder) ListLength(limit uint64) (int, error) {
	length, err := decoder.Uvarint()
	if err != nil {
		return 0, err
	}
	if length > limit || length > uint64(math.MaxInt) {
		return 0, ErrLimitExceeded
	}
	return int(length), nil
}

func (decoder *Decoder) Finish() error {
	if decoder.Remaining() != 0 {
		return ErrTrailingBytes
	}
	return nil
}
