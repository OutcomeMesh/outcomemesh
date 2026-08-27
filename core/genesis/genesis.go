package genesis

import (
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0       uint16 = 0
	MaxAllocations        = 65_536
)

var (
	ErrUnsupportedVersion = errors.New("unsupported genesis version")
	ErrNetworkID          = errors.New("genesis network identifier is zero")
	ErrTimestamp          = errors.New("genesis timestamp is zero")
	ErrTarget             = errors.New("genesis proof-of-work target is zero")
	ErrBlockSubsidy       = errors.New("genesis block subsidy is zero")
)

type Document struct {
	Version      uint16
	NetworkID    uint32
	Timestamp    uint64
	Target       types.Hash
	BlockSubsidy uint64
	Allocations  []resource.Resource
}

func (document Document) Validate() error {
	if document.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, document.Version)
	}
	if document.NetworkID == 0 {
		return ErrNetworkID
	}
	if document.Timestamp == 0 {
		return ErrTimestamp
	}
	if document.Target.IsZero() {
		return ErrTarget
	}
	if document.BlockSubsidy == 0 {
		return ErrBlockSubsidy
	}
	if len(document.Allocations) > MaxAllocations {
		return fmt.Errorf("genesis allocation count %d exceeds %d", len(document.Allocations), MaxAllocations)
	}
	_, err := state.New(document.Allocations)
	return err
}

func (document Document) EncodeTo(encoder *codec.Encoder) {
	encoder.U16(document.Version)
	encoder.U32(document.NetworkID)
	encoder.U64(document.Timestamp)
	encoder.Fixed(document.Target[:])
	encoder.U64(document.BlockSubsidy)
	encoder.Uvarint(uint64(len(document.Allocations)))
	for _, allocation := range document.Allocations {
		allocation.EncodeTo(encoder)
	}
}

func (document Document) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(55 + len(document.Allocations)*176)
	document.EncodeTo(encoder)
	return encoder.Bytes()
}

func (document Document) ID() (types.Hash, error) {
	if err := document.Validate(); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(types.DomainGenesisID, document.CanonicalBytes()), nil
}

func (document Document) State() (*state.Memory, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	return state.New(document.Allocations)
}

func (document Document) StateRoot() (types.Hash, error) {
	state, err := document.State()
	if err != nil {
		return types.Hash{}, err
	}
	return state.Root(), nil
}

func Decode(input []byte) (Document, error) {
	decoder := codec.NewDecoder(input)
	document, err := DecodeFrom(decoder)
	if err != nil {
		return Document{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func DecodeFrom(decoder *codec.Decoder) (Document, error) {
	var document Document
	var err error

	document.Version, err = decoder.U16()
	if err != nil {
		return Document{}, err
	}
	document.NetworkID, err = decoder.U32()
	if err != nil {
		return Document{}, err
	}
	document.Timestamp, err = decoder.U64()
	if err != nil {
		return Document{}, err
	}
	target, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Document{}, err
	}
	copy(document.Target[:], target)
	document.BlockSubsidy, err = decoder.U64()
	if err != nil {
		return Document{}, err
	}
	count, err := decoder.ListLength(MaxAllocations)
	if err != nil {
		return Document{}, err
	}
	if count > decoder.Remaining()/resource.CanonicalSize {
		return Document{}, codec.ErrUnexpectedEOF
	}
	document.Allocations = make([]resource.Resource, count)
	for index := range document.Allocations {
		document.Allocations[index], err = resource.Decode(decoder)
		if err != nil {
			return Document{}, fmt.Errorf("allocation %d: %w", index, err)
		}
	}
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}
