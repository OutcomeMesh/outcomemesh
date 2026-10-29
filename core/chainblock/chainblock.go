package chainblock

import (
	"encoding/binary"
	"errors"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
)

const (
	MaxCanonicalBytes       = workblock.MaxCanonicalBytes
	MaxHeaderCanonicalBytes = workblock.MaxHeaderCanonicalBytes
)

var (
	ErrBoundary = errors.New("block version is invalid at activation boundary")
	ErrEncoding = errors.New("invalid versioned chain encoding")
)

// Block is a strict tagged union. CanonicalBytes returns the unchanged
// version-specific consensus encoding; its leading uint16 selects the decoder.
type Block struct {
	version uint16
	legacy  legacyblock.Block
	work    workblock.Block
}

// Legacy validates and detaches one standalone block without applying an
// activation-height rule.
func Legacy(candidate legacyblock.Block) (Block, error) {
	if err := candidate.ValidateBasic(); err != nil {
		return Block{}, err
	}
	cloned, err := legacyblock.Decode(candidate.CanonicalBytes())
	if err != nil {
		return Block{}, err
	}
	return Block{version: cloned.Header.Version, legacy: cloned}, nil
}

// Work validates and detaches one WorkGraph block without applying an
// activation-height rule.
func Work(candidate workblock.Block) (Block, error) {
	if err := candidate.ValidateBasic(); err != nil {
		return Block{}, err
	}
	cloned, err := workblock.Decode(candidate.CanonicalBytes())
	if err != nil {
		return Block{}, err
	}
	return Block{version: cloned.Header.Version, work: cloned}, nil
}

// DecodeAny dispatches solely from the canonical leading version. Callers that
// admit blocks into a chain must separately apply Validate with their configured
// activation height and enforce the scheduled commitment in their executor.
func DecodeAny(input []byte) (Block, error) {
	if len(input) < 2 || len(input) > MaxCanonicalBytes {
		return Block{}, ErrEncoding
	}
	switch binary.BigEndian.Uint16(input[:2]) {
	case legacyblock.Version0, legacyblock.Version2:
		candidate, err := legacyblock.Decode(input)
		if err != nil {
			return Block{}, err
		}
		return Block{version: candidate.Header.Version, legacy: candidate}, nil
	case workblock.Version1, workblock.Version3:
		candidate, err := workblock.Decode(input)
		if err != nil {
			return Block{}, err
		}
		return Block{version: candidate.Header.Version, work: candidate}, nil
	default:
		return Block{}, ErrEncoding
	}
}

// Decode combines canonical version dispatch with the activation-height rule.
func Decode(input []byte, activationHeight uint64) (Block, error) {
	candidate, err := DecodeAny(input)
	if err != nil {
		return Block{}, err
	}
	if err := candidate.Validate(activationHeight); err != nil {
		return Block{}, err
	}
	return candidate, nil
}

func (candidate Block) ValidateBasic() error {
	switch candidate.version {
	case legacyblock.Version0, legacyblock.Version2:
		return candidate.legacy.ValidateBasic()
	case workblock.Version1, workblock.Version3:
		return candidate.work.ValidateBasic()
	default:
		return ErrEncoding
	}
}

func (candidate Block) Validate(activationHeight uint64) error {
	if activationHeight == 0 {
		return ErrBoundary
	}
	if err := candidate.ValidateBasic(); err != nil {
		return err
	}
	switch candidate.version {
	case legacyblock.Version0, legacyblock.Version2:
		if candidate.legacy.Header.Height >= activationHeight {
			return ErrBoundary
		}
	case workblock.Version1, workblock.Version3:
		if candidate.work.Header.Seal.Height < activationHeight {
			return ErrBoundary
		}
	default:
		return ErrEncoding
	}
	return nil
}

func (candidate Block) Version() uint16 { return candidate.version }

func (candidate Block) Height() uint64 {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.Header.Height
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Header.Seal.Height
	}
	return 0
}

func (candidate Block) ParentID() types.Hash {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.Header.Parent
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Header.Seal.AnchorParent
	}
	return types.Hash{}
}

func (candidate Block) ID() (types.Hash, error) {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.Header.ID()
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Header.ID()
	}
	return types.Hash{}, ErrEncoding
}

func (candidate Block) Header() Header {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		result, _ := LegacyHeader(candidate.legacy.Header)
		return result
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		result, _ := WorkHeader(candidate.work.Header)
		return result
	}
	return Header{}
}

func (candidate Block) CanonicalBytes() []byte {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.CanonicalBytes()
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.CanonicalBytes()
	}
	return nil
}

func (candidate Block) LegacyBlock() (legacyblock.Block, bool) {
	if candidate.version != legacyblock.Version0 && candidate.version != legacyblock.Version2 {
		return legacyblock.Block{}, false
	}
	cloned, err := legacyblock.Decode(candidate.legacy.CanonicalBytes())
	return cloned, err == nil
}

func (candidate Block) WorkBlock() (workblock.Block, bool) {
	if candidate.version != workblock.Version1 && candidate.version != workblock.Version3 {
		return workblock.Block{}, false
	}
	cloned, err := workblock.Decode(candidate.work.CanonicalBytes())
	return cloned, err == nil
}

// Header is the header-only counterpart of Block. Its representation is also
// detached so callers cannot mutate WorkSeal parent slices through an accessor.
type Header struct {
	version uint16
	legacy  legacyblock.Header
	work    workblock.Header
}

func LegacyHeader(candidate legacyblock.Header) (Header, error) {
	if err := candidate.ValidateBasic(); err != nil {
		return Header{}, err
	}
	cloned, err := legacyblock.DecodeHeader(candidate.CanonicalBytes())
	if err != nil {
		return Header{}, err
	}
	return Header{version: cloned.Version, legacy: cloned}, nil
}

func WorkHeader(candidate workblock.Header) (Header, error) {
	if err := candidate.ValidateBasic(); err != nil {
		return Header{}, err
	}
	cloned, err := workblock.DecodeHeader(candidate.CanonicalBytes())
	if err != nil {
		return Header{}, err
	}
	return Header{version: cloned.Version, work: cloned}, nil
}

func DecodeHeaderAny(input []byte) (Header, error) {
	if len(input) < 2 || len(input) > MaxHeaderCanonicalBytes {
		return Header{}, ErrEncoding
	}
	switch binary.BigEndian.Uint16(input[:2]) {
	case legacyblock.Version0, legacyblock.Version2:
		candidate, err := legacyblock.DecodeHeader(input)
		if err != nil {
			return Header{}, err
		}
		return Header{version: candidate.Version, legacy: candidate}, nil
	case workblock.Version1, workblock.Version3:
		candidate, err := workblock.DecodeHeader(input)
		if err != nil {
			return Header{}, err
		}
		return Header{version: candidate.Version, work: candidate}, nil
	default:
		return Header{}, ErrEncoding
	}
}

func DecodeHeader(input []byte, activationHeight uint64) (Header, error) {
	candidate, err := DecodeHeaderAny(input)
	if err != nil {
		return Header{}, err
	}
	if err := candidate.Validate(activationHeight); err != nil {
		return Header{}, err
	}
	return candidate, nil
}

func (candidate Header) ValidateBasic() error {
	switch candidate.version {
	case legacyblock.Version0, legacyblock.Version2:
		return candidate.legacy.ValidateBasic()
	case workblock.Version1, workblock.Version3:
		return candidate.work.ValidateBasic()
	default:
		return ErrEncoding
	}
}

func (candidate Header) Validate(activationHeight uint64) error {
	if activationHeight == 0 {
		return ErrBoundary
	}
	if err := candidate.ValidateBasic(); err != nil {
		return err
	}
	if (candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2) && candidate.legacy.Height >= activationHeight {
		return ErrBoundary
	}
	if (candidate.version == workblock.Version1 || candidate.version == workblock.Version3) && candidate.work.Seal.Height < activationHeight {
		return ErrBoundary
	}
	return nil
}

func (candidate Header) Version() uint16 { return candidate.version }

func (candidate Header) Height() uint64 {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.Height
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Seal.Height
	}
	return 0
}

func (candidate Header) ParentID() types.Hash {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.Parent
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Seal.AnchorParent
	}
	return types.Hash{}
}

func (candidate Header) NetworkID() uint32 {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.NetworkID
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Seal.NetworkID
	}
	return 0
}

func (candidate Header) Timestamp() uint64 {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.Timestamp
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Seal.Timestamp
	}
	return 0
}

func (candidate Header) Target() types.Hash {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.Target
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.Seal.Target
	}
	return types.Hash{}
}

func (candidate Header) StateRoot() types.Hash {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.StateRoot
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.StateRoot
	}
	return types.Hash{}
}

func (candidate Header) ID() (types.Hash, error) {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.ID()
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.ID()
	}
	return types.Hash{}, ErrEncoding
}

func (candidate Header) CanonicalBytes() []byte {
	if candidate.version == legacyblock.Version0 || candidate.version == legacyblock.Version2 {
		return candidate.legacy.CanonicalBytes()
	}
	if candidate.version == workblock.Version1 || candidate.version == workblock.Version3 {
		return candidate.work.CanonicalBytes()
	}
	return nil
}

func (candidate Header) LegacyHeader() (legacyblock.Header, bool) {
	if candidate.version != legacyblock.Version0 && candidate.version != legacyblock.Version2 {
		return legacyblock.Header{}, false
	}
	cloned, err := legacyblock.DecodeHeader(candidate.legacy.CanonicalBytes())
	return cloned, err == nil
}

func (candidate Header) WorkHeader() (workblock.Header, bool) {
	if candidate.version != workblock.Version1 && candidate.version != workblock.Version3 {
		return workblock.Header{}, false
	}
	cloned, err := workblock.DecodeHeader(candidate.work.CanonicalBytes())
	return cloned, err == nil
}
