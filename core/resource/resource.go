package resource

import (
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0      uint64 = 0
	CanonicalSize        = types.ResourceIDSize + 8 + types.AddressSize + types.AssetIDSize + 8 + 8 + types.HashSize + types.HashSize
)

var (
	ErrUnsupportedVersion = errors.New("unsupported resource version")
	ErrZeroResourceID     = errors.New("resource identifier is zero")
	ErrZeroOwner          = errors.New("resource owner is zero")
	ErrZeroAsset          = errors.New("resource asset is zero")
	ErrZeroAmount         = errors.New("resource amount is zero")
)

type Ref struct {
	ID      types.ResourceID
	Version uint64
}

type Output struct {
	Owner       types.Address
	Asset       types.AssetID
	Amount      uint64
	SpendAfter  uint64
	PolicyHash  types.Hash
	PayloadHash types.Hash
}

type Resource struct {
	ID          types.ResourceID
	Version     uint64
	Owner       types.Address
	Asset       types.AssetID
	Amount      uint64
	SpendAfter  uint64
	PolicyHash  types.Hash
	PayloadHash types.Hash
}

func (ref Ref) Validate() error {
	if ref.ID.IsZero() {
		return ErrZeroResourceID
	}
	if ref.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, ref.Version)
	}
	return nil
}

func (output Output) Validate() error {
	if output.Owner.IsZero() {
		return ErrZeroOwner
	}
	if output.Asset.IsZero() {
		return ErrZeroAsset
	}
	if output.Amount == 0 {
		return ErrZeroAmount
	}
	return nil
}

func (value Resource) Validate() error {
	if value.ID.IsZero() {
		return ErrZeroResourceID
	}
	if value.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, value.Version)
	}
	return Output{
		Owner:       value.Owner,
		Asset:       value.Asset,
		Amount:      value.Amount,
		SpendAfter:  value.SpendAfter,
		PolicyHash:  value.PolicyHash,
		PayloadHash: value.PayloadHash,
	}.Validate()
}

func (ref Ref) EncodeTo(encoder *codec.Encoder) {
	encoder.Fixed(ref.ID[:])
	encoder.U64(ref.Version)
}

func DecodeRef(decoder *codec.Decoder) (Ref, error) {
	var ref Ref

	id, err := decoder.Fixed(types.ResourceIDSize)
	if err != nil {
		return Ref{}, err
	}
	copy(ref.ID[:], id)

	ref.Version, err = decoder.U64()
	if err != nil {
		return Ref{}, err
	}
	if err := ref.Validate(); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

func (output Output) EncodeTo(encoder *codec.Encoder) {
	encoder.Fixed(output.Owner[:])
	encoder.Fixed(output.Asset[:])
	encoder.U64(output.Amount)
	encoder.U64(output.SpendAfter)
	encoder.Fixed(output.PolicyHash[:])
	encoder.Fixed(output.PayloadHash[:])
}

func DecodeOutput(decoder *codec.Decoder) (Output, error) {
	var output Output

	owner, err := decoder.Fixed(types.AddressSize)
	if err != nil {
		return Output{}, err
	}
	copy(output.Owner[:], owner)

	asset, err := decoder.Fixed(types.AssetIDSize)
	if err != nil {
		return Output{}, err
	}
	copy(output.Asset[:], asset)

	output.Amount, err = decoder.U64()
	if err != nil {
		return Output{}, err
	}
	output.SpendAfter, err = decoder.U64()
	if err != nil {
		return Output{}, err
	}

	policyHash, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Output{}, err
	}
	copy(output.PolicyHash[:], policyHash)

	payloadHash, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Output{}, err
	}
	copy(output.PayloadHash[:], payloadHash)

	if err := output.Validate(); err != nil {
		return Output{}, err
	}
	return output, nil
}

func (value Resource) EncodeTo(encoder *codec.Encoder) {
	encoder.Fixed(value.ID[:])
	encoder.U64(value.Version)
	Output{
		Owner:       value.Owner,
		Asset:       value.Asset,
		Amount:      value.Amount,
		SpendAfter:  value.SpendAfter,
		PolicyHash:  value.PolicyHash,
		PayloadHash: value.PayloadHash,
	}.EncodeTo(encoder)
}

func (value Resource) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(CanonicalSize)
	value.EncodeTo(encoder)
	return encoder.Bytes()
}

func Decode(decoder *codec.Decoder) (Resource, error) {
	var value Resource

	id, err := decoder.Fixed(types.ResourceIDSize)
	if err != nil {
		return Resource{}, err
	}
	copy(value.ID[:], id)

	value.Version, err = decoder.U64()
	if err != nil {
		return Resource{}, err
	}

	output, err := DecodeOutput(decoder)
	if err != nil {
		return Resource{}, err
	}
	value.Owner = output.Owner
	value.Asset = output.Asset
	value.Amount = output.Amount
	value.SpendAfter = output.SpendAfter
	value.PolicyHash = output.PolicyHash
	value.PayloadHash = output.PayloadHash

	if err := value.Validate(); err != nil {
		return Resource{}, err
	}
	return value, nil
}
