package outcome

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/guardvm"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0   uint16 = 0
	MaxInputs         = 256
	MaxOutputs        = 256
)

var (
	ErrUnsupportedVersion = errors.New("unsupported transaction version")
	ErrInputCount         = errors.New("invalid transaction input count")
	ErrOutputCount        = errors.New("invalid transaction output count")
	ErrInvalidPrivateKey  = errors.New("invalid Ed25519 private key")
	ErrInvalidSignature   = errors.New("invalid transaction signature")
	ErrOutputIndex        = errors.New("output index is out of range")
)

type Transaction struct {
	Version    uint16
	NetworkID  uint32
	Inputs     []resource.Ref
	Outputs    []resource.Output
	Guard      guardvm.Program
	Fee        uint64
	ValidUntil uint64
	Nonce      [32]byte
	SignerKey  [ed25519.PublicKeySize]byte
	Signature  [ed25519.SignatureSize]byte
}

func (transaction Transaction) ValidateBasic() error {
	if transaction.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, transaction.Version)
	}
	if len(transaction.Inputs) == 0 || len(transaction.Inputs) > MaxInputs {
		return fmt.Errorf("%w: %d", ErrInputCount, len(transaction.Inputs))
	}
	if len(transaction.Outputs) == 0 || len(transaction.Outputs) > MaxOutputs {
		return fmt.Errorf("%w: %d", ErrOutputCount, len(transaction.Outputs))
	}
	for index, input := range transaction.Inputs {
		if err := input.Validate(); err != nil {
			return fmt.Errorf("input %d: %w", index, err)
		}
	}
	for index, output := range transaction.Outputs {
		if err := output.Validate(); err != nil {
			return fmt.Errorf("output %d: %w", index, err)
		}
	}
	if err := transaction.Guard.Validate(); err != nil {
		return fmt.Errorf("guard program: %w", err)
	}
	return nil
}

func (transaction Transaction) encodeUnsignedTo(encoder *codec.Encoder) {
	encoder.U16(transaction.Version)
	encoder.U32(transaction.NetworkID)

	encoder.Uvarint(uint64(len(transaction.Inputs)))
	for _, input := range transaction.Inputs {
		input.EncodeTo(encoder)
	}

	encoder.Uvarint(uint64(len(transaction.Outputs)))
	for _, output := range transaction.Outputs {
		output.EncodeTo(encoder)
	}

	transaction.Guard.EncodeTo(encoder)
	encoder.U64(transaction.Fee)
	encoder.U64(transaction.ValidUntil)
	encoder.Fixed(transaction.Nonce[:])
	encoder.Fixed(transaction.SignerKey[:])
}

func (transaction Transaction) UnsignedBytes() []byte {
	encoder := codec.NewEncoder(256)
	transaction.encodeUnsignedTo(encoder)
	return encoder.Bytes()
}

func (transaction Transaction) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(320)
	transaction.encodeUnsignedTo(encoder)
	encoder.Fixed(transaction.Signature[:])
	return encoder.Bytes()
}

func (transaction Transaction) ID() (types.Hash, error) {
	if err := transaction.ValidateBasic(); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(types.DomainTransactionID, transaction.UnsignedBytes()), nil
}

func (transaction Transaction) SignatureMessage() (types.Hash, error) {
	id, err := transaction.ID()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(types.DomainTransactionSig, id[:]), nil
}

func (transaction *Transaction) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ErrInvalidPrivateKey
	}

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidPrivateKey
	}
	copy(transaction.SignerKey[:], publicKey)

	message, err := transaction.SignatureMessage()
	if err != nil {
		return err
	}
	copy(transaction.Signature[:], ed25519.Sign(privateKey, message[:]))
	return nil
}

func (transaction Transaction) VerifySignature() error {
	message, err := transaction.SignatureMessage()
	if err != nil {
		return err
	}
	if !ed25519.Verify(transaction.SignerKey[:], message[:], transaction.Signature[:]) {
		return ErrInvalidSignature
	}
	return nil
}

func (transaction Transaction) SignerAddress() (types.Address, error) {
	return types.AddressFromPublicKey(transaction.SignerKey[:])
}

func (transaction Transaction) DeriveOutputID(index int) (types.ResourceID, error) {
	if index < 0 || index >= len(transaction.Outputs) {
		return types.ResourceID{}, ErrOutputIndex
	}
	id, err := transaction.ID()
	if err != nil {
		return types.ResourceID{}, err
	}

	var encodedIndex [4]byte
	binary.BigEndian.PutUint32(encodedIndex[:], uint32(index))
	hash := types.DomainHash(types.DomainResourceOutput, id[:], encodedIndex[:])
	return types.ResourceID(hash), nil
}

func (transaction Transaction) MaterializeOutputs() ([]resource.Resource, error) {
	result := make([]resource.Resource, len(transaction.Outputs))
	for index, output := range transaction.Outputs {
		id, err := transaction.DeriveOutputID(index)
		if err != nil {
			return nil, err
		}
		result[index] = resource.Resource{
			ID:          id,
			Version:     resource.Version0,
			Owner:       output.Owner,
			Asset:       output.Asset,
			Amount:      output.Amount,
			SpendAfter:  output.SpendAfter,
			PolicyHash:  output.PolicyHash,
			PayloadHash: output.PayloadHash,
		}
	}
	return result, nil
}

func Decode(input []byte) (Transaction, error) {
	decoder := codec.NewDecoder(input)
	transaction, err := DecodeFrom(decoder)
	if err != nil {
		return Transaction{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Transaction{}, err
	}
	return transaction, nil
}

func DecodeFrom(decoder *codec.Decoder) (Transaction, error) {
	var transaction Transaction
	var err error

	transaction.Version, err = decoder.U16()
	if err != nil {
		return Transaction{}, err
	}
	transaction.NetworkID, err = decoder.U32()
	if err != nil {
		return Transaction{}, err
	}

	inputCount, err := decoder.ListLength(MaxInputs)
	if err != nil {
		return Transaction{}, err
	}
	transaction.Inputs = make([]resource.Ref, inputCount)
	for index := range transaction.Inputs {
		transaction.Inputs[index], err = resource.DecodeRef(decoder)
		if err != nil {
			return Transaction{}, fmt.Errorf("input %d: %w", index, err)
		}
	}

	outputCount, err := decoder.ListLength(MaxOutputs)
	if err != nil {
		return Transaction{}, err
	}
	transaction.Outputs = make([]resource.Output, outputCount)
	for index := range transaction.Outputs {
		transaction.Outputs[index], err = resource.DecodeOutput(decoder)
		if err != nil {
			return Transaction{}, fmt.Errorf("output %d: %w", index, err)
		}
	}

	transaction.Guard, err = guardvm.DecodeProgram(decoder)
	if err != nil {
		return Transaction{}, fmt.Errorf("guard program: %w", err)
	}
	transaction.Fee, err = decoder.U64()
	if err != nil {
		return Transaction{}, err
	}
	transaction.ValidUntil, err = decoder.U64()
	if err != nil {
		return Transaction{}, err
	}

	nonce, err := decoder.Fixed(len(transaction.Nonce))
	if err != nil {
		return Transaction{}, err
	}
	copy(transaction.Nonce[:], nonce)

	publicKey, err := decoder.Fixed(ed25519.PublicKeySize)
	if err != nil {
		return Transaction{}, err
	}
	copy(transaction.SignerKey[:], publicKey)

	signature, err := decoder.Fixed(ed25519.SignatureSize)
	if err != nil {
		return Transaction{}, err
	}
	copy(transaction.Signature[:], signature)

	if err := transaction.ValidateBasic(); err != nil {
		return Transaction{}, err
	}
	return transaction, nil
}
