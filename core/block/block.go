package block

import (
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/merkle"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0             uint16 = 0
	MaxTransactions             = 4_096
	MaxCanonicalBytes           = 8 << 20
	HeaderCanonicalBytes        = 222
)

var (
	ErrUnsupportedVersion = errors.New("unsupported block version")
	ErrNetworkID          = errors.New("block network identifier is zero")
	ErrHeight             = errors.New("block height is zero")
	ErrTimestamp          = errors.New("block timestamp is zero")
	ErrTarget             = errors.New("block proof-of-work target is zero")
	ErrMiner              = errors.New("block miner address is zero")
	ErrTransactionCount   = errors.New("invalid block transaction count")
	ErrBlockSize          = errors.New("block exceeds canonical size limit")
	ErrTransactionRoot    = errors.New("block transaction root mismatch")
	ErrReceiptVersion     = errors.New("unsupported receipt version")
)

type Header struct {
	Version     uint16
	NetworkID   uint32
	Height      uint64
	Parent      types.Hash
	Timestamp   uint64
	Target      types.Hash
	TxRoot      types.Hash
	ReceiptRoot types.Hash
	StateRoot   types.Hash
	Miner       types.Address
	Nonce       uint64
}

type Block struct {
	Header       Header
	Transactions []outcome.Transaction
}

type Receipt struct {
	Version       uint16
	TxID          types.Hash
	PostStateRoot types.Hash
	Fee           uint64
}

func (header Header) ValidateBasic() error {
	if header.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, header.Version)
	}
	if header.NetworkID == 0 {
		return ErrNetworkID
	}
	if header.Height == 0 {
		return ErrHeight
	}
	if header.Timestamp == 0 {
		return ErrTimestamp
	}
	if header.Target.IsZero() {
		return ErrTarget
	}
	if header.Miner.IsZero() {
		return ErrMiner
	}
	return nil
}

func (header Header) EncodeTo(encoder *codec.Encoder) {
	encoder.U16(header.Version)
	encoder.U32(header.NetworkID)
	encoder.U64(header.Height)
	encoder.Fixed(header.Parent[:])
	encoder.U64(header.Timestamp)
	encoder.Fixed(header.Target[:])
	encoder.Fixed(header.TxRoot[:])
	encoder.Fixed(header.ReceiptRoot[:])
	encoder.Fixed(header.StateRoot[:])
	encoder.Fixed(header.Miner[:])
	encoder.U64(header.Nonce)
}

func (header Header) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(HeaderCanonicalBytes)
	header.EncodeTo(encoder)
	return encoder.Bytes()
}

func (header Header) ID() (types.Hash, error) {
	if err := header.ValidateBasic(); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(types.DomainBlockID, header.CanonicalBytes()), nil
}

func decodeHeader(decoder *codec.Decoder) (Header, error) {
	var header Header
	var err error
	header.Version, err = decoder.U16()
	if err != nil {
		return Header{}, err
	}
	header.NetworkID, err = decoder.U32()
	if err != nil {
		return Header{}, err
	}
	header.Height, err = decoder.U64()
	if err != nil {
		return Header{}, err
	}

	parent, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Header{}, err
	}
	copy(header.Parent[:], parent)
	header.Timestamp, err = decoder.U64()
	if err != nil {
		return Header{}, err
	}

	target, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Header{}, err
	}
	copy(header.Target[:], target)
	txRoot, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Header{}, err
	}
	copy(header.TxRoot[:], txRoot)
	receiptRoot, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Header{}, err
	}
	copy(header.ReceiptRoot[:], receiptRoot)
	stateRoot, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Header{}, err
	}
	copy(header.StateRoot[:], stateRoot)
	miner, err := decoder.Fixed(types.AddressSize)
	if err != nil {
		return Header{}, err
	}
	copy(header.Miner[:], miner)
	header.Nonce, err = decoder.U64()
	if err != nil {
		return Header{}, err
	}
	if err := header.ValidateBasic(); err != nil {
		return Header{}, err
	}
	return header, nil
}

// DecodeHeader decodes exactly one canonical header. It is used by the
// header-first network protocol without accepting a block body or trailing
// bytes.
func DecodeHeader(input []byte) (Header, error) {
	if len(input) != HeaderCanonicalBytes {
		return Header{}, ErrBlockSize
	}
	decoder := codec.NewDecoder(input)
	header, err := decodeHeader(decoder)
	if err != nil {
		return Header{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Header{}, err
	}
	return header, nil
}

func (block Block) ValidateBasic() error {
	if err := block.Header.ValidateBasic(); err != nil {
		return err
	}
	if len(block.Transactions) > MaxTransactions {
		return fmt.Errorf("%w: %d", ErrTransactionCount, len(block.Transactions))
	}
	for index, transaction := range block.Transactions {
		if err := transaction.ValidateBasic(); err != nil {
			return fmt.Errorf("transaction %d: %w", index, err)
		}
	}
	root, err := TransactionRoot(block.Transactions)
	if err != nil {
		return err
	}
	if root != block.Header.TxRoot {
		return fmt.Errorf("%w: got %s want %s", ErrTransactionRoot, block.Header.TxRoot, root)
	}
	if len(block.CanonicalBytes()) > MaxCanonicalBytes {
		return ErrBlockSize
	}
	return nil
}

func (block Block) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(256 + len(block.Transactions)*384)
	block.Header.EncodeTo(encoder)
	encoder.Uvarint(uint64(len(block.Transactions)))
	for _, transaction := range block.Transactions {
		encoder.Fixed(transaction.CanonicalBytes())
	}
	return encoder.Bytes()
}

func Decode(input []byte) (Block, error) {
	if len(input) > MaxCanonicalBytes {
		return Block{}, ErrBlockSize
	}
	decoder := codec.NewDecoder(input)
	header, err := decodeHeader(decoder)
	if err != nil {
		return Block{}, err
	}
	count, err := decoder.ListLength(MaxTransactions)
	if err != nil {
		return Block{}, err
	}
	result := Block{Header: header, Transactions: make([]outcome.Transaction, count)}
	for index := range result.Transactions {
		result.Transactions[index], err = outcome.DecodeFrom(decoder)
		if err != nil {
			return Block{}, fmt.Errorf("transaction %d: %w", index, err)
		}
	}
	if err := decoder.Finish(); err != nil {
		return Block{}, err
	}
	if err := result.ValidateBasic(); err != nil {
		return Block{}, err
	}
	return result, nil
}

func TransactionRoot(transactions []outcome.Transaction) (types.Hash, error) {
	payloads := make([][]byte, len(transactions))
	for index, transaction := range transactions {
		id, err := transaction.ID()
		if err != nil {
			return types.Hash{}, fmt.Errorf("transaction %d: %w", index, err)
		}
		payloads[index] = append([]byte(nil), id[:]...)
	}
	return merkle.Root(payloads, types.DomainTxRootEmpty, types.DomainTxRootLeaf, types.DomainTxRootNode), nil
}

func (receipt Receipt) Validate() error {
	if receipt.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrReceiptVersion, receipt.Version)
	}
	return nil
}

func (receipt Receipt) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(74)
	encoder.U16(receipt.Version)
	encoder.Fixed(receipt.TxID[:])
	encoder.Fixed(receipt.PostStateRoot[:])
	encoder.U64(receipt.Fee)
	return encoder.Bytes()
}

func ReceiptRoot(receipts []Receipt) (types.Hash, error) {
	payloads := make([][]byte, len(receipts))
	for index, receipt := range receipts {
		if err := receipt.Validate(); err != nil {
			return types.Hash{}, fmt.Errorf("receipt %d: %w", index, err)
		}
		payloads[index] = receipt.CanonicalBytes()
	}
	return merkle.Root(payloads, types.DomainReceiptEmpty, types.DomainReceiptLeaf, types.DomainReceiptNode), nil
}
