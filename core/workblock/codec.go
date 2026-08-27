package workblock

import (
	"fmt"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

const (
	MaxHeaderCanonicalBytes = 2 + workgraph.MaxShareCanonicalBytes + 5*types.HashSize + 8
	MaxCanonicalBytes       = legacyblock.MaxCanonicalBytes + workgraph.MaxBatchCanonicalBytes + 1_024
)

func (header Header) ValidateBasic() error {
	if header.Version != Version1 {
		return ErrParameters
	}
	if err := header.Seal.ValidateBasic(); err != nil {
		return err
	}
	payloadRoot, err := workgraph.PayloadCommitmentV1(
		header.TxRoot, header.ReceiptRoot, header.StateRoot, header.PreviousWorkRoot,
		header.FeeQueueRoot, header.FeeAward,
	)
	if err != nil || payloadRoot != header.Seal.PayloadRoot {
		return ErrRoot
	}
	return nil
}

func (header Header) EncodeTo(encoder *codec.Encoder) {
	encoder.U16(header.Version)
	header.Seal.EncodeTo(encoder)
	encoder.Fixed(header.TxRoot[:])
	encoder.Fixed(header.ReceiptRoot[:])
	encoder.Fixed(header.StateRoot[:])
	encoder.Fixed(header.PreviousWorkRoot[:])
	encoder.Fixed(header.FeeQueueRoot[:])
	encoder.U64(header.FeeAward)
}

func (header Header) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(MaxHeaderCanonicalBytes)
	header.EncodeTo(encoder)
	return encoder.Bytes()
}

// ID is the unified WorkSeal ID. The roots and fee award are transitively committed by
// Seal.PayloadRoot, so hashing a second header preimage would break the rule
// that a lucky weak share is already a valid anchor proof.
func (header Header) ID() (types.Hash, error) {
	if err := header.ValidateBasic(); err != nil {
		return types.Hash{}, err
	}
	return header.Seal.ID()
}

func decodeHeader(decoder *codec.Decoder) (Header, error) {
	version, err := decoder.U16()
	if err != nil {
		return Header{}, err
	}
	seal, err := workgraph.DecodeFrom(decoder)
	if err != nil {
		return Header{}, err
	}
	header := Header{Version: version, Seal: seal}
	for _, destination := range []*types.Hash{
		&header.TxRoot, &header.ReceiptRoot, &header.StateRoot, &header.PreviousWorkRoot,
		&header.FeeQueueRoot,
	} {
		value, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return Header{}, err
		}
		copy(destination[:], value)
	}
	header.FeeAward, err = decoder.U64()
	if err != nil {
		return Header{}, err
	}
	if err := header.ValidateBasic(); err != nil {
		return Header{}, err
	}
	return header, nil
}

func DecodeHeader(input []byte) (Header, error) {
	if len(input) == 0 || len(input) > MaxHeaderCanonicalBytes {
		return Header{}, ErrParameters
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
	if len(block.Transactions) > legacyblock.MaxTransactions {
		return legacyblock.ErrTransactionCount
	}
	for index, transaction := range block.Transactions {
		if err := transaction.ValidateBasic(); err != nil {
			return fmt.Errorf("transaction %d: %w", index, err)
		}
	}
	txRoot, err := legacyblock.TransactionRoot(block.Transactions)
	if err != nil {
		return err
	}
	if txRoot != block.Header.TxRoot {
		return ErrRoot
	}
	if _, err := workgraph.EncodeShares(block.Shares); err != nil {
		return err
	}
	if len(block.CanonicalBytes()) > MaxCanonicalBytes {
		return legacyblock.ErrBlockSize
	}
	return nil
}

func (block Block) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(512 + len(block.Transactions)*384 + len(block.Shares)*224)
	block.Header.EncodeTo(encoder)
	encoder.Uvarint(uint64(len(block.Transactions)))
	for _, transaction := range block.Transactions {
		encoder.Fixed(transaction.CanonicalBytes())
	}
	encoder.Uvarint(uint64(len(block.Shares)))
	for _, share := range block.Shares {
		share.EncodeTo(encoder)
	}
	return encoder.Bytes()
}

func Decode(input []byte) (Block, error) {
	if len(input) == 0 || len(input) > MaxCanonicalBytes {
		return Block{}, legacyblock.ErrBlockSize
	}
	decoder := codec.NewDecoder(input)
	header, err := decodeHeader(decoder)
	if err != nil {
		return Block{}, err
	}
	transactionCount, err := decoder.ListLength(legacyblock.MaxTransactions)
	if err != nil {
		return Block{}, err
	}
	result := Block{Header: header, Transactions: make([]outcome.Transaction, transactionCount)}
	for index := range result.Transactions {
		result.Transactions[index], err = outcome.DecodeFrom(decoder)
		if err != nil {
			return Block{}, fmt.Errorf("transaction %d: %w", index, err)
		}
	}
	shareCount, err := decoder.ListLength(workgraph.MaxShares)
	if err != nil {
		return Block{}, err
	}
	result.Shares = make([]workgraph.Share, shareCount)
	for index := range result.Shares {
		result.Shares[index], err = workgraph.DecodeFrom(decoder)
		if err != nil {
			return Block{}, fmt.Errorf("share %d: %w", index, err)
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
