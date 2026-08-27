package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const (
	HashSize       = sha256.Size
	AddressSize    = sha256.Size
	AssetIDSize    = sha256.Size
	ResourceIDSize = sha256.Size
)

const (
	DomainAddressEd25519 = "OMESH/address/ed25519/v1"
	DomainNativeAsset    = "OMESH/asset/native/v1"
	DomainTransactionID  = "OMESH/txid/v0"
	DomainTransactionSig = "OMESH/sign/transaction/v0"
	DomainResourceOutput = "OMESH/resource/output/v0"
	DomainStateEmpty     = "OMESH/state/empty/v0"
	DomainStateLeaf      = "OMESH/state/leaf/v0"
	DomainStateNode      = "OMESH/state/node/v0"
	DomainGenesisID      = "OMESH/genesis/id/v0"
	DomainBlockID        = "OMESH/block/id/v0"
	DomainBlockReward    = "OMESH/block/reward/v0"
	DomainTxRootEmpty    = "OMESH/block/tx/empty/v0"
	DomainTxRootLeaf     = "OMESH/block/tx/leaf/v0"
	DomainTxRootNode     = "OMESH/block/tx/node/v0"
	DomainReceiptEmpty   = "OMESH/block/receipt/empty/v0"
	DomainReceiptLeaf    = "OMESH/block/receipt/leaf/v0"
	DomainReceiptNode    = "OMESH/block/receipt/node/v0"
	DomainWorkID         = "OMESH/workgraph/work/id/v0"
	DomainInclusionEmpty = "OMESH/workgraph/inclusion/empty/v0"
	DomainInclusionLeaf  = "OMESH/workgraph/inclusion/leaf/v0"
	DomainInclusionNode  = "OMESH/workgraph/inclusion/node/v0"
	DomainWorkEmpty      = "OMESH/workgraph/root/empty/v0"
	DomainWorkLeaf       = "OMESH/workgraph/root/leaf/v0"
	DomainWorkNode       = "OMESH/workgraph/root/node/v0"
	DomainWorkPayload    = "OMESH/workgraph/payload/v0"
	DomainWorkPayloadV1  = "OMESH/workgraph/payload/v1"
	DomainWorkReward     = "OMESH/workgraph/reward/v0"
	DomainWorkFeeQueue   = "OMESH/workgraph/fee-queue/v0"
)

var (
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrAmountOverflow   = errors.New("amount overflow")
	ErrAmountUnderflow  = errors.New("amount underflow")
)

type Hash [HashSize]byte
type Address [AddressSize]byte
type AssetID [AssetIDSize]byte
type ResourceID [ResourceIDSize]byte

func DomainHash(domain string, payloads ...[]byte) Hash {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	for _, payload := range payloads {
		_, _ = h.Write(payload)
	}

	var result Hash
	copy(result[:], h.Sum(nil))
	return result
}

func AddressFromPublicKey(publicKey ed25519.PublicKey) (Address, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Address{}, ErrInvalidPublicKey
	}

	hash := DomainHash(DomainAddressEd25519, publicKey)
	return Address(hash), nil
}

func NativeAssetID() AssetID {
	return AssetID(DomainHash(DomainNativeAsset))
}

func AddAmount(left, right uint64) (uint64, error) {
	result := left + right
	if result < left {
		return 0, ErrAmountOverflow
	}
	return result, nil
}

func SubAmount(left, right uint64) (uint64, error) {
	if right > left {
		return 0, ErrAmountUnderflow
	}
	return left - right, nil
}

func (value Hash) IsZero() bool       { return value == Hash{} }
func (value Address) IsZero() bool    { return value == Address{} }
func (value AssetID) IsZero() bool    { return value == AssetID{} }
func (value ResourceID) IsZero() bool { return value == ResourceID{} }

func (value Hash) String() string       { return hex.EncodeToString(value[:]) }
func (value Address) String() string    { return hex.EncodeToString(value[:]) }
func (value AssetID) String() string    { return hex.EncodeToString(value[:]) }
func (value ResourceID) String() string { return hex.EncodeToString(value[:]) }

func CompareHash(left, right Hash) int {
	return bytes.Compare(left[:], right[:])
}

func CompareAddress(left, right Address) int {
	return bytes.Compare(left[:], right[:])
}

func CompareAssetID(left, right AssetID) int {
	return bytes.Compare(left[:], right[:])
}

func CompareResourceID(left, right ResourceID) int {
	return bytes.Compare(left[:], right[:])
}
