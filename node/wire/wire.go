package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/storage"
)

const (
	Version0                 uint16 = 0
	Version1                 uint16 = 1
	MaxLocators                     = 32
	MaxBlocksPerRequest             = 128
	MaxHeadersPerRequest            = 128
	MaxPeerRecords                  = 64
	MaxPeerRecordBytes              = 2_048
	MaxSnapshotManifestBytes        = 128
	MaxSnapshotChunkBytes           = 128 * 1024
	MaxShareInventoryIDs            = 1_024
	MaxSharesPerMessage             = 256
	MinWorkFrameBodyBytes           = 512
	MaxWorkFrameBodyBytes           = 96 * 1024
	MaxPayloadBytes                 = block.MaxCanonicalBytes
	MaxFrameBodyBytes               = MaxPayloadBytes + 1
)

const WorkFeatureShareRelayV1 uint64 = 1 << 0

var (
	ErrFrameSize        = errors.New("invalid wire frame size")
	ErrMessageType      = errors.New("unknown wire message type")
	ErrMessage          = errors.New("invalid wire message")
	ErrUnsupported      = errors.New("unsupported wire version")
	ErrDuplicateLocator = errors.New("duplicate block locator")
)

type Type uint8

const (
	TypeStatus Type = iota + 1
	TypeGetBlocks
	TypeBlock
	TypeTransaction
	TypeBatchDone
	TypeResult
	TypeGetPeers
	TypePeers
	TypeGetSnapshot
	TypeSnapshotManifest
	TypeSnapshotChunk
	TypeSnapshotDone
	TypeGetHeaders
	TypeHeaders
	TypeShareInventory
	TypeGetShares
	TypeShares
	TypeWorkHello
	TypeShareResult
)

type ResultCode uint16

const (
	ResultAccepted ResultCode = iota + 1
	ResultRejected
)

type Message interface {
	messageType() Type
}

type Status struct {
	Version        uint16
	NetworkID      uint32
	GenesisID      types.Hash
	TipID          types.Hash
	StateRoot      types.Hash
	TipHeight      uint64
	CumulativeWork []byte
	MaxFrameBytes  uint32
}

func (Status) messageType() Type { return TypeStatus }

type GetBlocks struct {
	Version  uint16
	Locators []types.Hash
	Limit    uint16
}

func (GetBlocks) messageType() Type { return TypeGetBlocks }

type GetHeaders struct {
	Version  uint16
	Locators []types.Hash
	Limit    uint16
}

func (GetHeaders) messageType() Type { return TypeGetHeaders }

// Headers carries one bounded, contiguous canonical header batch and the
// responder's tip at the instant it assembled that batch.
type Headers struct {
	Version uint16
	Values  []block.Header
	TipID   types.Hash
}

func (Headers) messageType() Type { return TypeHeaders }

type Block struct {
	Value block.Block
}

func (Block) messageType() Type { return TypeBlock }

type Transaction struct {
	Value outcome.Transaction
}

func (Transaction) messageType() Type { return TypeTransaction }

type BatchDone struct {
	Version uint16
	TipID   types.Hash
}

func (BatchDone) messageType() Type { return TypeBatchDone }

type Result struct {
	Version  uint16
	Code     ResultCode
	ObjectID types.Hash
}

func (Result) messageType() Type { return TypeResult }

type GetPeers struct {
	Version uint16
	Limit   uint16
}

func (GetPeers) messageType() Type { return TypeGetPeers }

// Peers carries opaque signed advertisements. Their signature, network,
// lifetime, and anti-replay checks belong to node/discovery rather than the
// framing layer.
type Peers struct {
	Version uint16
	Records [][]byte
}

func (Peers) messageType() Type { return TypePeers }

type GetSnapshot struct {
	Version uint16
	TipID   types.Hash
}

func (GetSnapshot) messageType() Type { return TypeGetSnapshot }

type SnapshotManifest struct {
	Version uint16
	Value   []byte
}

func (SnapshotManifest) messageType() Type { return TypeSnapshotManifest }

type SnapshotChunk struct {
	Version uint16
	Value   []byte
}

func (SnapshotChunk) messageType() Type { return TypeSnapshotChunk }

type SnapshotDone struct {
	Version uint16
	TipID   types.Hash
}

func (SnapshotDone) messageType() Type { return TypeSnapshotDone }

type ShareContext struct {
	NetworkID    uint32
	Height       uint64
	AnchorParent types.Hash
	AnchorTarget types.Hash
	PayloadRoot  types.Hash
}

// ShareInventory announces sorted Work IDs without flooding share bodies.
type ShareInventory struct {
	Version uint16
	Context ShareContext
	IDs     []types.Hash
}

func (ShareInventory) messageType() Type { return TypeShareInventory }

// GetShares requests only missing bodies from one exact mining context.
type GetShares struct {
	Version uint16
	Context ShareContext
	IDs     []types.Hash
}

func (GetShares) messageType() Type { return TypeGetShares }

// Shares carries a bounded ID-sorted response. Full context/PoW/DAG admission
// remains the receiver's responsibility.
type Shares struct {
	Version uint16
	Context ShareContext
	Values  []workgraph.Share
}

func (Shares) messageType() Type { return TypeShares }

// WorkHello negotiates the isolated WorkGraph relay protocol. Both peers must
// advertise the same mining context; count and frame limits are intersected.
type WorkHello struct {
	Version        uint16
	Context        ShareContext
	Features       uint64
	MaxFrameBytes  uint32
	MaxInventory   uint16
	MaxShareBodies uint16
}

func (WorkHello) messageType() Type { return TypeWorkHello }

// ShareResult terminates one inventory relay and accounts for every requested
// unknown body, including bodies withheld or rejected by full pool admission.
type ShareResult struct {
	Version  uint16
	Context  ShareContext
	Accepted uint16
	Rejected uint16
}

func (ShareResult) messageType() Type { return TypeShareResult }

func WriteMessage(writer io.Writer, message Message) error {
	payload, err := encodePayload(message)
	if err != nil {
		return err
	}
	if len(payload) > MaxPayloadBytes {
		return ErrFrameSize
	}
	bodyLength := 1 + len(payload)
	var header [5]byte
	binary.BigEndian.PutUint32(header[:4], uint32(bodyLength))
	header[4] = byte(message.messageType())
	if err := writeFull(writer, header[:]); err != nil {
		return err
	}
	return writeFull(writer, payload)
}

func ReadMessage(reader io.Reader) (Message, error) {
	return ReadMessageLimit(reader, MaxFrameBodyBytes)
}

// ReadMessageLimit rejects a frame from its four-byte header before allocating
// its body. Subprotocols use this to negotiate limits below the global block
// frame ceiling.
func ReadMessageLimit(reader io.Reader, maximum uint32) (Message, error) {
	if maximum == 0 || maximum > uint32(MaxFrameBodyBytes) {
		return nil, ErrFrameSize
	}
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length == 0 || length > maximum {
		return nil, ErrFrameSize
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return DecodeFrameBody(body)
}

// DecodeFrameBody decodes the bytes after the four-byte frame length and is
// exported so the exact untrusted parser surface can be fuzzed.
func DecodeFrameBody(body []byte) (Message, error) {
	if len(body) == 0 || len(body) > MaxFrameBodyBytes {
		return nil, ErrFrameSize
	}
	payload := body[1:]
	switch Type(body[0]) {
	case TypeStatus:
		return decodeStatus(payload)
	case TypeGetBlocks:
		return decodeGetBlocks(payload)
	case TypeBlock:
		value, err := block.Decode(payload)
		if err != nil {
			return nil, err
		}
		return Block{Value: value}, nil
	case TypeTransaction:
		value, err := outcome.Decode(payload)
		if err != nil {
			return nil, err
		}
		return Transaction{Value: value}, nil
	case TypeBatchDone:
		return decodeBatchDone(payload)
	case TypeResult:
		return decodeResult(payload)
	case TypeGetPeers:
		return decodeGetPeers(payload)
	case TypePeers:
		return decodePeers(payload)
	case TypeGetSnapshot:
		return decodeGetSnapshot(payload)
	case TypeSnapshotManifest:
		return decodeSnapshotManifest(payload)
	case TypeSnapshotChunk:
		return decodeSnapshotChunk(payload)
	case TypeSnapshotDone:
		return decodeSnapshotDone(payload)
	case TypeGetHeaders:
		return decodeGetHeaders(payload)
	case TypeHeaders:
		return decodeHeaders(payload)
	case TypeShareInventory:
		return decodeShareInventory(payload)
	case TypeGetShares:
		return decodeGetShares(payload)
	case TypeShares:
		return decodeShares(payload)
	case TypeWorkHello:
		return decodeWorkHello(payload)
	case TypeShareResult:
		return decodeShareResult(payload)
	default:
		return nil, fmt.Errorf("%w: %d", ErrMessageType, body[0])
	}
}

func encodePayload(message Message) ([]byte, error) {
	switch value := message.(type) {
	case Status:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(128)
		encoder.U16(value.Version)
		encoder.U32(value.NetworkID)
		encoder.Fixed(value.GenesisID[:])
		encoder.Fixed(value.TipID[:])
		encoder.Fixed(value.StateRoot[:])
		encoder.U64(value.TipHeight)
		encoder.BytesField(value.CumulativeWork)
		encoder.U32(value.MaxFrameBytes)
		return encoder.Bytes(), nil
	case GetBlocks:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(8 + len(value.Locators)*types.HashSize)
		encoder.U16(value.Version)
		encoder.Uvarint(uint64(len(value.Locators)))
		for _, locator := range value.Locators {
			encoder.Fixed(locator[:])
		}
		encoder.U16(value.Limit)
		return encoder.Bytes(), nil
	case GetHeaders:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(8 + len(value.Locators)*types.HashSize)
		encoder.U16(value.Version)
		encoder.Uvarint(uint64(len(value.Locators)))
		for _, locator := range value.Locators {
			encoder.Fixed(locator[:])
		}
		encoder.U16(value.Limit)
		return encoder.Bytes(), nil
	case Headers:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(2 + 2 + len(value.Values)*block.HeaderCanonicalBytes + types.HashSize)
		encoder.U16(value.Version)
		encoder.Uvarint(uint64(len(value.Values)))
		for _, header := range value.Values {
			encoder.Fixed(header.CanonicalBytes())
		}
		encoder.Fixed(value.TipID[:])
		return encoder.Bytes(), nil
	case Block:
		if err := value.Value.ValidateBasic(); err != nil {
			return nil, err
		}
		return value.Value.CanonicalBytes(), nil
	case Transaction:
		if err := value.Value.ValidateBasic(); err != nil {
			return nil, err
		}
		return value.Value.CanonicalBytes(), nil
	case BatchDone:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(2 + types.HashSize)
		encoder.U16(value.Version)
		encoder.Fixed(value.TipID[:])
		return encoder.Bytes(), nil
	case Result:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(2 + 2 + types.HashSize)
		encoder.U16(value.Version)
		encoder.U16(uint16(value.Code))
		encoder.Fixed(value.ObjectID[:])
		return encoder.Bytes(), nil
	case GetPeers:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(4)
		encoder.U16(value.Version)
		encoder.U16(value.Limit)
		return encoder.Bytes(), nil
	case Peers:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(4 + len(value.Records)*MaxPeerRecordBytes)
		encoder.U16(value.Version)
		encoder.Uvarint(uint64(len(value.Records)))
		for _, record := range value.Records {
			encoder.BytesField(record)
		}
		return encoder.Bytes(), nil
	case GetSnapshot:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(2 + types.HashSize)
		encoder.U16(value.Version)
		encoder.Fixed(value.TipID[:])
		return encoder.Bytes(), nil
	case SnapshotManifest:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(2 + len(value.Value) + 2)
		encoder.U16(value.Version)
		encoder.BytesField(value.Value)
		return encoder.Bytes(), nil
	case SnapshotChunk:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(2 + len(value.Value) + 4)
		encoder.U16(value.Version)
		encoder.BytesField(value.Value)
		return encoder.Bytes(), nil
	case SnapshotDone:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(2 + types.HashSize)
		encoder.U16(value.Version)
		encoder.Fixed(value.TipID[:])
		return encoder.Bytes(), nil
	case ShareInventory:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(112 + len(value.IDs)*types.HashSize)
		encoder.U16(value.Version)
		encodeShareContext(encoder, value.Context)
		encodeHashList(encoder, value.IDs)
		return encoder.Bytes(), nil
	case GetShares:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(112 + len(value.IDs)*types.HashSize)
		encoder.U16(value.Version)
		encodeShareContext(encoder, value.Context)
		encodeHashList(encoder, value.IDs)
		return encoder.Bytes(), nil
	case Shares:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(112 + len(value.Values)*workgraph.MaxShareCanonicalBytes)
		encoder.U16(value.Version)
		encodeShareContext(encoder, value.Context)
		encoder.Uvarint(uint64(len(value.Values)))
		for _, share := range value.Values {
			share.EncodeTo(encoder)
		}
		return encoder.Bytes(), nil
	case WorkHello:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(128)
		encoder.U16(value.Version)
		encodeShareContext(encoder, value.Context)
		encoder.U64(value.Features)
		encoder.U32(value.MaxFrameBytes)
		encoder.U16(value.MaxInventory)
		encoder.U16(value.MaxShareBodies)
		return encoder.Bytes(), nil
	case ShareResult:
		if err := value.Validate(); err != nil {
			return nil, err
		}
		encoder := codec.NewEncoder(116)
		encoder.U16(value.Version)
		encodeShareContext(encoder, value.Context)
		encoder.U16(value.Accepted)
		encoder.U16(value.Rejected)
		return encoder.Bytes(), nil
	default:
		return nil, ErrMessageType
	}
}

func (status Status) Validate() error {
	if status.Version != Version0 {
		return ErrUnsupported
	}
	if status.NetworkID == 0 || status.GenesisID.IsZero() || status.TipID.IsZero() || status.StateRoot.IsZero() ||
		status.MaxFrameBytes == 0 || status.MaxFrameBytes > uint32(MaxFrameBodyBytes) {
		return ErrMessage
	}
	if len(status.CumulativeWork) > storage.MaxWorkBytes ||
		(len(status.CumulativeWork) > 0 && status.CumulativeWork[0] == 0) ||
		(status.TipHeight > 0 && len(status.CumulativeWork) == 0) {
		return storage.ErrWorkEncoding
	}
	return nil
}

func (request GetBlocks) Validate() error {
	return validateLocatedRequest(request.Version, request.Locators, request.Limit, MaxBlocksPerRequest)
}

func (request GetHeaders) Validate() error {
	return validateLocatedRequest(request.Version, request.Locators, request.Limit, MaxHeadersPerRequest)
}

func validateLocatedRequest(version uint16, locators []types.Hash, limit uint16, maximum uint16) error {
	if version != Version0 {
		return ErrUnsupported
	}
	if len(locators) == 0 || len(locators) > MaxLocators || limit == 0 || limit > maximum {
		return ErrMessage
	}
	seen := make(map[types.Hash]struct{}, len(locators))
	for _, locator := range locators {
		if locator.IsZero() {
			return ErrMessage
		}
		if _, exists := seen[locator]; exists {
			return ErrDuplicateLocator
		}
		seen[locator] = struct{}{}
	}
	return nil
}

func (headers Headers) Validate() error {
	if headers.Version != Version0 {
		return ErrUnsupported
	}
	if len(headers.Values) > MaxHeadersPerRequest || headers.TipID.IsZero() {
		return ErrMessage
	}
	for index, header := range headers.Values {
		if err := header.ValidateBasic(); err != nil {
			return err
		}
		if index > 0 {
			parentID, err := headers.Values[index-1].ID()
			if err != nil || header.Parent != parentID || header.Height != headers.Values[index-1].Height+1 {
				return ErrMessage
			}
		}
	}
	return nil
}

func (done BatchDone) Validate() error {
	if done.Version != Version0 {
		return ErrUnsupported
	}
	if done.TipID.IsZero() {
		return ErrMessage
	}
	return nil
}

func (result Result) Validate() error {
	if result.Version != Version0 {
		return ErrUnsupported
	}
	if (result.Code != ResultAccepted && result.Code != ResultRejected) || result.ObjectID.IsZero() {
		return ErrMessage
	}
	return nil
}

func (request GetPeers) Validate() error {
	if request.Version != Version0 {
		return ErrUnsupported
	}
	if request.Limit == 0 || request.Limit > MaxPeerRecords {
		return ErrMessage
	}
	return nil
}

func (peers Peers) Validate() error {
	if peers.Version != Version0 {
		return ErrUnsupported
	}
	if len(peers.Records) > MaxPeerRecords {
		return ErrMessage
	}
	for _, record := range peers.Records {
		if len(record) == 0 || len(record) > MaxPeerRecordBytes {
			return ErrMessage
		}
	}
	return nil
}

func (request GetSnapshot) Validate() error {
	if request.Version != Version0 {
		return ErrUnsupported
	}
	if request.TipID.IsZero() {
		return ErrMessage
	}
	return nil
}

func (manifest SnapshotManifest) Validate() error {
	if manifest.Version != Version0 {
		return ErrUnsupported
	}
	if len(manifest.Value) == 0 || len(manifest.Value) > MaxSnapshotManifestBytes {
		return ErrMessage
	}
	return nil
}

func (chunk SnapshotChunk) Validate() error {
	if chunk.Version != Version0 {
		return ErrUnsupported
	}
	if len(chunk.Value) == 0 || len(chunk.Value) > MaxSnapshotChunkBytes {
		return ErrMessage
	}
	return nil
}

func (done SnapshotDone) Validate() error {
	if done.Version != Version0 {
		return ErrUnsupported
	}
	if done.TipID.IsZero() {
		return ErrMessage
	}
	return nil
}

func (inventory ShareInventory) Validate() error {
	return validateShareIDs(inventory.Version, inventory.Context, inventory.IDs, MaxShareInventoryIDs)
}

func (request GetShares) Validate() error {
	return validateShareIDs(request.Version, request.Context, request.IDs, MaxSharesPerMessage)
}

func (shares Shares) Validate() error {
	if shares.Version != Version1 {
		return ErrUnsupported
	}
	if err := shares.Context.validate(); err != nil || len(shares.Values) == 0 ||
		len(shares.Values) > MaxSharesPerMessage {
		return ErrMessage
	}
	var previous types.Hash
	for index, share := range shares.Values {
		if err := share.ValidateBasic(); err != nil || share.NetworkID != shares.Context.NetworkID ||
			share.Height != shares.Context.Height || share.AnchorParent != shares.Context.AnchorParent ||
			share.Target != shares.Context.AnchorTarget || share.PayloadRoot != shares.Context.PayloadRoot {
			return ErrMessage
		}
		id, err := share.ID()
		if err != nil || (index > 0 && types.CompareHash(previous, id) >= 0) {
			return ErrMessage
		}
		previous = id
	}
	return nil
}

func (hello WorkHello) Validate() error {
	if hello.Version != Version1 {
		return ErrUnsupported
	}
	if err := hello.Context.validate(); err != nil ||
		hello.Features&WorkFeatureShareRelayV1 == 0 ||
		hello.MaxFrameBytes < MinWorkFrameBodyBytes || hello.MaxFrameBytes > MaxWorkFrameBodyBytes ||
		hello.MaxInventory == 0 || hello.MaxInventory > MaxShareInventoryIDs ||
		hello.MaxShareBodies == 0 || hello.MaxShareBodies > MaxSharesPerMessage {
		return ErrMessage
	}
	return nil
}

func (result ShareResult) Validate() error {
	if result.Version != Version1 {
		return ErrUnsupported
	}
	if err := result.Context.validate(); err != nil ||
		uint32(result.Accepted)+uint32(result.Rejected) > MaxShareInventoryIDs {
		return ErrMessage
	}
	return nil
}

func (context ShareContext) validate() error {
	if context.NetworkID == 0 || context.Height == 0 || context.AnchorParent.IsZero() ||
		context.AnchorTarget.IsZero() || context.PayloadRoot.IsZero() ||
		!workgraph.ExactShareRatio(context.AnchorTarget) {
		return ErrMessage
	}
	return nil
}

func validateShareIDs(version uint16, context ShareContext, ids []types.Hash, maximum int) error {
	if version != Version1 {
		return ErrUnsupported
	}
	if err := context.validate(); err != nil || len(ids) == 0 || len(ids) > maximum {
		return ErrMessage
	}
	for index, id := range ids {
		if id.IsZero() || (index > 0 && types.CompareHash(ids[index-1], id) >= 0) {
			return ErrMessage
		}
	}
	return nil
}

func decodeStatus(payload []byte) (Status, error) {
	decoder := codec.NewDecoder(payload)
	var result Status
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return Status{}, err
	}
	result.NetworkID, err = decoder.U32()
	if err != nil {
		return Status{}, err
	}
	genesisID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Status{}, err
	}
	copy(result.GenesisID[:], genesisID)
	tipID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Status{}, err
	}
	copy(result.TipID[:], tipID)
	stateRoot, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Status{}, err
	}
	copy(result.StateRoot[:], stateRoot)
	result.TipHeight, err = decoder.U64()
	if err != nil {
		return Status{}, err
	}
	result.CumulativeWork, err = decoder.BytesField(storage.MaxWorkBytes)
	if err != nil {
		return Status{}, err
	}
	result.MaxFrameBytes, err = decoder.U32()
	if err != nil {
		return Status{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Status{}, err
	}
	return result, result.Validate()
}

func decodeGetBlocks(payload []byte) (GetBlocks, error) {
	decoder := codec.NewDecoder(payload)
	var result GetBlocks
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return GetBlocks{}, err
	}
	count, err := decoder.ListLength(MaxLocators)
	if err != nil {
		return GetBlocks{}, err
	}
	result.Locators = make([]types.Hash, count)
	for index := range result.Locators {
		value, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return GetBlocks{}, err
		}
		copy(result.Locators[index][:], value)
	}
	result.Limit, err = decoder.U16()
	if err != nil {
		return GetBlocks{}, err
	}
	if err := decoder.Finish(); err != nil {
		return GetBlocks{}, err
	}
	return result, result.Validate()
}

func decodeGetHeaders(payload []byte) (GetHeaders, error) {
	decoder := codec.NewDecoder(payload)
	var result GetHeaders
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return GetHeaders{}, err
	}
	count, err := decoder.ListLength(MaxLocators)
	if err != nil {
		return GetHeaders{}, err
	}
	result.Locators = make([]types.Hash, count)
	for index := range result.Locators {
		value, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return GetHeaders{}, err
		}
		copy(result.Locators[index][:], value)
	}
	result.Limit, err = decoder.U16()
	if err != nil {
		return GetHeaders{}, err
	}
	if err := decoder.Finish(); err != nil {
		return GetHeaders{}, err
	}
	return result, result.Validate()
}

func decodeHeaders(payload []byte) (Headers, error) {
	decoder := codec.NewDecoder(payload)
	var result Headers
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return Headers{}, err
	}
	count, err := decoder.ListLength(MaxHeadersPerRequest)
	if err != nil {
		return Headers{}, err
	}
	result.Values = make([]block.Header, count)
	for index := range result.Values {
		encoded, err := decoder.Fixed(block.HeaderCanonicalBytes)
		if err != nil {
			return Headers{}, err
		}
		result.Values[index], err = block.DecodeHeader(encoded)
		if err != nil {
			return Headers{}, err
		}
	}
	id, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Headers{}, err
	}
	copy(result.TipID[:], id)
	if err := decoder.Finish(); err != nil {
		return Headers{}, err
	}
	return result, result.Validate()
}

func decodeBatchDone(payload []byte) (BatchDone, error) {
	decoder := codec.NewDecoder(payload)
	var result BatchDone
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return BatchDone{}, err
	}
	id, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return BatchDone{}, err
	}
	copy(result.TipID[:], id)
	if err := decoder.Finish(); err != nil {
		return BatchDone{}, err
	}
	return result, result.Validate()
}

func decodeResult(payload []byte) (Result, error) {
	decoder := codec.NewDecoder(payload)
	var result Result
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return Result{}, err
	}
	code, err := decoder.U16()
	if err != nil {
		return Result{}, err
	}
	result.Code = ResultCode(code)
	id, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Result{}, err
	}
	copy(result.ObjectID[:], id)
	if err := decoder.Finish(); err != nil {
		return Result{}, err
	}
	return result, result.Validate()
}

func decodeGetPeers(payload []byte) (GetPeers, error) {
	decoder := codec.NewDecoder(payload)
	var result GetPeers
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return GetPeers{}, err
	}
	result.Limit, err = decoder.U16()
	if err != nil {
		return GetPeers{}, err
	}
	if err := decoder.Finish(); err != nil {
		return GetPeers{}, err
	}
	return result, result.Validate()
}

func decodePeers(payload []byte) (Peers, error) {
	decoder := codec.NewDecoder(payload)
	var result Peers
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return Peers{}, err
	}
	count, err := decoder.ListLength(MaxPeerRecords)
	if err != nil {
		return Peers{}, err
	}
	result.Records = make([][]byte, count)
	for index := range result.Records {
		result.Records[index], err = decoder.BytesField(MaxPeerRecordBytes)
		if err != nil {
			return Peers{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return Peers{}, err
	}
	return result, result.Validate()
}

func decodeGetSnapshot(payload []byte) (GetSnapshot, error) {
	decoder := codec.NewDecoder(payload)
	var result GetSnapshot
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return GetSnapshot{}, err
	}
	id, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return GetSnapshot{}, err
	}
	copy(result.TipID[:], id)
	if err := decoder.Finish(); err != nil {
		return GetSnapshot{}, err
	}
	return result, result.Validate()
}

func decodeSnapshotManifest(payload []byte) (SnapshotManifest, error) {
	decoder := codec.NewDecoder(payload)
	var result SnapshotManifest
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return SnapshotManifest{}, err
	}
	result.Value, err = decoder.BytesField(MaxSnapshotManifestBytes)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if err := decoder.Finish(); err != nil {
		return SnapshotManifest{}, err
	}
	return result, result.Validate()
}

func decodeSnapshotChunk(payload []byte) (SnapshotChunk, error) {
	decoder := codec.NewDecoder(payload)
	var result SnapshotChunk
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return SnapshotChunk{}, err
	}
	result.Value, err = decoder.BytesField(MaxSnapshotChunkBytes)
	if err != nil {
		return SnapshotChunk{}, err
	}
	if err := decoder.Finish(); err != nil {
		return SnapshotChunk{}, err
	}
	return result, result.Validate()
}

func decodeSnapshotDone(payload []byte) (SnapshotDone, error) {
	decoder := codec.NewDecoder(payload)
	var result SnapshotDone
	var err error
	result.Version, err = decoder.U16()
	if err != nil {
		return SnapshotDone{}, err
	}
	id, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return SnapshotDone{}, err
	}
	copy(result.TipID[:], id)
	if err := decoder.Finish(); err != nil {
		return SnapshotDone{}, err
	}
	return result, result.Validate()
}

func decodeShareInventory(payload []byte) (ShareInventory, error) {
	decoder := codec.NewDecoder(payload)
	version, err := decoder.U16()
	if err != nil {
		return ShareInventory{}, err
	}
	context, err := decodeShareContext(decoder)
	if err != nil {
		return ShareInventory{}, err
	}
	ids, err := decodeHashList(decoder, MaxShareInventoryIDs)
	if err != nil {
		return ShareInventory{}, err
	}
	if err := decoder.Finish(); err != nil {
		return ShareInventory{}, err
	}
	result := ShareInventory{Version: version, Context: context, IDs: ids}
	return result, result.Validate()
}

func decodeGetShares(payload []byte) (GetShares, error) {
	decoder := codec.NewDecoder(payload)
	version, err := decoder.U16()
	if err != nil {
		return GetShares{}, err
	}
	context, err := decodeShareContext(decoder)
	if err != nil {
		return GetShares{}, err
	}
	ids, err := decodeHashList(decoder, MaxSharesPerMessage)
	if err != nil {
		return GetShares{}, err
	}
	if err := decoder.Finish(); err != nil {
		return GetShares{}, err
	}
	result := GetShares{Version: version, Context: context, IDs: ids}
	return result, result.Validate()
}

func decodeShares(payload []byte) (Shares, error) {
	decoder := codec.NewDecoder(payload)
	version, err := decoder.U16()
	if err != nil {
		return Shares{}, err
	}
	context, err := decodeShareContext(decoder)
	if err != nil {
		return Shares{}, err
	}
	count, err := decoder.ListLength(MaxSharesPerMessage)
	if err != nil {
		return Shares{}, err
	}
	values := make([]workgraph.Share, count)
	for index := range values {
		values[index], err = workgraph.DecodeFrom(decoder)
		if err != nil {
			return Shares{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return Shares{}, err
	}
	result := Shares{Version: version, Context: context, Values: values}
	return result, result.Validate()
}

func decodeWorkHello(payload []byte) (WorkHello, error) {
	decoder := codec.NewDecoder(payload)
	version, err := decoder.U16()
	if err != nil {
		return WorkHello{}, err
	}
	context, err := decodeShareContext(decoder)
	if err != nil {
		return WorkHello{}, err
	}
	features, err := decoder.U64()
	if err != nil {
		return WorkHello{}, err
	}
	maxFrameBytes, err := decoder.U32()
	if err != nil {
		return WorkHello{}, err
	}
	maxInventory, err := decoder.U16()
	if err != nil {
		return WorkHello{}, err
	}
	maxShareBodies, err := decoder.U16()
	if err != nil {
		return WorkHello{}, err
	}
	if err := decoder.Finish(); err != nil {
		return WorkHello{}, err
	}
	result := WorkHello{
		Version: version, Context: context, Features: features, MaxFrameBytes: maxFrameBytes,
		MaxInventory: maxInventory, MaxShareBodies: maxShareBodies,
	}
	return result, result.Validate()
}

func decodeShareResult(payload []byte) (ShareResult, error) {
	decoder := codec.NewDecoder(payload)
	version, err := decoder.U16()
	if err != nil {
		return ShareResult{}, err
	}
	context, err := decodeShareContext(decoder)
	if err != nil {
		return ShareResult{}, err
	}
	accepted, err := decoder.U16()
	if err != nil {
		return ShareResult{}, err
	}
	rejected, err := decoder.U16()
	if err != nil {
		return ShareResult{}, err
	}
	if err := decoder.Finish(); err != nil {
		return ShareResult{}, err
	}
	result := ShareResult{Version: version, Context: context, Accepted: accepted, Rejected: rejected}
	return result, result.Validate()
}

func encodeShareContext(encoder *codec.Encoder, context ShareContext) {
	encoder.U32(context.NetworkID)
	encoder.U64(context.Height)
	encoder.Fixed(context.AnchorParent[:])
	encoder.Fixed(context.AnchorTarget[:])
	encoder.Fixed(context.PayloadRoot[:])
}

func decodeShareContext(decoder *codec.Decoder) (ShareContext, error) {
	var result ShareContext
	var err error
	result.NetworkID, err = decoder.U32()
	if err != nil {
		return ShareContext{}, err
	}
	result.Height, err = decoder.U64()
	if err != nil {
		return ShareContext{}, err
	}
	for _, destination := range []*types.Hash{&result.AnchorParent, &result.AnchorTarget, &result.PayloadRoot} {
		value, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return ShareContext{}, err
		}
		copy(destination[:], value)
	}
	return result, nil
}

func encodeHashList(encoder *codec.Encoder, ids []types.Hash) {
	encoder.Uvarint(uint64(len(ids)))
	for _, id := range ids {
		encoder.Fixed(id[:])
	}
}

func decodeHashList(decoder *codec.Decoder, maximum int) ([]types.Hash, error) {
	count, err := decoder.ListLength(uint64(maximum))
	if err != nil {
		return nil, err
	}
	result := make([]types.Hash, count)
	for index := range result {
		value, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return nil, err
		}
		copy(result[index][:], value)
	}
	return result, nil
}

func writeFull(writer io.Writer, input []byte) error {
	for len(input) > 0 {
		written, err := writer.Write(input)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(input) {
			return io.ErrShortWrite
		}
		input = input[written:]
	}
	return nil
}
