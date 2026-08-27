package chainsession

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"sort"
	"time"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/chainblock"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrUnexpected     = errors.New("unexpected versioned chain session message")
	ErrNoProgress     = errors.New("versioned chain synchronization made no progress")
	ErrTooManyBatches = errors.New("versioned chain synchronization exceeded batch limit")
	ErrSessionBudget  = errors.New("versioned chain session message budget exhausted")
	ErrBatch          = errors.New("invalid versioned chain batch")
	ErrHeaderMismatch = errors.New("versioned header-first synchronization mismatch")
)

type Stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

type SessionConfig struct {
	HandshakeTimeout   time.Duration
	RequestTimeout     time.Duration
	MaxSyncBatches     int
	MaxInboundMessages int
	MaxBlockRequests   int
	MaxHeaderRequests  int
	BatchSize          uint16
	MaxFrameBytes      uint32
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		HandshakeTimeout: 5 * time.Second, RequestTimeout: 30 * time.Second,
		MaxSyncBatches: 64, MaxInboundMessages: 4_096,
		MaxBlockRequests: 64, MaxHeaderRequests: 64,
		BatchSize: wire.MaxBlocksPerRequest, MaxFrameBytes: uint32(wire.MaxVersionedFrameBodyBytes),
	}
}

type Node struct {
	router   *activation.Router
	protocol *Protocol
	legacy   legacyblock.Parameters
	work     workblock.Parameters
	config   SessionConfig
}

func NewNode(
	router *activation.Router,
	document genesis.Document,
	config SessionConfig,
) (*Node, error) {
	if router == nil || document.Validate() != nil {
		return nil, ErrConfiguration
	}
	defaults := DefaultSessionConfig()
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = defaults.HandshakeTimeout
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaults.RequestTimeout
	}
	if config.MaxSyncBatches == 0 {
		config.MaxSyncBatches = defaults.MaxSyncBatches
	}
	if config.MaxInboundMessages == 0 {
		config.MaxInboundMessages = defaults.MaxInboundMessages
	}
	if config.MaxBlockRequests == 0 {
		config.MaxBlockRequests = defaults.MaxBlockRequests
	}
	if config.MaxHeaderRequests == 0 {
		config.MaxHeaderRequests = defaults.MaxHeaderRequests
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaults.BatchSize
	}
	if config.MaxFrameBytes == 0 {
		config.MaxFrameBytes = defaults.MaxFrameBytes
	}
	if config.HandshakeTimeout <= 0 || config.RequestTimeout <= 0 || config.MaxSyncBatches <= 0 ||
		config.MaxInboundMessages <= 0 || config.MaxInboundMessages > 1_000_000 ||
		config.MaxBlockRequests <= 0 || config.MaxBlockRequests > config.MaxInboundMessages ||
		config.MaxHeaderRequests <= 0 || config.MaxHeaderRequests > config.MaxInboundMessages ||
		config.MaxSyncBatches > config.MaxBlockRequests || config.MaxSyncBatches > config.MaxHeaderRequests ||
		config.BatchSize > wire.MaxBlocksPerRequest || config.BatchSize > wire.MaxHeadersPerRequest ||
		config.MaxFrameBytes < wire.MinVersionedChainFrameBodyBytes ||
		config.MaxFrameBytes > uint32(wire.MaxVersionedFrameBodyBytes) {
		return nil, ErrConfiguration
	}
	legacy, work, err := router.Parameters()
	if err != nil || legacy != legacyblock.ParametersFromGenesis(document) {
		return nil, ErrConfiguration
	}
	genesisID, err := document.ID()
	if err != nil {
		return nil, err
	}
	expectedGenesis, err := storage.GenesisTip(document)
	if err != nil {
		return nil, ErrConfiguration
	}
	routedGenesis, err := router.TipByID(genesisID)
	if err != nil || !storage.EqualTips(expectedGenesis, routedGenesis) {
		return nil, ErrConfiguration
	}
	protocol, err := New(Config{
		NetworkID: document.NetworkID, GenesisID: genesisID, ActivationHeight: work.ActivationHeight,
		Features: wire.ChainFeatureVersionedSyncV1, MaxFrameBytes: config.MaxFrameBytes,
	})
	if err != nil {
		return nil, err
	}
	return &Node{
		router: router, protocol: protocol, legacy: legacy, work: work, config: config,
	}, nil
}

func (node *Node) Status() (wire.ChainHello, error) {
	if node == nil {
		return wire.ChainHello{}, ErrConfiguration
	}
	tip, err := node.router.Tip()
	if err != nil {
		return wire.ChainHello{}, err
	}
	return node.protocol.Hello(tip)
}

func (node *Node) Locators() ([]types.Hash, error) {
	path, err := node.canonicalPath()
	if err != nil {
		return nil, err
	}
	result := make([]types.Hash, 0, wire.MaxLocators)
	height := path.tip.Height
	step := uint64(1)
	for len(result) < wire.MaxLocators-1 && height > 0 {
		result = append(result, path.nodes[height-1].id)
		if height <= step {
			break
		}
		height -= step
		if len(result) > 10 && step <= ^uint64(0)/2 {
			step *= 2
		}
	}
	if len(result) == 0 || result[len(result)-1] != node.protocol.config.GenesisID {
		result = append(result, node.protocol.config.GenesisID)
	}
	return result, nil
}

func (node *Node) BlocksAfter(request wire.GetVersionedBlocks) ([]chainblock.Block, wire.VersionedBatchDone, error) {
	if err := request.Validate(); err != nil {
		return nil, wire.VersionedBatchDone{}, err
	}
	path, err := node.canonicalPath()
	if err != nil {
		return nil, wire.VersionedBatchDone{}, err
	}
	ancestorHeight, found := node.findCanonicalAncestor(request.Locators, path)
	if !found {
		return nil, wire.VersionedBatchDone{}, ErrNoProgress
	}
	count := min(uint64(request.Limit), path.tip.Height-ancestorHeight)
	result := make([]chainblock.Block, count)
	for index := range result {
		candidate, err := node.router.BlockByID(path.nodes[ancestorHeight+uint64(index)].id)
		if err != nil {
			return nil, wire.VersionedBatchDone{}, err
		}
		result[index] = candidate
	}
	return result, wire.VersionedBatchDone{Version: wire.Version1, TipID: path.tip.ID}, nil
}

func (node *Node) HeadersAfter(request wire.GetVersionedHeaders) (wire.VersionedHeaders, error) {
	if err := request.Validate(); err != nil {
		return wire.VersionedHeaders{}, err
	}
	path, err := node.canonicalPath()
	if err != nil {
		return wire.VersionedHeaders{}, err
	}
	return node.headersAfterPath(request, path)
}

func (node *Node) headersAfterPath(request wire.GetVersionedHeaders, path canonicalPath) (wire.VersionedHeaders, error) {
	if err := request.Validate(); err != nil {
		return wire.VersionedHeaders{}, err
	}
	ancestorHeight, found := node.findCanonicalAncestor(request.Locators, path)
	if !found {
		return wire.VersionedHeaders{}, ErrNoProgress
	}
	count := min(uint64(request.Limit), path.tip.Height-ancestorHeight)
	result := wire.VersionedHeaders{
		Version: wire.Version1, Values: make([]chainblock.Header, count), TipID: path.tip.ID,
	}
	for index := range result.Values {
		result.Values[index] = path.nodes[ancestorHeight+uint64(index)].header
	}
	return result, result.Validate()
}

// ValidateHeaders performs all PoW, target, time, ancestry, and activation
// checks that do not require transaction/share bodies or state execution.
func (node *Node) ValidateHeaders(
	request wire.GetVersionedHeaders,
	response wire.VersionedHeaders,
	validationTime uint64,
) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := response.Validate(); err != nil {
		return err
	}
	if validationTime == 0 || len(response.Values) > int(request.Limit) {
		return ErrBatch
	}
	if len(response.Values) == 0 {
		return nil
	}
	parentID := response.Values[0].ParentID()
	requested := false
	for _, locator := range request.Locators {
		if locator == parentID {
			requested = true
			break
		}
	}
	if !requested {
		return ErrBatch
	}
	parent, err := node.router.TipByID(parentID)
	if err != nil {
		return ErrNoProgress
	}
	history, err := node.recentTimestamps(parent)
	if err != nil {
		return err
	}
	for _, header := range response.Values {
		if err := header.Validate(node.work.ActivationHeight); err != nil {
			return err
		}
		if parent.Height == ^uint64(0) || header.Height() != parent.Height+1 || header.ParentID() != parent.ID {
			return ErrBatch
		}
		median := parent.Timestamp
		if len(history) > 0 {
			median = medianTimestamp(history)
		}
		switch header.Version() {
		case legacyblock.Version0:
			value, ok := header.LegacyHeader()
			if !ok {
				return ErrBatch
			}
			context := legacyblock.Parent{
				ID: parent.ID, Height: parent.Height, Timestamp: parent.Timestamp,
				MedianTimePast: median, Target: parent.Target,
			}
			if err := legacyblock.ValidateHeaderAt(context, value, node.legacy, validationTime); err != nil {
				return err
			}
		case workblock.Version1:
			value, ok := header.WorkHeader()
			if !ok {
				return ErrBatch
			}
			position := workblock.Position{
				Height: header.Height(), ParentID: parent.ID, ParentTimestamp: parent.Timestamp,
				MedianTimePast: median, Timestamp: header.Timestamp(), Target: header.Target(),
			}
			if err := workblock.ValidateHeaderAt(position, value, node.work, validationTime); err != nil {
				return err
			}
		default:
			return ErrBatch
		}
		id, err := header.ID()
		if err != nil {
			return err
		}
		parent = storage.Tip{
			ID: id, Height: header.Height(), Timestamp: header.Timestamp(), Target: header.Target(),
			StateRoot: header.StateRoot(),
		}
		history = append(history, header.Timestamp())
		if len(history) > 11 {
			history = history[len(history)-11:]
		}
	}
	return nil
}

func (node *Node) ApplyBlocks(blocks []chainblock.Block) (storage.Tip, error) {
	if len(blocks) == 0 || len(blocks) > wire.MaxBlocksPerRequest {
		return storage.Tip{}, ErrBatch
	}
	for index, candidate := range blocks {
		if err := candidate.Validate(node.work.ActivationHeight); err != nil {
			return storage.Tip{}, err
		}
		if index > 0 {
			previousID, err := blocks[index-1].ID()
			if err != nil || blocks[index-1].Height() == ^uint64(0) ||
				candidate.ParentID() != previousID || candidate.Height() != blocks[index-1].Height()+1 {
				return storage.Tip{}, ErrBatch
			}
		}
	}
	var result storage.Tip
	for _, candidate := range blocks {
		var err error
		result, err = node.router.Submit(candidate)
		if errors.Is(err, storage.ErrBlockExists) {
			result, err = node.router.Tip()
		}
		if err != nil {
			return storage.Tip{}, err
		}
	}
	return result, nil
}

// Serve performs a separate v1 handshake and responds only to bounded pull
// requests. It is not registered by the active transport or CLI.
func (node *Node) Serve(ctx context.Context, stream Stream) error {
	if node == nil || stream == nil {
		return ErrConfiguration
	}
	defer stream.Close()
	_, _, limits, path, err := node.responderHandshake(ctx, stream)
	if err != nil {
		return err
	}
	messages := 0
	blockRequests := 0
	headerRequests := 0
	var pending *servedHeaders
	for {
		message, err := node.read(ctx, stream, limits.MaxFrameBytes)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		if err != nil {
			return err
		}
		messages++
		if messages > node.config.MaxInboundMessages {
			return ErrSessionBudget
		}
		switch value := message.(type) {
		case wire.GetVersionedHeaders:
			if pending != nil {
				return ErrUnexpected
			}
			headerRequests++
			if headerRequests > node.config.MaxHeaderRequests {
				return ErrSessionBudget
			}
			response, err := node.headersAfterPath(value, path)
			if err != nil {
				return err
			}
			for {
				err = node.write(ctx, stream, response, limits.MaxFrameBytes)
				if !errors.Is(err, wire.ErrFrameSize) || len(response.Values) <= 1 {
					break
				}
				response.Values = response.Values[:max(1, len(response.Values)/2)]
			}
			if err != nil {
				return err
			}
			pending = &servedHeaders{
				locators: append([]types.Hash(nil), value.Locators...), headers: response,
			}
		case wire.GetVersionedBlocks:
			if pending == nil || int(value.Limit) != len(pending.headers.Values) ||
				!equalHashes(value.Locators, pending.locators) {
				return ErrUnexpected
			}
			blockRequests++
			if blockRequests > node.config.MaxBlockRequests {
				return ErrSessionBudget
			}
			for _, header := range pending.headers.Values {
				id, err := header.ID()
				if err != nil {
					return err
				}
				candidate, err := node.router.BlockByID(id)
				if err != nil || !bytes.Equal(candidate.Header().CanonicalBytes(), header.CanonicalBytes()) {
					return ErrHeaderMismatch
				}
				if err := node.write(ctx, stream, wire.VersionedBlock{
					Version: wire.Version1, Value: candidate,
				}, limits.MaxFrameBytes); err != nil {
					return err
				}
			}
			done := wire.VersionedBatchDone{Version: wire.Version1, TipID: pending.headers.TipID}
			if err := node.write(ctx, stream, done, limits.MaxFrameBytes); err != nil {
				return err
			}
			pending = nil
		default:
			return ErrUnexpected
		}
	}
}

// Synchronize downloads header-validated batches along one remote canonical
// path. A continuation locator allows a long divergent branch to make progress
// before it has accumulated enough work to become the local selected tip.
func (node *Node) Synchronize(ctx context.Context, stream Stream) (storage.Tip, error) {
	if node == nil || stream == nil {
		return storage.Tip{}, ErrConfiguration
	}
	defer stream.Close()
	remote, limits, err := node.initiatorHandshake(ctx, stream)
	if err != nil {
		return storage.Tip{}, err
	}
	local, err := node.router.Tip()
	if err != nil {
		return storage.Tip{}, err
	}
	better, err := node.protocol.PeerIsBetter(local, remote)
	if err != nil {
		return storage.Tip{}, err
	}
	if !better {
		return local, nil
	}
	var continuation types.Hash
	for batchIndex := 0; batchIndex < node.config.MaxSyncBatches; batchIndex++ {
		locators, err := node.continuationLocators(continuation)
		if err != nil {
			return storage.Tip{}, err
		}
		headerRequest := wire.GetVersionedHeaders{
			Version: wire.Version1, Locators: locators, Limit: node.config.BatchSize,
		}
		if err := node.write(ctx, stream, headerRequest, limits.MaxFrameBytes); err != nil {
			return storage.Tip{}, err
		}
		message, err := node.read(ctx, stream, limits.MaxFrameBytes)
		if err != nil {
			return storage.Tip{}, err
		}
		headers, ok := message.(wire.VersionedHeaders)
		if !ok {
			return storage.Tip{}, ErrUnexpected
		}
		if len(headers.Values) == 0 {
			return storage.Tip{}, ErrNoProgress
		}
		validationTime, err := node.router.AdmissionTime()
		if err != nil {
			return storage.Tip{}, err
		}
		if err := node.ValidateHeaders(headerRequest, headers, validationTime); err != nil {
			return storage.Tip{}, err
		}
		if headers.TipID != remote.TipID {
			return storage.Tip{}, ErrHeaderMismatch
		}
		lastHeader := headers.Values[len(headers.Values)-1]
		lastHeaderID, err := lastHeader.ID()
		if err != nil {
			return storage.Tip{}, err
		}
		if lastHeader.Height() > remote.TipHeight ||
			(lastHeader.Height() == remote.TipHeight && lastHeaderID != remote.TipID) {
			return storage.Tip{}, ErrHeaderMismatch
		}
		blockRequest := wire.GetVersionedBlocks{
			Version: wire.Version1, Locators: locators, Limit: uint16(len(headers.Values)),
		}
		if err := node.write(ctx, stream, blockRequest, limits.MaxFrameBytes); err != nil {
			return storage.Tip{}, err
		}
		blocks, done, err := node.readBatch(ctx, stream, limits.MaxFrameBytes)
		if err != nil {
			return storage.Tip{}, err
		}
		if len(blocks) != len(headers.Values) || done.TipID != headers.TipID {
			return storage.Tip{}, ErrHeaderMismatch
		}
		for index := range blocks {
			if !bytes.Equal(blocks[index].Header().CanonicalBytes(), headers.Values[index].CanonicalBytes()) {
				return storage.Tip{}, ErrHeaderMismatch
			}
		}
		if continuation == lastHeaderID {
			return storage.Tip{}, ErrNoProgress
		}
		if _, err := node.ApplyBlocks(blocks); err != nil {
			return storage.Tip{}, err
		}
		continuation = lastHeaderID
		if continuation == remote.TipID {
			current, err := node.router.Tip()
			if err != nil {
				return storage.Tip{}, err
			}
			if current.ID == remote.TipID {
				if current.Height != remote.TipHeight || current.StateRoot != remote.StateRoot ||
					!bytes.Equal(current.CumulativeWork, remote.CumulativeWork) {
					return storage.Tip{}, ErrHeaderMismatch
				}
				return current, nil
			}
			stillBetter, err := node.protocol.PeerIsBetter(current, remote)
			if err != nil {
				return storage.Tip{}, err
			}
			if !stillBetter {
				return current, nil
			}
			return storage.Tip{}, ErrNoProgress
		}
	}
	return storage.Tip{}, ErrTooManyBatches
}

type canonicalPath struct {
	tip   storage.Tip
	nodes []pathNode
}

type servedHeaders struct {
	locators []types.Hash
	headers  wire.VersionedHeaders
}

type pathNode struct {
	id     types.Hash
	header chainblock.Header
}

func (node *Node) canonicalPath() (canonicalPath, error) {
	tip, err := node.router.Tip()
	if err != nil {
		return canonicalPath{}, err
	}
	if tip.Height > uint64(math.MaxInt) {
		return canonicalPath{}, storage.ErrCorrupt
	}
	reversed := make([]pathNode, 0, int(tip.Height))
	cursor := tip.ID
	for height := tip.Height; height > 0; height-- {
		candidate, err := node.router.BlockByID(cursor)
		if err != nil {
			return canonicalPath{}, err
		}
		id, err := candidate.ID()
		if err != nil || id != cursor || candidate.Height() != height ||
			candidate.Validate(node.work.ActivationHeight) != nil {
			return canonicalPath{}, storage.ErrCorrupt
		}
		reversed = append(reversed, pathNode{id: id, header: candidate.Header()})
		cursor = candidate.ParentID()
	}
	if cursor != node.protocol.config.GenesisID {
		return canonicalPath{}, storage.ErrCorrupt
	}
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return canonicalPath{tip: tip, nodes: reversed}, nil
}

func (node *Node) findCanonicalAncestor(locators []types.Hash, path canonicalPath) (uint64, bool) {
	heights := make(map[types.Hash]uint64, len(path.nodes)+1)
	heights[node.protocol.config.GenesisID] = 0
	for index, candidate := range path.nodes {
		heights[candidate.id] = uint64(index) + 1
	}
	for _, locator := range locators {
		if height, exists := heights[locator]; exists {
			return height, true
		}
	}
	return 0, false
}

func (node *Node) recentTimestamps(parent storage.Tip) ([]uint64, error) {
	if parent.Height == 0 {
		return nil, nil
	}
	result := make([]uint64, 0, 11)
	cursor := parent.ID
	for height := parent.Height; height > 0 && len(result) < 11; height-- {
		candidate, err := node.router.BlockByID(cursor)
		if err != nil {
			return nil, err
		}
		id, err := candidate.ID()
		if err != nil || id != cursor || candidate.Height() != height {
			return nil, storage.ErrCorrupt
		}
		result = append(result, candidate.Header().Timestamp())
		cursor = candidate.ParentID()
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result, nil
}

func (node *Node) continuationLocators(continuation types.Hash) ([]types.Hash, error) {
	locators, err := node.Locators()
	if err != nil || continuation.IsZero() {
		return locators, err
	}
	result := make([]types.Hash, 0, wire.MaxLocators)
	result = append(result, continuation)
	for _, locator := range locators {
		if locator != continuation && len(result) < wire.MaxLocators {
			result = append(result, locator)
		}
	}
	return result, nil
}

func (node *Node) initiatorHandshake(ctx context.Context, stream Stream) (wire.ChainHello, Limits, error) {
	local, err := node.Status()
	if err != nil {
		return wire.ChainHello{}, Limits{}, err
	}
	if err := node.writeWithTimeout(ctx, stream, local, node.config.MaxFrameBytes, node.config.HandshakeTimeout); err != nil {
		return wire.ChainHello{}, Limits{}, err
	}
	message, err := node.readWithTimeout(ctx, stream, node.config.MaxFrameBytes, node.config.HandshakeTimeout)
	if err != nil {
		return wire.ChainHello{}, Limits{}, err
	}
	remote, ok := message.(wire.ChainHello)
	if !ok {
		return wire.ChainHello{}, Limits{}, ErrUnexpected
	}
	limits, err := node.protocol.Negotiate(remote)
	return remote, limits, err
}

func (node *Node) responderHandshake(
	ctx context.Context,
	stream Stream,
) (wire.ChainHello, wire.ChainHello, Limits, canonicalPath, error) {
	message, err := node.readWithTimeout(ctx, stream, node.config.MaxFrameBytes, node.config.HandshakeTimeout)
	if err != nil {
		return wire.ChainHello{}, wire.ChainHello{}, Limits{}, canonicalPath{}, err
	}
	remote, ok := message.(wire.ChainHello)
	if !ok {
		return wire.ChainHello{}, wire.ChainHello{}, Limits{}, canonicalPath{}, ErrUnexpected
	}
	limits, err := node.protocol.Negotiate(remote)
	if err != nil {
		return wire.ChainHello{}, wire.ChainHello{}, Limits{}, canonicalPath{}, err
	}
	path, err := node.canonicalPath()
	if err != nil {
		return wire.ChainHello{}, wire.ChainHello{}, Limits{}, canonicalPath{}, err
	}
	local, err := node.protocol.Hello(path.tip)
	if err != nil {
		return wire.ChainHello{}, wire.ChainHello{}, Limits{}, canonicalPath{}, err
	}
	if err := node.writeWithTimeout(ctx, stream, local, limits.MaxFrameBytes, node.config.HandshakeTimeout); err != nil {
		return wire.ChainHello{}, wire.ChainHello{}, Limits{}, canonicalPath{}, err
	}
	return remote, local, limits, path, nil
}

func (node *Node) readBatch(ctx context.Context, stream Stream, maximum uint32) ([]chainblock.Block, wire.VersionedBatchDone, error) {
	blocks := make([]chainblock.Block, 0, wire.MaxBlocksPerRequest)
	for {
		message, err := node.read(ctx, stream, maximum)
		if err != nil {
			return nil, wire.VersionedBatchDone{}, err
		}
		switch value := message.(type) {
		case wire.VersionedBlock:
			if len(blocks) == wire.MaxBlocksPerRequest {
				return nil, wire.VersionedBatchDone{}, ErrUnexpected
			}
			blocks = append(blocks, value.Value)
		case wire.VersionedBatchDone:
			return blocks, value, nil
		default:
			return nil, wire.VersionedBatchDone{}, ErrUnexpected
		}
	}
}

func (node *Node) read(ctx context.Context, stream Stream, maximum uint32) (wire.Message, error) {
	return node.readWithTimeout(ctx, stream, maximum, node.config.RequestTimeout)
}

func (node *Node) readWithTimeout(
	ctx context.Context,
	stream Stream,
	maximum uint32,
	timeout time.Duration,
) (wire.Message, error) {
	if err := setDeadline(ctx, stream, timeout); err != nil {
		return nil, err
	}
	return wire.ReadMessageLimit(stream, maximum)
}

func (node *Node) write(ctx context.Context, stream Stream, message wire.Message, maximum uint32) error {
	return node.writeWithTimeout(ctx, stream, message, maximum, node.config.RequestTimeout)
}

func (node *Node) writeWithTimeout(
	ctx context.Context,
	stream Stream,
	message wire.Message,
	maximum uint32,
	timeout time.Duration,
) error {
	if err := setDeadline(ctx, stream, timeout); err != nil {
		return err
	}
	return wire.WriteMessageLimit(stream, message, maximum)
}

func setDeadline(ctx context.Context, stream Stream, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return stream.SetDeadline(deadline)
}

func medianTimestamp(values []uint64) uint64 {
	ordered := append([]uint64(nil), values...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	return ordered[len(ordered)/2]
}

func equalHashes(left, right []types.Hash) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
