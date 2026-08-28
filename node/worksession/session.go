package worksession

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/node/workpool"
)

var (
	ErrConfiguration = errors.New("invalid WorkGraph session configuration")
	ErrContext       = errors.New("WorkGraph session mining context mismatch")
	ErrNegotiation   = errors.New("WorkGraph session has no compatible capability")
	ErrUnexpected    = errors.New("unexpected WorkGraph session message")
	ErrNoProgress    = errors.New("WorkGraph share relay made no progress")
)

type Stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

type Config struct {
	HandshakeTimeout time.Duration
	RequestTimeout   time.Duration
	MaxFrameBytes    uint32
	MaxInventory     uint16
	MaxShareBodies   uint16
}

func DefaultConfig() Config {
	return Config{
		HandshakeTimeout: 5 * time.Second,
		RequestTimeout:   15 * time.Second,
		MaxFrameBytes:    wire.MaxWorkFrameBodyBytes,
		MaxInventory:     wire.MaxShareInventoryIDs,
		MaxShareBodies:   wire.MaxSharesPerMessage,
	}
}

type Stats struct {
	Announced int
	Requested int
	Accepted  int
	Rejected  int
	Batches   int
}

// AcceptFunc observes a share only after its first successful admission to the
// parent-scoped pool. Implementations must return promptly; session processing
// calls it synchronously and gives it an owned parent slice.
type AcceptFunc func(workgraph.Share, types.Hash)

type Node struct {
	pool    *workpool.Pool
	context wire.ShareContext
	config  Config
	hello   wire.WorkHello
}

type negotiated struct {
	frameBytes uint32
	inventory  int
	bodies     int
}

// MaximumRelayApplicationBytes is the exact worst-case bidirectional wire
// framing for one full 1,024-ID relay. The maximum occurs when negotiation
// permits one maximum-size share body per request, maximizing frame overhead.
// QUIC/IP headers and transport retransmissions are outside this value.
func MaximumRelayApplicationBytes() int {
	const (
		framePrefixBytes  = 4
		messageTypeBytes  = 1
		versionBytes      = 2
		shareContextBytes = 4 + 8 + 3*types.HashSize
		helloFieldsBytes  = 8 + 4 + 2 + 2
		largeCountBytes   = 2
		singleCountBytes  = 1
	)
	hello := framePrefixBytes + messageTypeBytes + versionBytes + shareContextBytes + helloFieldsBytes
	inventory := framePrefixBytes + messageTypeBytes + versionBytes + shareContextBytes +
		largeCountBytes + wire.MaxShareInventoryIDs*types.HashSize
	singleRequest := framePrefixBytes + messageTypeBytes + versionBytes + shareContextBytes +
		singleCountBytes + types.HashSize
	singleResponse := framePrefixBytes + messageTypeBytes + versionBytes + shareContextBytes +
		singleCountBytes + workgraph.MaxShareCanonicalBytes
	result := framePrefixBytes + messageTypeBytes + versionBytes + shareContextBytes + 2 + 2
	return 2*hello + inventory + wire.MaxShareInventoryIDs*(singleRequest+singleResponse) + result
}

func New(pool *workpool.Pool, config Config) (*Node, error) {
	if pool == nil {
		return nil, ErrConfiguration
	}
	defaults := DefaultConfig()
	if config.MaxFrameBytes == 0 {
		config.MaxFrameBytes = defaults.MaxFrameBytes
	}
	if config.MaxInventory == 0 {
		config.MaxInventory = defaults.MaxInventory
	}
	if config.MaxShareBodies == 0 {
		config.MaxShareBodies = defaults.MaxShareBodies
	}
	if config.HandshakeTimeout <= 0 || config.RequestTimeout <= 0 ||
		config.MaxFrameBytes < wire.MinWorkFrameBodyBytes || config.MaxFrameBytes > wire.MaxWorkFrameBodyBytes ||
		config.MaxInventory > wire.MaxShareInventoryIDs || config.MaxShareBodies > wire.MaxSharesPerMessage {
		return nil, ErrConfiguration
	}
	context := shareContext(pool.Context())
	hello := wire.WorkHello{
		Version: wire.Version1, Context: context, Features: wire.WorkFeatureShareRelayV1,
		MaxFrameBytes: config.MaxFrameBytes, MaxInventory: config.MaxInventory,
		MaxShareBodies: config.MaxShareBodies,
	}
	if err := hello.Validate(); err != nil {
		return nil, ErrConfiguration
	}
	return &Node{pool: pool, context: context, config: config, hello: hello}, nil
}

// Relay announces the caller's bounded inventory and serves only bodies the
// negotiated peer explicitly requests. One stream carries one finite relay.
func (node *Node) Relay(ctx context.Context, stream Stream) (Stats, error) {
	return node.relay(ctx, stream, nil)
}

// RelayInventory announces only the caller-selected, locally owned IDs. The
// negotiated peer limit may shorten the prefix; Stats.Announced tells the
// caller exactly how many input IDs were attempted so it can retain the tail.
func (node *Node) RelayInventory(ctx context.Context, stream Stream, ids []types.Hash) (Stats, error) {
	if node == nil || node.pool == nil || stream == nil || len(ids) == 0 {
		if stream != nil {
			_ = stream.Close()
		}
		return Stats{}, ErrConfiguration
	}
	selected := append([]types.Hash(nil), ids...)
	if err := node.pool.Known(selected); err != nil {
		_ = stream.Close()
		return Stats{}, err
	}
	return node.relay(ctx, stream, selected)
}

func (node *Node) relay(ctx context.Context, stream Stream, selected []types.Hash) (Stats, error) {
	if node == nil || stream == nil {
		return Stats{}, ErrConfiguration
	}
	defer stream.Close()
	limits, err := node.initiatorHandshake(ctx, stream)
	if err != nil {
		return Stats{}, err
	}
	ids := selected
	if len(ids) == 0 {
		ids = node.pool.Inventory(limits.inventory)
	} else if len(ids) > limits.inventory {
		ids = ids[:limits.inventory]
	}
	stats := Stats{Announced: len(ids)}
	if len(ids) == 0 {
		return stats, nil
	}
	if err := node.write(ctx, stream, wire.ShareInventory{
		Version: wire.Version1, Context: node.context, IDs: ids,
	}); err != nil {
		return Stats{}, err
	}
	advertised := make(map[types.Hash]struct{}, len(ids))
	for _, id := range ids {
		advertised[id] = struct{}{}
	}
	requested := make(map[types.Hash]struct{}, len(ids))
	for messages := 0; messages <= len(ids); messages++ {
		message, err := node.read(ctx, stream, limits.frameBytes)
		if err != nil {
			return Stats{}, err
		}
		switch value := message.(type) {
		case wire.GetShares:
			if value.Context != node.context || len(value.IDs) > limits.bodies {
				return Stats{}, ErrContext
			}
			for _, id := range value.IDs {
				if _, exists := advertised[id]; !exists {
					return Stats{}, ErrUnexpected
				}
				if _, exists := requested[id]; exists {
					return Stats{}, ErrNoProgress
				}
				requested[id] = struct{}{}
			}
			shares, err := node.pool.Shares(value.IDs)
			if err != nil || len(shares) == 0 {
				return Stats{}, ErrNoProgress
			}
			if err := node.write(ctx, stream, wire.Shares{
				Version: wire.Version1, Context: node.context, Values: shares,
			}); err != nil {
				return Stats{}, err
			}
			stats.Requested += len(value.IDs)
			stats.Batches++
		case wire.ShareResult:
			if value.Context != node.context || int(value.Accepted)+int(value.Rejected) > len(ids) {
				return Stats{}, ErrContext
			}
			stats.Accepted = int(value.Accepted)
			stats.Rejected = int(value.Rejected)
			return stats, nil
		default:
			return Stats{}, ErrUnexpected
		}
	}
	return Stats{}, ErrNoProgress
}

// Serve receives one inventory, requests only unknown IDs in bounded batches,
// and admits returned bodies through the full WorkGraph pool validator.
func (node *Node) Serve(ctx context.Context, stream Stream) error {
	return node.ServeAccepted(ctx, stream, nil)
}

// ServeAccepted is Serve with an optional first-admission observer. Duplicate
// bodies remain protocol-accepted for idempotency but are never observed twice.
func (node *Node) ServeAccepted(ctx context.Context, stream Stream, observe AcceptFunc) error {
	if node == nil || stream == nil {
		return ErrConfiguration
	}
	defer stream.Close()
	limits, err := node.responderHandshake(ctx, stream)
	if err != nil {
		return err
	}
	message, err := node.read(ctx, stream, limits.frameBytes)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	if err != nil {
		return err
	}
	inventory, ok := message.(wire.ShareInventory)
	if !ok {
		return ErrUnexpected
	}
	if inventory.Context != node.context || len(inventory.IDs) > limits.inventory {
		return ErrContext
	}
	pending, err := node.missing(inventory.IDs, limits.bodies)
	if err != nil {
		return err
	}
	accepted := 0
	rejected := 0
	for len(pending) > 0 {
		count := min(limits.bodies, len(pending))
		requestIDs := append([]types.Hash(nil), pending[:count]...)
		pending = pending[count:]
		if err := node.write(ctx, stream, wire.GetShares{
			Version: wire.Version1, Context: node.context, IDs: requestIDs,
		}); err != nil {
			return err
		}
		message, err := node.read(ctx, stream, limits.frameBytes)
		if err != nil {
			return err
		}
		response, ok := message.(wire.Shares)
		if !ok {
			return ErrUnexpected
		}
		if response.Context != node.context || len(response.Values) > len(requestIDs) {
			return ErrContext
		}
		requested := make(map[types.Hash]struct{}, len(requestIDs))
		for _, id := range requestIDs {
			requested[id] = struct{}{}
		}
		returned := make(map[types.Hash]struct{}, len(response.Values))
		for _, share := range response.Values {
			id, err := share.ID()
			if err != nil {
				return err
			}
			if _, exists := requested[id]; !exists {
				return ErrUnexpected
			}
			returned[id] = struct{}{}
			addedID, addErr := node.pool.Add(share)
			if addErr == nil {
				accepted++
				if observe != nil {
					observed := share
					observed.Parents = append([]types.Hash(nil), share.Parents...)
					observe(observed, addedID)
				}
			} else if errors.Is(addErr, workpool.ErrDuplicate) {
				accepted++
			} else {
				rejected++
			}
		}
		rejected += len(requestIDs) - len(returned)
	}
	return node.write(ctx, stream, wire.ShareResult{
		Version: wire.Version1, Context: node.context,
		Accepted: uint16(accepted), Rejected: uint16(rejected),
	})
}

func (node *Node) missing(ids []types.Hash, batch int) ([]types.Hash, error) {
	result := make([]types.Hash, 0, len(ids))
	for start := 0; start < len(ids); start += batch {
		end := min(start+batch, len(ids))
		missing, err := node.pool.Missing(ids[start:end], end-start)
		if err != nil {
			return nil, err
		}
		result = append(result, missing...)
	}
	return result, nil
}

func (node *Node) initiatorHandshake(ctx context.Context, stream Stream) (negotiated, error) {
	if err := node.writeWithTimeout(ctx, stream, node.hello, node.config.HandshakeTimeout); err != nil {
		return negotiated{}, err
	}
	message, err := node.readWithTimeout(ctx, stream, node.config.MaxFrameBytes, node.config.HandshakeTimeout)
	if err != nil {
		return negotiated{}, err
	}
	remote, ok := message.(wire.WorkHello)
	if !ok {
		return negotiated{}, ErrUnexpected
	}
	return node.negotiate(remote)
}

func (node *Node) responderHandshake(ctx context.Context, stream Stream) (negotiated, error) {
	message, err := node.readWithTimeout(ctx, stream, node.config.MaxFrameBytes, node.config.HandshakeTimeout)
	if err != nil {
		return negotiated{}, err
	}
	remote, ok := message.(wire.WorkHello)
	if !ok {
		return negotiated{}, ErrUnexpected
	}
	limits, err := node.negotiate(remote)
	if err != nil {
		return negotiated{}, err
	}
	if err := node.writeWithTimeout(ctx, stream, node.hello, node.config.HandshakeTimeout); err != nil {
		return negotiated{}, err
	}
	return limits, nil
}

func (node *Node) negotiate(remote wire.WorkHello) (negotiated, error) {
	if err := remote.Validate(); err != nil {
		return negotiated{}, err
	}
	if remote.Context != node.context {
		return negotiated{}, ErrContext
	}
	if remote.Features&node.hello.Features&wire.WorkFeatureShareRelayV1 == 0 {
		return negotiated{}, ErrNegotiation
	}
	frameBytes := min(remote.MaxFrameBytes, node.config.MaxFrameBytes)
	inventory := min(int(remote.MaxInventory), int(node.config.MaxInventory), maxInventoryForFrame(frameBytes))
	bodies := min(int(remote.MaxShareBodies), int(node.config.MaxShareBodies), maxBodiesForFrame(frameBytes))
	if inventory == 0 || bodies == 0 {
		return negotiated{}, ErrNegotiation
	}
	return negotiated{frameBytes: frameBytes, inventory: inventory, bodies: bodies}, nil
}

func maxInventoryForFrame(frameBytes uint32) int {
	const overhead = 1 + 2 + 4 + 8 + 3*types.HashSize + 3
	if frameBytes <= overhead {
		return 0
	}
	return min(int((frameBytes-overhead)/types.HashSize), wire.MaxShareInventoryIDs)
}

func maxBodiesForFrame(frameBytes uint32) int {
	const overhead = 1 + 2 + 4 + 8 + 3*types.HashSize + 3
	if frameBytes <= overhead {
		return 0
	}
	return min(int((frameBytes-overhead)/workgraph.MaxShareCanonicalBytes), wire.MaxSharesPerMessage)
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

func (node *Node) write(ctx context.Context, stream Stream, message wire.Message) error {
	return node.writeWithTimeout(ctx, stream, message, node.config.RequestTimeout)
}

func (node *Node) writeWithTimeout(
	ctx context.Context,
	stream Stream,
	message wire.Message,
	timeout time.Duration,
) error {
	if err := setDeadline(ctx, stream, timeout); err != nil {
		return err
	}
	return wire.WriteMessage(stream, message)
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

func shareContext(context workgraph.Context) wire.ShareContext {
	return wire.ShareContext{
		NetworkID: context.NetworkID, Height: context.Height, AnchorParent: context.AnchorParent,
		AnchorTarget: context.AnchorTarget, PayloadRoot: context.PayloadRoot,
	}
}
