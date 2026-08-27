package session

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/execution"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/mempool"
	snapshotprotocol "github.com/outcomemesh/outcomemesh/node/snapshot"
	"github.com/outcomemesh/outcomemesh/node/syncer"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrConfiguration  = errors.New("invalid peer session configuration")
	ErrUnexpected     = errors.New("unexpected peer session message")
	ErrNoProgress     = errors.New("peer synchronization made no progress")
	ErrRejected       = errors.New("peer rejected object")
	ErrTooManyBatches = errors.New("peer synchronization exceeded batch limit")
	ErrSnapshotTip    = errors.New("snapshot request does not match handshake tip")
	ErrSessionBudget  = errors.New("peer session message budget exhausted")
	ErrHeaderMismatch = errors.New("header-first synchronization mismatch")
)

type Stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

type Config struct {
	HandshakeTimeout       time.Duration
	RequestTimeout         time.Duration
	MaxSyncBatches         int
	MaxSnapshotResources   uint64
	MaxInboundMessages     int
	MaxInboundBlocks       int
	MaxInboundTransactions int
	MaxBlockRequests       int
	MaxHeaderRequests      int
	MaxPeerRequests        int
}

func DefaultConfig() Config {
	return Config{
		HandshakeTimeout:       5 * time.Second,
		RequestTimeout:         30 * time.Second,
		MaxSyncBatches:         1_024,
		MaxSnapshotResources:   snapshotprotocol.MaxSnapshotResources,
		MaxInboundMessages:     4_096,
		MaxInboundBlocks:       128,
		MaxInboundTransactions: 1_024,
		MaxBlockRequests:       64,
		MaxHeaderRequests:      64,
		MaxPeerRequests:        16,
	}
}

type Node struct {
	sync        *syncer.Service
	ledger      storage.Ledger
	pool        *mempool.Pool
	networkID   uint32
	config      Config
	discoveryMu sync.RWMutex
	book        *discovery.Book
}

// AttachDiscovery installs the bounded address book used by GetPeers and
// Discover. It is safe to call before or while peer sessions are running.
func (node *Node) AttachDiscovery(book *discovery.Book) {
	node.discoveryMu.Lock()
	defer node.discoveryMu.Unlock()
	node.book = book
}

func New(syncService *syncer.Service, ledger storage.Ledger, pool *mempool.Pool, config Config) (*Node, error) {
	defaults := DefaultConfig()
	if config.MaxSnapshotResources == 0 {
		config.MaxSnapshotResources = defaults.MaxSnapshotResources
	}
	if config.MaxInboundMessages == 0 {
		config.MaxInboundMessages = defaults.MaxInboundMessages
	}
	if config.MaxInboundBlocks == 0 {
		config.MaxInboundBlocks = defaults.MaxInboundBlocks
	}
	if config.MaxInboundTransactions == 0 {
		config.MaxInboundTransactions = defaults.MaxInboundTransactions
	}
	if config.MaxBlockRequests == 0 {
		config.MaxBlockRequests = defaults.MaxBlockRequests
	}
	if config.MaxHeaderRequests == 0 {
		config.MaxHeaderRequests = defaults.MaxHeaderRequests
	}
	if config.MaxPeerRequests == 0 {
		config.MaxPeerRequests = defaults.MaxPeerRequests
	}
	if syncService == nil || ledger == nil || config.HandshakeTimeout <= 0 || config.RequestTimeout <= 0 || config.MaxSyncBatches <= 0 ||
		config.MaxSnapshotResources > snapshotprotocol.MaxSnapshotResources ||
		config.MaxInboundMessages <= 0 || config.MaxInboundMessages > 1_000_000 ||
		config.MaxInboundBlocks <= 0 || config.MaxInboundBlocks > config.MaxInboundMessages ||
		config.MaxInboundTransactions <= 0 || config.MaxInboundTransactions > config.MaxInboundMessages ||
		config.MaxBlockRequests <= 0 || config.MaxBlockRequests > config.MaxInboundMessages ||
		config.MaxHeaderRequests <= 0 || config.MaxHeaderRequests > config.MaxInboundMessages ||
		config.MaxPeerRequests <= 0 || config.MaxPeerRequests > config.MaxInboundMessages {
		return nil, ErrConfiguration
	}
	status, err := syncService.Status()
	if err != nil {
		return nil, err
	}
	return &Node{sync: syncService, ledger: ledger, pool: pool, networkID: status.NetworkID, config: config}, nil
}

// Serve performs the responder handshake and processes bounded messages until
// the remote closes the stream or the context/deadline expires.
func (node *Node) Serve(ctx context.Context, stream Stream) error {
	defer stream.Close()
	remote, local, err := node.responderHandshake(ctx, stream)
	if err != nil {
		return err
	}
	_ = remote
	snapshotServed := false
	inboundMessages := 0
	inboundBlocks := 0
	inboundTransactions := 0
	blockRequests := 0
	headerRequests := 0
	peerRequests := 0
	for {
		if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		}
		message, err := wire.ReadMessage(stream)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		if err != nil {
			return err
		}
		inboundMessages++
		if inboundMessages > node.config.MaxInboundMessages {
			return ErrSessionBudget
		}
		switch value := message.(type) {
		case wire.GetBlocks:
			blockRequests++
			if blockRequests > node.config.MaxBlockRequests {
				return ErrSessionBudget
			}
			blocks, done, err := node.sync.BlocksAfter(value)
			if err != nil {
				return err
			}
			for _, candidate := range blocks {
				if err := wire.WriteMessage(stream, wire.Block{Value: candidate}); err != nil {
					return err
				}
			}
			if err := wire.WriteMessage(stream, done); err != nil {
				return err
			}
		case wire.GetHeaders:
			headerRequests++
			if headerRequests > node.config.MaxHeaderRequests {
				return ErrSessionBudget
			}
			headers, err := node.sync.HeadersAfter(value)
			if err != nil {
				return err
			}
			if err := wire.WriteMessage(stream, headers); err != nil {
				return err
			}
		case wire.Transaction:
			inboundTransactions++
			if inboundTransactions > node.config.MaxInboundTransactions {
				return ErrSessionBudget
			}
			if err := node.acceptTransaction(value.Value); err != nil {
				if err := writeResult(stream, value.Value, wire.ResultRejected); err != nil {
					return err
				}
				continue
			}
			if err := writeResult(stream, value.Value, wire.ResultAccepted); err != nil {
				return err
			}
		case wire.Block:
			inboundBlocks++
			if inboundBlocks > node.config.MaxInboundBlocks {
				return ErrSessionBudget
			}
			id, idErr := value.Value.Header.ID()
			_, submitErr := node.sync.ApplyBlocks([]block.Block{value.Value})
			code := wire.ResultAccepted
			if idErr != nil || submitErr != nil {
				code = wire.ResultRejected
			}
			if submitErr == nil {
				_ = node.revalidatePool()
			}
			if idErr != nil {
				return idErr
			}
			if err := wire.WriteMessage(stream, wire.Result{Version: wire.Version0, Code: code, ObjectID: id}); err != nil {
				return err
			}
		case wire.GetPeers:
			peerRequests++
			if peerRequests > node.config.MaxPeerRequests {
				return ErrSessionBudget
			}
			records := node.discoveryRecords(int(value.Limit))
			encoded := make([][]byte, len(records))
			for index, record := range records {
				encoded[index] = record.CanonicalBytes()
			}
			if err := wire.WriteMessage(stream, wire.Peers{Version: wire.Version0, Records: encoded}); err != nil {
				return err
			}
		case wire.GetSnapshot:
			if snapshotServed || value.TipID != local.TipID {
				return ErrSnapshotTip
			}
			snapshotServed = true
			tip, err := node.ledger.TipByID(value.TipID)
			if err != nil {
				return err
			}
			source, err := node.ledger.SnapshotAt(value.TipID)
			if err != nil {
				return err
			}
			exporter, err := snapshotprotocol.NewExporter(node.networkID, tip, source, snapshotprotocol.DefaultChunkResources)
			if err != nil {
				return err
			}
			manifest := exporter.Manifest()
			if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
				return err
			}
			if err := wire.WriteMessage(stream, wire.SnapshotManifest{Version: wire.Version0, Value: manifest.CanonicalBytes()}); err != nil {
				return err
			}
			for index := uint32(0); index < manifest.ChunkCount; index++ {
				chunk, err := exporter.Chunk(index)
				if err != nil {
					return err
				}
				if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
					return err
				}
				if err := wire.WriteMessage(stream, wire.SnapshotChunk{Version: wire.Version0, Value: chunk.CanonicalBytes()}); err != nil {
					return err
				}
			}
			if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
				return err
			}
			if err := wire.WriteMessage(stream, wire.SnapshotDone{Version: wire.Version0, TipID: manifest.BlockID}); err != nil {
				return err
			}
		default:
			return ErrUnexpected
		}
	}
}

// Synchronize downloads bounded canonical batches from a better peer. The same
// fork-aware Chain.Submit path validates every received block independently.
func (node *Node) Synchronize(ctx context.Context, stream Stream) (wire.Status, error) {
	remote, err := node.initiatorHandshake(ctx, stream)
	if err != nil {
		return wire.Status{}, err
	}
	better, err := node.sync.PeerIsBetter(remote)
	if err != nil {
		return wire.Status{}, err
	}
	if !better {
		return node.sync.Status()
	}
	for batchIndex := 0; batchIndex < node.config.MaxSyncBatches; batchIndex++ {
		locators, err := node.sync.Locators()
		if err != nil {
			return wire.Status{}, err
		}
		headerRequest := wire.GetHeaders{Version: wire.Version0, Locators: locators, Limit: wire.MaxHeadersPerRequest}
		if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
			return wire.Status{}, err
		}
		if err := wire.WriteMessage(stream, headerRequest); err != nil {
			return wire.Status{}, err
		}
		message, err := wire.ReadMessage(stream)
		if err != nil {
			return wire.Status{}, err
		}
		headers, ok := message.(wire.Headers)
		if !ok {
			return wire.Status{}, ErrUnexpected
		}
		if len(headers.Values) == 0 {
			return wire.Status{}, ErrNoProgress
		}
		if err := node.sync.ValidateHeaders(headerRequest, headers, currentUnix()); err != nil {
			return wire.Status{}, err
		}
		if headers.TipID != remote.TipID {
			return wire.Status{}, ErrHeaderMismatch
		}
		lastHeader := headers.Values[len(headers.Values)-1]
		if lastHeader.Height == remote.TipHeight {
			lastID, err := lastHeader.ID()
			if err != nil || lastID != remote.TipID {
				return wire.Status{}, ErrHeaderMismatch
			}
		}
		request := wire.GetBlocks{Version: wire.Version0, Locators: locators, Limit: uint16(len(headers.Values))}
		if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
			return wire.Status{}, err
		}
		if err := wire.WriteMessage(stream, request); err != nil {
			return wire.Status{}, err
		}
		blocks, done, err := readBatch(stream)
		if err != nil {
			return wire.Status{}, err
		}
		if len(blocks) != len(headers.Values) || done.TipID != headers.TipID {
			return wire.Status{}, ErrHeaderMismatch
		}
		for index := range blocks {
			if blocks[index].Header != headers.Values[index] {
				return wire.Status{}, ErrHeaderMismatch
			}
		}
		if _, err := node.sync.ApplyBlocks(blocks); err != nil {
			return wire.Status{}, err
		}
		if err := node.revalidatePool(); err != nil {
			return wire.Status{}, err
		}
		local, err := node.sync.Status()
		if err != nil {
			return wire.Status{}, err
		}
		if local.TipID == done.TipID {
			return local, nil
		}
	}
	return wire.Status{}, ErrTooManyBatches
}

func (node *Node) SendTransaction(ctx context.Context, stream Stream, transaction outcome.Transaction) error {
	if _, err := node.initiatorHandshake(ctx, stream); err != nil {
		return err
	}
	if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
		return err
	}
	if err := wire.WriteMessage(stream, wire.Transaction{Value: transaction}); err != nil {
		return err
	}
	message, err := wire.ReadMessage(stream)
	if err != nil {
		return err
	}
	result, ok := message.(wire.Result)
	if !ok {
		return ErrUnexpected
	}
	id, err := transaction.ID()
	if err != nil {
		return err
	}
	if result.ObjectID != id || result.Code != wire.ResultAccepted {
		return ErrRejected
	}
	return nil
}

// Discover requests a bounded set of signed advertisements and atomically
// admits them to the attached address book after full validation.
func (node *Node) Discover(ctx context.Context, stream Stream, limit uint16) ([]discovery.Record, error) {
	if _, err := node.initiatorHandshake(ctx, stream); err != nil {
		return nil, err
	}
	return node.DiscoverEstablished(ctx, stream, limit)
}

// DiscoverEstablished exchanges peer records on a stream whose OutcomeMesh
// handshake has already completed. It lets a bounded long-running connector
// synchronize and refresh discovery without opening a second authenticated
// connection. Calling it on a fresh stream fails closed at the responder.
func (node *Node) DiscoverEstablished(ctx context.Context, stream Stream, limit uint16) ([]discovery.Record, error) {
	request := wire.GetPeers{Version: wire.Version0, Limit: limit}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
		return nil, err
	}
	if err := wire.WriteMessage(stream, request); err != nil {
		return nil, err
	}
	message, err := wire.ReadMessage(stream)
	if err != nil {
		return nil, err
	}
	response, ok := message.(wire.Peers)
	if !ok {
		return nil, ErrUnexpected
	}
	records := make([]discovery.Record, len(response.Records))
	now := currentUnix()
	for index, encoded := range response.Records {
		record, err := discovery.Decode(encoded)
		if err != nil {
			return nil, err
		}
		if err := record.Validate(now); err != nil {
			return nil, err
		}
		if record.NetworkID != node.networkID {
			return nil, discovery.ErrNetwork
		}
		records[index] = record
	}
	node.discoveryMu.RLock()
	book := node.book
	node.discoveryMu.RUnlock()
	if book != nil {
		if err := book.MergeBatch(records, now); err != nil {
			return nil, err
		}
	}
	return records, nil
}

// DownloadSnapshot downloads and verifies a bounded state snapshot against the
// state root advertised in the authenticated handshake. It intentionally does
// not mutate the ledger: callers must first establish the anchor through a
// separately validated history before any future import path may use it.
func (node *Node) DownloadSnapshot(ctx context.Context, stream Stream) (*state.Memory, wire.Status, error) {
	remote, err := node.initiatorHandshake(ctx, stream)
	if err != nil {
		return nil, wire.Status{}, err
	}
	if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
		return nil, wire.Status{}, err
	}
	if err := wire.WriteMessage(stream, wire.GetSnapshot{Version: wire.Version0, TipID: remote.TipID}); err != nil {
		return nil, wire.Status{}, err
	}
	message, err := wire.ReadMessage(stream)
	if err != nil {
		return nil, wire.Status{}, err
	}
	manifestMessage, ok := message.(wire.SnapshotManifest)
	if !ok {
		return nil, wire.Status{}, ErrUnexpected
	}
	manifest, err := snapshotprotocol.DecodeManifest(manifestMessage.Value)
	if err != nil {
		return nil, wire.Status{}, err
	}
	collector, err := snapshotprotocol.NewCollector(manifest, snapshotprotocol.Anchor{
		NetworkID: remote.NetworkID,
		BlockID:   remote.TipID,
		Height:    remote.TipHeight,
		StateRoot: remote.StateRoot,
	}, node.config.MaxSnapshotResources)
	if err != nil {
		return nil, wire.Status{}, err
	}
	for {
		if err := setDeadline(ctx, stream, node.config.RequestTimeout); err != nil {
			return nil, wire.Status{}, err
		}
		message, err := wire.ReadMessage(stream)
		if err != nil {
			return nil, wire.Status{}, err
		}
		switch value := message.(type) {
		case wire.SnapshotChunk:
			chunk, err := snapshotprotocol.DecodeChunk(value.Value)
			if err != nil {
				return nil, wire.Status{}, err
			}
			if err := collector.Add(chunk); err != nil {
				return nil, wire.Status{}, err
			}
		case wire.SnapshotDone:
			if value.TipID != remote.TipID {
				return nil, wire.Status{}, ErrSnapshotTip
			}
			verified, err := collector.Finalize()
			if err != nil {
				return nil, wire.Status{}, err
			}
			return verified, remote, nil
		default:
			return nil, wire.Status{}, ErrUnexpected
		}
	}
}

func (node *Node) initiatorHandshake(ctx context.Context, stream Stream) (wire.Status, error) {
	if err := setDeadline(ctx, stream, node.config.HandshakeTimeout); err != nil {
		return wire.Status{}, err
	}
	local, err := node.sync.Status()
	if err != nil {
		return wire.Status{}, err
	}
	if err := wire.WriteMessage(stream, local); err != nil {
		return wire.Status{}, err
	}
	message, err := wire.ReadMessage(stream)
	if err != nil {
		return wire.Status{}, err
	}
	remote, ok := message.(wire.Status)
	if !ok {
		return wire.Status{}, ErrUnexpected
	}
	if err := node.sync.ValidatePeer(remote); err != nil {
		return wire.Status{}, err
	}
	return remote, nil
}

func (node *Node) responderHandshake(ctx context.Context, stream Stream) (wire.Status, wire.Status, error) {
	if err := setDeadline(ctx, stream, node.config.HandshakeTimeout); err != nil {
		return wire.Status{}, wire.Status{}, err
	}
	message, err := wire.ReadMessage(stream)
	if err != nil {
		return wire.Status{}, wire.Status{}, err
	}
	remote, ok := message.(wire.Status)
	if !ok {
		return wire.Status{}, wire.Status{}, ErrUnexpected
	}
	if err := node.sync.ValidatePeer(remote); err != nil {
		return wire.Status{}, wire.Status{}, err
	}
	local, err := node.sync.Status()
	if err != nil {
		return wire.Status{}, wire.Status{}, err
	}
	if err := wire.WriteMessage(stream, local); err != nil {
		return wire.Status{}, wire.Status{}, err
	}
	return remote, local, nil
}

func (node *Node) acceptTransaction(transaction outcome.Transaction) error {
	if node.pool == nil {
		return ErrRejected
	}
	tip, err := node.ledger.Tip()
	if err != nil {
		return err
	}
	if tip.Height == ^uint64(0) {
		return ErrRejected
	}
	preState, err := node.ledger.Snapshot()
	if err != nil {
		return err
	}
	_, err = node.pool.Add(preState, transaction, execution.Context{NetworkID: node.networkID, Height: tip.Height + 1})
	return err
}

func (node *Node) revalidatePool() error {
	if node.pool == nil {
		return nil
	}
	tip, err := node.ledger.Tip()
	if err != nil {
		return err
	}
	if tip.Height == ^uint64(0) {
		return ErrRejected
	}
	preState, err := node.ledger.Snapshot()
	if err != nil {
		return err
	}
	node.pool.Revalidate(preState, execution.Context{NetworkID: node.networkID, Height: tip.Height + 1})
	return nil
}

func (node *Node) discoveryRecords(limit int) []discovery.Record {
	node.discoveryMu.RLock()
	book := node.book
	node.discoveryMu.RUnlock()
	if book == nil {
		return nil
	}
	return book.List(currentUnix(), limit)
}

func currentUnix() uint64 {
	now := time.Now().Unix()
	if now < 0 {
		return 0
	}
	return uint64(now)
}

func readBatch(stream Stream) ([]block.Block, wire.BatchDone, error) {
	blocks := make([]block.Block, 0, wire.MaxBlocksPerRequest)
	for {
		message, err := wire.ReadMessage(stream)
		if err != nil {
			return nil, wire.BatchDone{}, err
		}
		switch value := message.(type) {
		case wire.Block:
			if len(blocks) == wire.MaxBlocksPerRequest {
				return nil, wire.BatchDone{}, ErrUnexpected
			}
			blocks = append(blocks, value.Value)
		case wire.BatchDone:
			return blocks, value, nil
		default:
			return nil, wire.BatchDone{}, ErrUnexpected
		}
	}
}

func writeResult(stream Stream, transaction outcome.Transaction, code wire.ResultCode) error {
	id, err := transaction.ID()
	if err != nil {
		return err
	}
	return wire.WriteMessage(stream, wire.Result{Version: wire.Version0, Code: code, ObjectID: id})
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
