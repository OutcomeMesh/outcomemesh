// Command omd manages the standalone OutcomeMesh development node.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/mempool"
	"github.com/outcomemesh/outcomemesh/node/peers"
	"github.com/outcomemesh/outcomemesh/node/routing"
	"github.com/outcomemesh/outcomemesh/node/session"
	"github.com/outcomemesh/outcomemesh/node/syncer"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
	pebblestore "github.com/outcomemesh/outcomemesh/storage/pebble"
	"github.com/outcomemesh/outcomemesh/wallet"
)

const (
	defaultDataDirectory  = "./outcomemesh-data"
	genesisFilename       = "genesis.bin"
	ledgerDirectory       = "ledger"
	peerbookFilename      = "peers.bin"
	reputationFilename    = "reputation.bin"
	storagePolicyFilename = "storage-policy.bin"
	minimumHistoryBytes   = 64 << 20
)

var storagePolicyMagic = [8]byte{'O', 'M', 'H', 'I', 'S', 'T', '0', '0'}

var peerBookSaveMu sync.Mutex

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		printUsage()
		return errors.New("missing command")
	}
	switch arguments[0] {
	case "keygen":
		return runKeygen(arguments[1:])
	case "init":
		return runInit(arguments[1:])
	case "status":
		return runStatus(arguments[1:])
	case "balance":
		return runBalance(arguments[1:])
	case "transfer":
		return runTransfer(arguments[1:])
	case "mine":
		return runMine(arguments[1:])
	case "verify":
		return runVerify(arguments[1:])
	case "serve":
		return runServe(arguments[1:])
	case "sync":
		return runPeerSync(arguments[1:])
	case "peers":
		return runPeerDiscovery(arguments[1:])
	case "snapshot-check":
		return runSnapshotCheck(arguments[1:])
	case "serve-quic":
		return runServeQUIC(arguments[1:])
	case "sync-quic":
		return runSyncQUIC(arguments[1:])
	case "peers-quic":
		return runPeersQUIC(arguments[1:])
	case "auto-sync-quic":
		return runAutoSyncQUIC(arguments[1:])
	case "work-enable":
		return runWorkEnable(arguments[1:])
	case "work-status":
		return runWorkStatus(arguments[1:])
	case "work-balance":
		return runWorkBalance(arguments[1:])
	case "work-verify":
		return runWorkVerify(arguments[1:])
	case "work-mine":
		return runWorkMine(arguments[1:])
	case "work-mine-quic":
		return runWorkMineQUIC(arguments[1:])
	case "work-serve-quic":
		return runWorkServeQUIC(arguments[1:])
	case "work-sync-quic":
		return runWorkSyncQUIC(arguments[1:])
	case "work-telemetry-policy":
		return runWorkTelemetryPolicy(arguments[1:])
	case "work-telemetry-tie-plan":
		return runWorkTelemetryTiePlan(arguments[1:])
	case "work-telemetry-tie-produce":
		return runWorkTelemetryTieProduce(arguments[1:])
	case "work-telemetry-tie-campaign":
		return runWorkTelemetryTieCampaign(arguments[1:])
	case "work-telemetry-tie-campaign-audit":
		return runWorkTelemetryTieCampaignAudit(arguments[1:])
	case "work-telemetry-tie-campaign-recover":
		return runWorkTelemetryTieCampaignRecover(arguments[1:])
	case "work-telemetry-tie-campaign-receive-quic":
		return runWorkTelemetryTieCampaignReceiveQUIC(arguments[1:])
	case "work-telemetry-tie-pair-create":
		return runWorkTelemetryTiePairCreate(arguments[1:])
	case "work-telemetry-tie-pair-checkpoint":
		return runWorkTelemetryTiePairCheckpoint(arguments[1:])
	case "work-telemetry-tie-pair-admit":
		return runWorkTelemetryTiePairAdmit(arguments[1:])
	case "work-telemetry-tie-pair-receive-quic":
		return runWorkTelemetryTiePairReceiveQUIC(arguments[1:])
	case "work-telemetry-tie-pair-send-quic":
		return runWorkTelemetryTiePairSendQUIC(arguments[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func runKeygen(arguments []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	output := flags.String("out", "wallet.key", "new seed file (created with mode 0600)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	if _, err := file.Write(seed); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	address, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	fmt.Printf("created key=%s address=%s\n", *output, address)
	return nil
}

func runInit(arguments []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	network := flags.Uint("network", 20260826, "non-zero network identifier")
	timestamp := flags.Uint64("timestamp", 0, "genesis Unix timestamp (default: now)")
	leadingZeroBits := flags.Uint("difficulty-bits", 12, "development target leading zero bits")
	subsidy := flags.Uint64("subsidy", 5_000_000_000, "raw native units minted per block")
	supply := flags.Uint64("supply", 100_000_000_000_000, "raw native units in the genesis allocation")
	maxHistoryBytes := flags.Uint64("max-history-bytes", pebblestore.DefaultMaxHistoryBytes, "logical immutable ledger-history budget")
	ownerText := flags.String("owner", defaultDevelopmentAddress().String(), "genesis allocation address as 64 hex characters")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *network == 0 || *network > uint(^uint32(0)) {
		return errors.New("network must fit a non-zero uint32")
	}
	if *maxHistoryBytes < minimumHistoryBytes {
		return fmt.Errorf("max-history-bytes must be at least %d", minimumHistoryBytes)
	}
	if *timestamp == 0 {
		*timestamp = uint64(time.Now().Unix())
	}
	owner, err := parseAddress(*ownerText)
	if err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	target, err := targetWithLeadingZeroBits(*leadingZeroBits)
	if err != nil {
		return err
	}
	allocationID := types.ResourceID(types.DomainHash(
		"OMESH/genesis/allocation/v0",
		[]byte(strconv.FormatUint(uint64(*network), 10)),
		owner[:],
	))
	document := genesis.Document{
		Version:      genesis.Version0,
		NetworkID:    uint32(*network),
		Timestamp:    *timestamp,
		Target:       target,
		BlockSubsidy: *subsidy,
		Allocations: []resource.Resource{{
			ID:      allocationID,
			Version: resource.Version0,
			Owner:   owner,
			Asset:   types.NativeAssetID(),
			Amount:  *supply,
		}},
	}
	if err := document.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(*data, 0o755); err != nil {
		return err
	}
	genesisPath := filepath.Join(*data, genesisFilename)
	file, err := os.OpenFile(genesisPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create genesis file: %w", err)
	}
	if _, err := file.Write(document.CanonicalBytes()); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := writeStoragePolicy(*data, *maxHistoryBytes); err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	tip, err := store.Tip()
	if err != nil {
		return err
	}
	fmt.Printf("initialized network=%d genesis=%s state=%s owner=%s target=%s\n", document.NetworkID, tip.ID, tip.StateRoot, owner, target)
	return nil
}

func runStatus(arguments []string) error {
	data, store, document, err := openNode(arguments, "status")
	if err != nil {
		return err
	}
	defer store.Close()
	tip, err := store.Tip()
	if err != nil {
		return err
	}
	state, err := store.Snapshot()
	if err != nil {
		return err
	}
	historyBytes, historyLimit, err := store.HistoryUsage()
	if err != nil {
		return err
	}
	fmt.Printf("data=%s network=%d height=%d tip=%s state=%s resources=%d cumulative_work=%x history_bytes=%d history_limit=%d\n", data, document.NetworkID, tip.Height, tip.ID, tip.StateRoot, state.Len(), tip.CumulativeWork, historyBytes, historyLimit)
	return nil
}

func runBalance(arguments []string) error {
	flags := flag.NewFlagSet("balance", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	addressText := flags.String("address", "", "address as 64 hex characters (default: first genesis owner)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "balance"); err != nil {
		return err
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	var address types.Address
	if *addressText == "" {
		if len(document.Allocations) == 0 {
			return errors.New("genesis has no default allocation owner")
		}
		address = document.Allocations[0].Owner
	} else {
		address, err = parseAddress(*addressText)
		if err != nil {
			return err
		}
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	state, err := store.Snapshot()
	if err != nil {
		return err
	}
	balance, err := state.Balance(address, types.NativeAssetID())
	if err != nil {
		return err
	}
	tip, err := store.Tip()
	if err != nil {
		return err
	}
	if tip.Height == ^uint64(0) {
		return errors.New("tip height overflow")
	}
	spendable, err := state.SpendableBalance(address, types.NativeAssetID(), tip.Height+1)
	if err != nil {
		return err
	}
	locked, err := types.SubAmount(balance, spendable)
	if err != nil {
		return err
	}
	fmt.Printf("address=%s asset=%s total=%d spendable_next_height=%d locked=%d\n", address, types.NativeAssetID(), balance, spendable, locked)
	return nil
}

func runTransfer(arguments []string) error {
	flags := flag.NewFlagSet("transfer", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "Ed25519 seed file created by keygen")
	recipientText := flags.String("to", "", "recipient address as 64 hex characters")
	amount := flags.Uint64("amount", 0, "raw native units to transfer")
	fee := flags.Uint64("fee", 1, "raw native fee units")
	validFor := flags.Uint64("valid-for", 100, "validity window in block heights")
	minerText := flags.String("miner", "", "reward address (default: sender)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "transfer"); err != nil {
		return err
	}
	if *keyPath == "" || *recipientText == "" {
		return errors.New("key and to are required")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	recipient, err := parseAddress(*recipientText)
	if err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	sender, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	miner := sender
	if *minerText != "" {
		miner, err = parseAddress(*minerText)
		if err != nil {
			return fmt.Errorf("miner: %w", err)
		}
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	tip, err := store.Tip()
	if err != nil {
		return err
	}
	preState, err := store.Snapshot()
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	transaction, err := wallet.BuildNativeTransfer(preState, privateKey, wallet.TransferRequest{
		NetworkID:     document.NetworkID,
		CurrentHeight: tip.Height,
		ValidFor:      *validFor,
		Recipient:     recipient,
		Amount:        *amount,
		Fee:           *fee,
		Nonce:         nonce,
	})
	if err != nil {
		return err
	}
	transactionID, err := transaction.ID()
	if err != nil {
		return err
	}
	chainService, err := chain.New(store, block.ParametersFromGenesis(document))
	if err != nil {
		return err
	}
	timestamp := uint64(time.Now().Unix())
	if timestamp <= tip.Timestamp {
		timestamp = tip.Timestamp + 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := chainService.Mine(ctx, []outcome.Transaction{transaction}, miner, timestamp, 0)
	if err != nil {
		return err
	}
	fmt.Printf("transferred tx=%s block=%s height=%d sender=%s recipient=%s amount=%d fee=%d\n", transactionID, result.ID, result.Tip.Height, sender, recipient, *amount, *fee)
	return nil
}

func runMine(arguments []string) error {
	flags := flag.NewFlagSet("mine", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	minerText := flags.String("miner", defaultDevelopmentAddress().String(), "reward address as 64 hex characters")
	count := flags.Uint64("count", 1, "number of empty development blocks")
	startNonce := flags.Uint64("start-nonce", 0, "first nonce to test")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "mine"); err != nil {
		return err
	}
	if *count == 0 {
		return errors.New("count must be positive")
	}
	miner, err := parseAddress(*minerText)
	if err != nil {
		return fmt.Errorf("miner: %w", err)
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	chainService, err := chain.New(store, block.ParametersFromGenesis(document))
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for index := uint64(0); index < *count; index++ {
		tip, err := chainService.Status()
		if err != nil {
			return err
		}
		timestamp := uint64(time.Now().Unix())
		if timestamp <= tip.Timestamp {
			timestamp = tip.Timestamp + 1
		}
		started := time.Now()
		result, err := chainService.Mine(ctx, nil, miner, timestamp, *startNonce)
		if err != nil {
			return err
		}
		fmt.Printf("mined height=%d id=%s nonce=%d elapsed=%s state=%s\n", result.Tip.Height, result.ID, result.Block.Header.Nonce, time.Since(started).Round(time.Millisecond), result.Tip.StateRoot)
	}
	return nil
}

func runVerify(arguments []string) error {
	data, store, document, err := openNode(arguments, "verify")
	if err != nil {
		return err
	}
	defer store.Close()
	tip, err := verifyLegacyLedger(store, document)
	if err != nil {
		return err
	}
	fmt.Printf("verified data=%s height=%d tip=%s state=%s\n", data, tip.Height, tip.ID, tip.StateRoot)
	return nil
}

func verifyLegacyLedger(store storage.Ledger, document genesis.Document) (storage.Tip, error) {
	tip, err := store.Tip()
	if err != nil {
		return storage.Tip{}, err
	}
	currentState, err := document.State()
	if err != nil {
		return storage.Tip{}, err
	}
	currentTip, err := storage.GenesisTip(document)
	if err != nil {
		return storage.Tip{}, err
	}
	parameters := block.ParametersFromGenesis(document)
	for height := uint64(1); height <= tip.Height; height++ {
		candidate, err := store.Block(height)
		if err != nil {
			return storage.Tip{}, err
		}
		parent, err := storage.ParentContext(store, currentTip)
		if err != nil {
			return storage.Tip{}, err
		}
		executed, err := block.ValidateAndExecuteAt(currentState, parent, candidate, parameters, uint64(time.Now().Unix()))
		if err != nil {
			return storage.Tip{}, fmt.Errorf("block %d: %w", height, err)
		}
		currentTip, err = storage.NextTip(currentTip, candidate)
		if err != nil {
			return storage.Tip{}, err
		}
		currentState = executed.State
	}
	if currentState.Root() != tip.StateRoot || currentTip.ID != tip.ID {
		return storage.Tip{}, errors.New("replayed chain does not match stored tip")
	}
	return tip, nil
}

func runServe(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	listenAddress := flags.String("listen", "127.0.0.1:9844", "TLS/TCP peer listen address")
	advertiseAddress := flags.String("advertise", "", "IP:port advertised to peers (default: actual listen address)")
	maxConnections := flags.Int("max-connections", 64, "maximum concurrent peer sessions")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "serve"); err != nil {
		return err
	}
	if *keyPath == "" || *maxConnections <= 0 {
		return errors.New("key is required and max-connections must be positive")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	identity, err := transport.NewIdentity(privateKey)
	if err != nil {
		return err
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	listener, err := transport.Listen(*listenAddress, identity)
	if err != nil {
		return err
	}
	defer listener.Close()
	advertised := *advertiseAddress
	if advertised == "" {
		advertised = listener.Addr().String()
	}
	now := uint64(time.Now().Unix())
	sequence := uint64(time.Now().UnixNano())
	if sequence == 0 {
		sequence = 1
	}
	addressBook, err := openPeerBook(*data, document.NetworkID, now)
	if err != nil {
		return err
	}
	sequence, err = addressBook.NextSequence(identity.ID(), sequence)
	if err != nil {
		return err
	}
	record, err := discovery.Sign(identity.PrivateKey(), document.NetworkID, sequence, now+uint64(time.Hour/time.Second), []string{advertised})
	if err != nil {
		return fmt.Errorf("advertise address: %w", err)
	}
	if err := addressBook.Add(record, now); err != nil {
		return err
	}
	if err := savePeerBook(*data, addressBook, now); err != nil {
		return err
	}
	sessionService.AttachDiscovery(addressBook)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	fmt.Printf("serving peer_id=%s listen=%s network=%d\n", identity.ID(), listener.Addr(), document.NetworkID)
	semaphore := make(chan struct{}, *maxConnections)
	peerManager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		cancel()
		return err
	}
	var sessions sync.WaitGroup
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				cancel()
				sessions.Wait()
				return nil
			}
			cancel()
			sessions.Wait()
			return err
		}
		select {
		case semaphore <- struct{}{}:
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				defer func() { <-semaphore }()
				closed := make(chan struct{})
				go func() {
					select {
					case <-ctx.Done():
						_ = connection.Close()
					case <-closed:
					}
				}()
				defer close(closed)
				tlsConnection, ok := connection.(*tls.Conn)
				if !ok {
					_ = connection.Close()
					return
				}
				handshakeContext, handshakeCancel := context.WithTimeout(ctx, session.DefaultConfig().HandshakeTimeout)
				if err := tlsConnection.HandshakeContext(handshakeContext); err != nil {
					handshakeCancel()
					_ = connection.Close()
					return
				}
				handshakeCancel()
				peerID, peerErr := transport.PeerID(tlsConnection)
				if peerErr != nil || peerManager.Acquire(peerID) != nil {
					_ = connection.Close()
					return
				}
				defer peerManager.Release(peerID)
				limited := &peerLimitedStream{Stream: connection, manager: peerManager, peerID: peerID}
				sessionErr := sessionService.Serve(ctx, limited)
				if sessionErr == nil {
					_ = peerManager.Record(peerID, peers.EventValidMessage)
				} else if networkError, ok := sessionErr.(net.Error); ok && networkError.Timeout() {
					_ = peerManager.Record(peerID, peers.EventTimeout)
				} else {
					_ = peerManager.Record(peerID, peers.EventInvalidMessage)
				}
				if sessionErr != nil && ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "peer session %s: %v\n", peerID, sessionErr)
				}
			}()
		default:
			_ = connection.Close()
		}
	}
}

func runPeerSync(arguments []string) error {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	peerAddress := flags.String("peer", "", "TLS/TCP peer address")
	peerIDText := flags.String("peer-id", "", "expected peer ID as 64 hex characters")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "sync"); err != nil {
		return err
	}
	if *keyPath == "" || *peerAddress == "" {
		return errors.New("key and peer are required")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	identity, err := transport.NewIdentity(privateKey)
	if err != nil {
		return err
	}
	var expectedPeer *types.Hash
	if *peerIDText != "" {
		parsed, err := parseHash(*peerIDText)
		if err != nil {
			return fmt.Errorf("peer-id: %w", err)
		}
		expectedPeer = &parsed
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	connection, peerID, err := transport.Dial(ctx, *peerAddress, identity, expectedPeer)
	if err != nil {
		return err
	}
	defer connection.Close()
	status, err := sessionService.Synchronize(ctx, connection)
	if err != nil {
		return err
	}
	fmt.Printf("synced peer_id=%s height=%d tip=%s cumulative_work=%x\n", peerID, status.TipHeight, status.TipID, status.CumulativeWork)
	return nil
}

func runServeQUIC(arguments []string) error {
	flags := flag.NewFlagSet("serve-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	listenAddress := flags.String("listen", "/ip4/127.0.0.1/udp/9844/quic-v1", "QUIC-v1 libp2p listen multiaddress")
	maxConnections := flags.Int("max-connections", 64, "maximum authenticated QUIC connections")
	maxStreamsPerPeer := flags.Int("max-streams-per-peer", 4, "maximum concurrent streams per peer")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "serve-quic"); err != nil {
		return err
	}
	if *keyPath == "" || *maxConnections <= 0 || *maxConnections > libp2ptransport.MaxConnectionLimit ||
		*maxStreamsPerPeer <= 0 || *maxStreamsPerPeer > libp2ptransport.MaxStreamsPerPeerLimit {
		return fmt.Errorf("key is required, max-connections must be 1..%d, and max-streams-per-peer must be 1..%d",
			libp2ptransport.MaxConnectionLimit, libp2ptransport.MaxStreamsPerPeerLimit)
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	peerManager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{*listenAddress}
	config.MaxConnections = *maxConnections
	config.MaxStreamsPerPeer = *maxStreamsPerPeer
	// Keep the descriptor scope coherent when an operator raises the
	// connection limit above the default. QUIC may share sockets, but reserving
	// two descriptors per configured connection avoids an accidental hidden
	// ceiling while the resource manager still enforces its absolute cap.
	config.MaxFileDescriptors = max(config.MaxFileDescriptors, 2*config.MaxConnections)
	host, err := libp2ptransport.New(ctx, privateKey, config, func(handlerContext context.Context, peerID types.Hash, stream libp2pnetwork.Stream) {
		if err := peerManager.Acquire(peerID); err != nil {
			_ = stream.Reset()
			return
		}
		defer peerManager.Release(peerID)
		limited := &peerLimitedStream{Stream: stream, manager: peerManager, peerID: peerID}
		sessionErr := sessionService.Serve(handlerContext, limited)
		recordPeerSession(peerManager, peerID, sessionErr)
		if sessionErr != nil && handlerContext.Err() == nil {
			fmt.Fprintf(os.Stderr, "QUIC peer session %s: %v\n", peerID, sessionErr)
		}
	})
	if err != nil {
		return err
	}
	defer host.Close()
	now := uint64(time.Now().Unix())
	sequence := uint64(time.Now().UnixNano())
	if sequence == 0 {
		sequence = 1
	}
	addressBook, err := openPeerBook(*data, document.NetworkID, now)
	if err != nil {
		return err
	}
	sequence, err = addressBook.NextSequence(host.ID(), sequence)
	if err != nil {
		return err
	}
	record, err := discovery.Sign(privateKey, document.NetworkID, sequence, now+uint64(time.Hour/time.Second), host.Addresses())
	if err != nil {
		return err
	}
	if err := addressBook.Add(record, now); err != nil {
		return err
	}
	if err := savePeerBook(*data, addressBook, now); err != nil {
		return err
	}
	sessionService.AttachDiscovery(addressBook)
	fmt.Printf("serving_quic peer_id=%s libp2p_id=%s network=%d listen=%s\n",
		host.ID(), host.Libp2pID(), document.NetworkID, strings.Join(host.Addresses(), ","))
	refresh := time.NewTicker(30 * time.Minute)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-refresh.C:
			now = uint64(time.Now().Unix())
			suggested := uint64(time.Now().UnixNano())
			if suggested == 0 {
				suggested = sequence
			}
			sequence, err = addressBook.NextSequence(host.ID(), suggested)
			if err != nil {
				return err
			}
			record, err = discovery.Sign(privateKey, document.NetworkID, sequence, now+uint64(time.Hour/time.Second), host.Addresses())
			if err != nil {
				return err
			}
			if err := addressBook.Add(record, now); err != nil {
				return err
			}
			if err := savePeerBook(*data, addressBook, now); err != nil {
				return err
			}
		}
	}
}

func runSyncQUIC(arguments []string) error {
	flags := flag.NewFlagSet("sync-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	peerAddress := flags.String("peer", "", "QUIC-v1 libp2p multiaddress including /p2p/<id>")
	peerIDText := flags.String("peer-id", "", "expected OutcomeMesh peer ID as 64 hex characters")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "sync-quic"); err != nil {
		return err
	}
	if *keyPath == "" || *peerAddress == "" {
		return errors.New("key and peer are required")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	var expectedPeer *types.Hash
	if *peerIDText != "" {
		parsed, err := parseHash(*peerIDText)
		if err != nil {
			return fmt.Errorf("peer-id: %w", err)
		}
		expectedPeer = &parsed
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	host, err := libp2ptransport.New(ctx, privateKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		return err
	}
	defer host.Close()
	stream, peerID, err := host.OpenStream(ctx, *peerAddress, expectedPeer)
	if err != nil {
		return err
	}
	defer stream.Close()
	status, err := sessionService.Synchronize(ctx, stream)
	if err != nil {
		return err
	}
	fmt.Printf("synced_quic peer_id=%s height=%d tip=%s cumulative_work=%x\n",
		peerID, status.TipHeight, status.TipID, status.CumulativeWork)
	return nil
}

func runPeersQUIC(arguments []string) error {
	flags := flag.NewFlagSet("peers-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	peerAddress := flags.String("peer", "", "QUIC-v1 libp2p multiaddress including /p2p/<id>")
	peerIDText := flags.String("peer-id", "", "expected OutcomeMesh peer ID as 64 hex characters")
	limit := flags.Uint("limit", 32, "maximum signed peer records to request")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "peers-quic"); err != nil {
		return err
	}
	if *keyPath == "" || *peerAddress == "" {
		return errors.New("key and peer are required")
	}
	if *limit == 0 || *limit > wire.MaxPeerRecords {
		return fmt.Errorf("limit must be between 1 and %d", wire.MaxPeerRecords)
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	var expectedPeer *types.Hash
	if *peerIDText != "" {
		parsed, err := parseHash(*peerIDText)
		if err != nil {
			return fmt.Errorf("peer-id: %w", err)
		}
		expectedPeer = &parsed
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	addressBook, err := openPeerBook(*data, document.NetworkID, now)
	if err != nil {
		return err
	}
	sessionService.AttachDiscovery(addressBook)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	host, err := libp2ptransport.New(ctx, privateKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		return err
	}
	defer host.Close()
	stream, peerID, err := host.OpenStream(ctx, *peerAddress, expectedPeer)
	if err != nil {
		return err
	}
	defer stream.Close()
	records, err := sessionService.Discover(ctx, stream, uint16(*limit))
	if err != nil {
		return err
	}
	if err := savePeerBook(*data, addressBook, now); err != nil {
		return err
	}
	fmt.Printf("discovered_quic_from=%s records=%d\n", peerID, len(records))
	for _, record := range records {
		id, err := record.PeerID()
		if err != nil {
			return err
		}
		fmt.Printf("peer_id=%s sequence=%d expires=%d addresses=%s\n", id, record.Sequence, record.ExpiresAt, strings.Join(record.Addresses, ","))
	}
	return nil
}

func runAutoSyncQUIC(arguments []string) error {
	flags := flag.NewFlagSet("auto-sync-quic", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	limit := flags.Int("limit", 8, "maximum eligible persisted peers to try once")
	asnMapPath := flags.String("asn-map", "", "optional local CIDR,ASN table for diversity-aware selection")
	asnMaxAge := flags.Duration("asn-max-age", 24*time.Hour, "maximum accepted age of the local ASN table")
	maxPerASN := flags.Int("max-per-asn", 2, "maximum dial attempts from one resolved ASN per pass")
	watchInterval := flags.Duration("watch-interval", 0, "repeat bounded passes at this interval; requires --asn-map")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "auto-sync-quic"); err != nil {
		return err
	}
	if *keyPath == "" || *limit <= 0 || *limit > wire.MaxPeerRecords || *maxPerASN <= 0 || *maxPerASN > wire.MaxPeerRecords {
		return fmt.Errorf("key is required, and limit/max-per-asn must be between 1 and %d", wire.MaxPeerRecords)
	}
	if *watchInterval < 0 || *watchInterval > routing.MaxSchedulerInterval ||
		(*watchInterval > 0 && (*watchInterval < 5*time.Second || *asnMapPath == "")) {
		return errors.New("watch-interval must be zero or 5s..1h and requires --asn-map")
	}
	if *asnMaxAge <= 0 || *asnMaxAge > routing.MaxASNTableAge {
		return fmt.Errorf("asn-max-age must be between 1ns and %s", routing.MaxASNTableAge)
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	now := func() uint64 {
		current := time.Now().Unix()
		if current < 0 {
			return 0
		}
		return uint64(current)
	}
	addressBook, err := openPeerBook(*data, document.NetworkID, now())
	if err != nil {
		return err
	}
	peerManager, err := openPeerManager(*data)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	host, err := libp2ptransport.New(ctx, privateKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		return err
	}
	defer host.Close()
	routingPolicy := routing.DefaultPolicy()
	routingPolicy.MaxPerASN = *maxPerASN
	var managedASN *routing.ManagedASNTable
	if *asnMapPath != "" {
		managedASN, err = routing.NewManagedASNTable(*asnMapPath, *asnMaxAge, time.Now)
		if err != nil {
			return err
		}
		routingPolicy.ASNResolver = managedASN
	}
	router, err := routing.NewWithPolicy(addressBook, peerManager, host.ID(), now, routingPolicy)
	if err != nil {
		return err
	}
	connector := func(connectorContext context.Context, record discovery.Record) error {
		peerID, err := record.PeerID()
		if err != nil {
			return err
		}
		before, err := store.Tip()
		if err != nil {
			return err
		}
		dialStarted := time.Now()
		stream, _, err := host.OpenRecord(connectorContext, record, document.NetworkID, now())
		if err != nil {
			return err
		}
		defer stream.Close()
		if err := peerManager.ObserveLatency(peerID, time.Since(dialStarted)); err != nil {
			return err
		}
		if _, err = sessionService.Synchronize(connectorContext, stream); err != nil {
			return err
		}
		after, err := store.Tip()
		if err != nil {
			return err
		}
		if !storage.EqualTips(before, after) {
			if err := peerManager.Record(peerID, peers.EventUsefulSync); err != nil {
				return err
			}
		}
		if _, err = sessionService.DiscoverEstablished(connectorContext, stream, wire.MaxPeerRecords); err != nil {
			return err
		}
		return savePeerBook(*data, addressBook, now())
	}
	printResults := func(results []routing.Result) (int, []error) {
		succeeded := 0
		var failures []error
		for _, result := range results {
			if result.Err == nil {
				succeeded++
				fmt.Printf("auto_sync_quic peer_id=%s result=ok\n", result.PeerID)
			} else {
				failures = append(failures, result.Err)
				fmt.Printf("auto_sync_quic peer_id=%s result=failed error=%q\n", result.PeerID, result.Err)
			}
		}
		return succeeded, failures
	}
	if *watchInterval > 0 {
		scheduler, err := routing.NewScheduler(router, routing.SchedulerConfig{
			Interval: *watchInterval, AttemptLimit: *limit, Preflight: managedASN.Refresh,
		}, connector, func(results []routing.Result) error {
			succeeded, _ := printResults(results)
			if err := peers.SaveFile(filepath.Join(*data, reputationFilename), peerManager); err != nil {
				return err
			}
			status, statusErr := store.Tip()
			if statusErr != nil {
				return statusErr
			}
			fmt.Printf("auto_sync_quic_pass attempts=%d succeeded=%d height=%d tip=%s\n", len(results), succeeded, status.Height, status.ID)
			return nil
		})
		if err != nil {
			return err
		}
		fmt.Printf("auto_sync_quic_watch interval=%s limit=%d asn_map=%s\n", watchInterval.String(), *limit, *asnMapPath)
		return scheduler.Run(ctx)
	}
	results := router.RunOnce(ctx, *limit, connector)
	if err := peers.SaveFile(filepath.Join(*data, reputationFilename), peerManager); err != nil {
		return err
	}
	succeeded, failures := printResults(results)
	if succeeded == 0 {
		if len(failures) == 0 {
			return errors.New("no eligible QUIC peers in persisted peerbook")
		}
		return errors.Join(failures...)
	}
	status, err := store.Tip()
	if err != nil {
		return err
	}
	fmt.Printf("auto_sync_quic_complete attempts=%d succeeded=%d height=%d tip=%s\n", len(results), succeeded, status.Height, status.ID)
	return nil
}

func runPeerDiscovery(arguments []string) error {
	flags := flag.NewFlagSet("peers", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	peerAddress := flags.String("peer", "", "TLS/TCP peer address")
	peerIDText := flags.String("peer-id", "", "expected peer ID as 64 hex characters")
	limit := flags.Uint("limit", 32, "maximum signed peer records to request")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "peers"); err != nil {
		return err
	}
	if *keyPath == "" || *peerAddress == "" {
		return errors.New("key and peer are required")
	}
	if *limit == 0 || *limit > wire.MaxPeerRecords {
		return fmt.Errorf("limit must be between 1 and %d", wire.MaxPeerRecords)
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	identity, err := transport.NewIdentity(privateKey)
	if err != nil {
		return err
	}
	var expectedPeer *types.Hash
	if *peerIDText != "" {
		parsed, err := parseHash(*peerIDText)
		if err != nil {
			return fmt.Errorf("peer-id: %w", err)
		}
		expectedPeer = &parsed
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	addressBook, err := openPeerBook(*data, document.NetworkID, now)
	if err != nil {
		return err
	}
	sessionService.AttachDiscovery(addressBook)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	connection, peerID, err := transport.Dial(ctx, *peerAddress, identity, expectedPeer)
	if err != nil {
		return err
	}
	defer connection.Close()
	records, err := sessionService.Discover(ctx, connection, uint16(*limit))
	if err != nil {
		return err
	}
	if err := savePeerBook(*data, addressBook, now); err != nil {
		return err
	}
	fmt.Printf("discovered_from=%s records=%d\n", peerID, len(records))
	for _, record := range records {
		id, err := record.PeerID()
		if err != nil {
			return err
		}
		fmt.Printf("peer_id=%s sequence=%d expires=%d addresses=%s\n", id, record.Sequence, record.ExpiresAt, strings.Join(record.Addresses, ","))
	}
	return nil
}

func runSnapshotCheck(arguments []string) error {
	flags := flag.NewFlagSet("snapshot-check", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	keyPath := flags.String("key", "", "persistent Ed25519 seed file created by keygen")
	peerAddress := flags.String("peer", "", "TLS/TCP peer address")
	peerIDText := flags.String("peer-id", "", "expected peer ID as 64 hex characters")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := rejectWorkActivation(*data, "snapshot-check"); err != nil {
		return err
	}
	if *keyPath == "" || *peerAddress == "" {
		return errors.New("key and peer are required")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	identity, err := transport.NewIdentity(privateKey)
	if err != nil {
		return err
	}
	var expectedPeer *types.Hash
	if *peerIDText != "" {
		parsed, err := parseHash(*peerIDText)
		if err != nil {
			return fmt.Errorf("peer-id: %w", err)
		}
		expectedPeer = &parsed
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return err
	}
	defer store.Close()
	sessionService, err := buildSession(store, document)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	connection, peerID, err := transport.Dial(ctx, *peerAddress, identity, expectedPeer)
	if err != nil {
		return err
	}
	defer connection.Close()
	verified, remote, err := sessionService.DownloadSnapshot(ctx, connection)
	if err != nil {
		return err
	}
	fmt.Printf("snapshot_verified peer_id=%s height=%d tip=%s state=%s resources=%d imported=false\n",
		peerID, remote.TipHeight, remote.TipID, verified.Root(), verified.Len())
	return nil
}

func buildSession(ledger storage.Ledger, document genesis.Document) (*session.Node, error) {
	chainService, err := chain.New(ledger, block.ParametersFromGenesis(document))
	if err != nil {
		return nil, err
	}
	syncService, err := syncer.New(ledger, chainService, document)
	if err != nil {
		return nil, err
	}
	pool, err := mempool.New(mempool.DefaultPolicy())
	if err != nil {
		return nil, err
	}
	return session.New(syncService, ledger, pool, session.DefaultConfig())
}

func openNode(arguments []string, name string) (string, *pebblestore.Store, genesis.Document, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "node data directory")
	if err := flags.Parse(arguments); err != nil {
		return "", nil, genesis.Document{}, err
	}
	if err := rejectWorkActivation(*data, name); err != nil {
		return "", nil, genesis.Document{}, err
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return "", nil, genesis.Document{}, err
	}
	store, err := openStore(*data, document)
	if err != nil {
		return "", nil, genesis.Document{}, err
	}
	return *data, store, document, nil
}

func openStore(data string, document genesis.Document) (*pebblestore.Store, error) {
	policy := pebblestore.DefaultPolicy()
	encoded, err := os.ReadFile(filepath.Join(data, storagePolicyFilename))
	if err == nil {
		if len(encoded) != len(storagePolicyMagic)+8 || string(encoded[:len(storagePolicyMagic)]) != string(storagePolicyMagic[:]) {
			return nil, errors.New("invalid storage policy file")
		}
		policy.MaxHistoryBytes = binary.BigEndian.Uint64(encoded[len(storagePolicyMagic):])
		if policy.MaxHistoryBytes < minimumHistoryBytes {
			return nil, errors.New("storage policy history budget is below the minimum")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read storage policy: %w", err)
	}
	return pebblestore.OpenWithPolicy(filepath.Join(data, ledgerDirectory), document, policy)
}

func writeStoragePolicy(data string, maxHistoryBytes uint64) error {
	if maxHistoryBytes < minimumHistoryBytes {
		return errors.New("storage policy history budget is below the minimum")
	}
	path := filepath.Join(data, storagePolicyFilename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create storage policy: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	encoded := make([]byte, len(storagePolicyMagic)+8)
	copy(encoded, storagePolicyMagic[:])
	binary.BigEndian.PutUint64(encoded[len(storagePolicyMagic):], maxHistoryBytes)
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func loadGenesis(data string) (genesis.Document, error) {
	encoded, err := os.ReadFile(filepath.Join(data, genesisFilename))
	if err != nil {
		return genesis.Document{}, fmt.Errorf("read genesis file: %w", err)
	}
	document, err := genesis.Decode(encoded)
	if err != nil {
		return genesis.Document{}, fmt.Errorf("decode genesis file: %w", err)
	}
	return document, nil
}

func openPeerBook(data string, networkID uint32, now uint64) (*discovery.Book, error) {
	path := filepath.Join(data, peerbookFilename)
	book, err := discovery.LoadFile(path, networkID, discovery.DefaultPolicy(), now)
	if errors.Is(err, os.ErrNotExist) {
		return discovery.NewBookWithPolicy(networkID, discovery.DefaultPolicy())
	}
	return book, err
}

func savePeerBook(data string, book *discovery.Book, now uint64) error {
	peerBookSaveMu.Lock()
	defer peerBookSaveMu.Unlock()
	return discovery.SaveFile(filepath.Join(data, peerbookFilename), book, now)
}

func openPeerManager(data string) (*peers.Manager, error) {
	path := filepath.Join(data, reputationFilename)
	manager, err := peers.LoadFile(path, peers.DefaultPolicy(), nil)
	if os.IsNotExist(err) {
		return peers.New(peers.DefaultPolicy(), nil)
	}
	return manager, err
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key file contains %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func parseAddress(input string) (types.Address, error) {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		return types.Address{}, err
	}
	if len(decoded) != types.AddressSize {
		return types.Address{}, fmt.Errorf("got %d bytes, want %d", len(decoded), types.AddressSize)
	}
	var address types.Address
	copy(address[:], decoded)
	if address.IsZero() {
		return types.Address{}, errors.New("zero address is reserved")
	}
	return address, nil
}

func parseHash(input string) (types.Hash, error) {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		return types.Hash{}, err
	}
	if len(decoded) != types.HashSize {
		return types.Hash{}, fmt.Errorf("got %d bytes, want %d", len(decoded), types.HashSize)
	}
	var result types.Hash
	copy(result[:], decoded)
	if result.IsZero() {
		return types.Hash{}, errors.New("zero hash is reserved")
	}
	return result, nil
}

type peerLimitedStream struct {
	session.Stream
	manager *peers.Manager
	peerID  types.Hash
}

func (stream *peerLimitedStream) Read(output []byte) (int, error) {
	count, err := stream.Stream.Read(output)
	if count > 0 {
		if limitErr := stream.manager.AllowInbound(stream.peerID, uint64(count)); limitErr != nil {
			return 0, limitErr
		}
	}
	return count, err
}

func (stream *peerLimitedStream) Write(input []byte) (int, error) {
	if err := stream.manager.AllowOutbound(stream.peerID, uint64(len(input))); err != nil {
		return 0, err
	}
	return stream.Stream.Write(input)
}

func recordPeerSession(manager *peers.Manager, peerID types.Hash, sessionErr error) {
	if sessionErr == nil {
		_ = manager.Record(peerID, peers.EventValidMessage)
	} else if networkError, ok := sessionErr.(net.Error); ok && networkError.Timeout() {
		_ = manager.Record(peerID, peers.EventTimeout)
	} else {
		_ = manager.Record(peerID, peers.EventInvalidMessage)
	}
}

func targetWithLeadingZeroBits(bits uint) (types.Hash, error) {
	if bits >= 256 {
		return types.Hash{}, errors.New("difficulty-bits must be less than 256")
	}
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	fullBytes := bits / 8
	partialBits := bits % 8
	for index := uint(0); index < fullBytes; index++ {
		target[index] = 0
	}
	if partialBits > 0 {
		target[fullBytes] = byte(0xff >> partialBits)
	}
	return target, nil
}

func defaultDevelopmentAddress() types.Address {
	return types.Address(types.DomainHash("OMESH/development/default-address/v0"))
}

func printUsage() {
	fmt.Println("OutcomeMesh standalone development node")
	fmt.Println("usage: omd <keygen|init|status|balance|transfer|mine|verify|serve|sync|peers|snapshot-check|serve-quic|sync-quic|peers-quic|auto-sync-quic|work-enable|work-status|work-balance|work-verify|work-mine|work-mine-quic|work-serve-quic|work-sync-quic|work-telemetry-policy|work-telemetry-tie-plan|work-telemetry-tie-produce|work-telemetry-tie-campaign|work-telemetry-tie-campaign-audit|work-telemetry-tie-campaign-recover|work-telemetry-tie-campaign-receive-quic|work-telemetry-tie-pair-create|work-telemetry-tie-pair-checkpoint|work-telemetry-tie-pair-admit|work-telemetry-tie-pair-receive-quic|work-telemetry-tie-pair-send-quic> [flags]")
}
