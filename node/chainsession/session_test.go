package chainsession

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/chainblock"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

type chainFixture struct {
	document genesis.Document
	ledger   *reference.Store
	router   *activation.Router
	node     *Node
	config   activation.Config
}

func TestSessionSynchronizesDivergentBranchAcrossActivation(t *testing.T) {
	t.Parallel()

	sessionConfig := DefaultSessionConfig()
	sessionConfig.BatchSize = 2
	sessionConfig.MaxSyncBatches = 8
	source := newChainFixture(t, 731, 2, sessionConfig)
	destinationConfig := sessionConfig
	destinationConfig.MaxFrameBytes = wire.MinVersionedChainFrameBodyBytes
	destination := newChainFixture(t, 731, 2, destinationConfig)
	defer source.ledger.Close()
	defer destination.ledger.Close()
	extendChain(t, source, "source", 4)
	extendChain(t, destination, "destination", 2)
	destinationBefore, _ := destination.router.Tip()
	if destinationBefore.Height != 3 {
		t.Fatalf("destination setup height=%d", destinationBefore.Height)
	}

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- source.node.Serve(ctx, server) }()
	tip, err := destination.node.Synchronize(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	sourceTip, _ := source.router.Tip()
	if !storage.EqualTips(tip, sourceTip) {
		t.Fatalf("synchronized tip=%+v source=%+v", tip, sourceTip)
	}
	activationBlock, err := destination.router.BlockByID(sourceChainIDAt(t, source, 2))
	if err != nil || activationBlock.Version() != workblock.Version1 {
		t.Fatalf("activation block version=%d err=%v", activationBlock.Version(), err)
	}
}

func TestResponderPathRemainsPinnedWhileSelectedChainAdvances(t *testing.T) {
	source := newChainFixture(t, 739, 2, DefaultSessionConfig())
	remote := newChainFixture(t, 739, 2, DefaultSessionConfig())
	defer source.ledger.Close()
	defer remote.ledger.Close()
	extendChain(t, source, "pinned", 2)
	oldTip, err := source.router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- source.node.Serve(ctx, server) }()
	remoteHello, err := remote.node.Status()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, remoteHello); err != nil {
		t.Fatal(err)
	}
	message, err := wire.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	servedHello, ok := message.(wire.ChainHello)
	if !ok || servedHello.TipID != oldTip.ID {
		t.Fatalf("served hello=%+v, want tip %s", message, oldTip.ID)
	}
	newTipID := mineWork(t, source, "newer")
	genesisID, err := source.document.ID()
	if err != nil {
		t.Fatal(err)
	}
	headerRequest := wire.GetVersionedHeaders{
		Version: wire.Version1, Locators: []types.Hash{genesisID}, Limit: wire.MaxHeadersPerRequest,
	}
	if err := wire.WriteMessage(client, headerRequest); err != nil {
		t.Fatal(err)
	}
	message, err = wire.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	headers, ok := message.(wire.VersionedHeaders)
	if !ok || headers.TipID != oldTip.ID || len(headers.Values) != int(oldTip.Height) {
		t.Fatalf("pinned response=%+v, want tip %s with %d headers", message, oldTip.ID, oldTip.Height)
	}
	for _, header := range headers.Values {
		id, idErr := header.ID()
		if idErr != nil || id == newTipID {
			t.Fatalf("pinned response leaked post-handshake tip %s (error %v)", newTipID, idErr)
		}
	}
	blockRequest := wire.GetVersionedBlocks{
		Version: wire.Version1, Locators: headerRequest.Locators, Limit: uint16(len(headers.Values)),
	}
	if err := wire.WriteMessage(client, blockRequest); err != nil {
		t.Fatal(err)
	}
	for range headers.Values {
		message, err = wire.ReadMessage(client)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := message.(wire.VersionedBlock); !ok {
			t.Fatalf("body response=%T, want VersionedBlock", message)
		}
	}
	message, err = wire.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	done, ok := message.(wire.VersionedBatchDone)
	if !ok || done.TipID != oldTip.ID {
		t.Fatalf("pinned batch done=%+v, want tip %s", message, oldTip.ID)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestHeaderFirstSessionRejectsInvalidHeaderBeforeBodies(t *testing.T) {
	t.Parallel()

	config := DefaultSessionConfig()
	source := newChainFixture(t, 732, 3, config)
	destination := newChainFixture(t, 732, 3, config)
	defer source.ledger.Close()
	defer destination.ledger.Close()
	mineLegacy(t, source, "invalid-header-source")

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type serverResult struct {
		bodyRequested bool
		err           error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		defer server.Close()
		message, err := wire.ReadMessage(server)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		if _, ok := message.(wire.ChainHello); !ok {
			serverDone <- serverResult{err: ErrUnexpected}
			return
		}
		hello, err := source.node.Status()
		if err == nil {
			err = wire.WriteMessage(server, hello)
		}
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		message, err = wire.ReadMessage(server)
		request, ok := message.(wire.GetVersionedHeaders)
		if err != nil || !ok {
			serverDone <- serverResult{err: err}
			return
		}
		headers, err := source.node.HeadersAfter(request)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		legacy, ok := headers.Values[0].LegacyHeader()
		if !ok {
			serverDone <- serverResult{err: ErrUnexpected}
			return
		}
		legacy.Timestamp = source.document.Timestamp
		headers.Values[0], err = chainblock.LegacyHeader(legacy)
		if err == nil {
			err = wire.WriteMessage(server, headers)
		}
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		message, err = wire.ReadMessage(server)
		_, bodyRequested := message.(wire.GetVersionedBlocks)
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			err = nil
		}
		serverDone <- serverResult{bodyRequested: bodyRequested, err: err}
	}()

	_, err := destination.node.Synchronize(ctx, client)
	if !errors.Is(err, legacyblock.ErrMedianTimePast) {
		t.Fatalf("invalid header error=%v", err)
	}
	result := <-serverDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.bodyRequested {
		t.Fatal("client requested bodies after versioned header validation failed")
	}
	tip, _ := destination.router.Tip()
	if tip.Height != 0 {
		t.Fatalf("invalid header changed destination height=%d", tip.Height)
	}
}

func TestSessionHandshakeRejectsDifferentActivationHeight(t *testing.T) {
	t.Parallel()

	left := newChainFixture(t, 733, 2, DefaultSessionConfig())
	right := newChainFixture(t, 733, 3, DefaultSessionConfig())
	defer left.ledger.Close()
	defer right.ledger.Close()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- left.node.Serve(ctx, server) }()
	_, _ = right.node.Synchronize(ctx, client)
	if err := <-serverDone; !errors.Is(err, ErrActivation) {
		t.Fatalf("activation mismatch error=%v", err)
	}
}

func TestActivationSessionAtomicallyRefreshesSignedPeerbook(t *testing.T) {
	t.Parallel()

	source := newChainFixture(t, 740, 2, DefaultSessionConfig())
	destination := newChainFixture(t, 740, 2, DefaultSessionConfig())
	defer source.ledger.Close()
	defer destination.ledger.Close()
	now := uint64(time.Now().Unix())
	seed := types.DomainHash("test/chainsession/discovery-key")
	record, err := discovery.SignActivation(
		ed25519.NewKeyFromSeed(seed[:]), 740, 1, now+600, 2,
		discovery.FeatureVersionedChainV1|discovery.FeatureWorkGraphV1|discovery.FeaturePeerExchangeV1,
		[]string{"127.0.0.1:9845"},
	)
	if err != nil {
		t.Fatal(err)
	}
	sourceBook, _ := discovery.NewBook(740, 8)
	destinationBook, _ := discovery.NewBook(740, 8)
	if err := sourceBook.Add(record, now); err != nil {
		t.Fatal(err)
	}
	source.node.AttachDiscovery(sourceBook)
	destination.node.AttachDiscovery(destinationBook)

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- source.node.Serve(ctx, server) }()
	records, err := destination.node.Discover(ctx, client, wire.MaxPeerRecords)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || destinationBook.Len(now) != 1 ||
		!records[0].Supports(discovery.FeatureWorkGraphV1|discovery.FeaturePeerExchangeV1, 2) {
		t.Fatalf("discovered records=%+v book=%d", records, destinationBook.Len(now))
	}
}

func TestActivationDiscoveryFitsNegotiatedFrameBudget(t *testing.T) {
	t.Parallel()

	source := newChainFixture(t, 742, 2, DefaultSessionConfig())
	destinationConfig := DefaultSessionConfig()
	destinationConfig.MaxFrameBytes = wire.MinVersionedChainFrameBodyBytes
	destination := newChainFixture(t, 742, 2, destinationConfig)
	defer source.ledger.Close()
	defer destination.ledger.Close()
	now := uint64(time.Now().Unix())
	sourceBook, _ := discovery.NewBook(742, 8)
	destinationBook, _ := discovery.NewBook(742, 8)
	addresses := []string{
		"127.0.0.1:9840", "127.0.0.1:9841", "127.0.0.1:9842", "127.0.0.1:9843",
		"127.0.0.1:9844", "127.0.0.1:9845", "127.0.0.1:9846", "127.0.0.1:9847",
	}
	for index, address := range addresses {
		seed := types.DomainHash("test/chainsession/frame-budget-discovery", []byte{byte(index)})
		record, err := discovery.SignActivation(
			ed25519.NewKeyFromSeed(seed[:]), 742, 1, now+600, 2,
			discovery.FeatureVersionedChainV1|discovery.FeaturePeerExchangeV1,
			[]string{address},
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := sourceBook.Add(record, now); err != nil {
			t.Fatal(err)
		}
	}
	source.node.AttachDiscovery(sourceBook)
	destination.node.AttachDiscovery(destinationBook)

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- source.node.Serve(ctx, server) }()
	records, err := destination.node.Discover(ctx, client, wire.MaxPeerRecords)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 || len(records) >= len(addresses) || destinationBook.Len(now) != len(records) {
		t.Fatalf("frame-limited discovery returned=%d stored=%d", len(records), destinationBook.Len(now))
	}
}

func TestActivationDiscoveryRejectsForeignHeightBatchAtomically(t *testing.T) {
	t.Parallel()

	source := newChainFixture(t, 741, 2, DefaultSessionConfig())
	destination := newChainFixture(t, 741, 2, DefaultSessionConfig())
	defer source.ledger.Close()
	defer destination.ledger.Close()
	destinationBook, _ := discovery.NewBook(741, 8)
	destination.node.AttachDiscovery(destinationBook)
	now := uint64(time.Now().Unix())
	sign := func(label string, activationHeight uint64) discovery.Record {
		seed := types.DomainHash("test/chainsession/foreign-discovery", []byte(label))
		record, err := discovery.SignActivation(
			ed25519.NewKeyFromSeed(seed[:]), 741, 1, now+600, activationHeight,
			discovery.FeatureVersionedChainV1|discovery.FeaturePeerExchangeV1,
			[]string{"127.0.0.1:9845"},
		)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	valid := sign("valid", 2)
	foreign := sign("foreign", 3)
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := wire.ReadMessage(server); err != nil {
			serverDone <- err
			return
		}
		hello, err := source.node.Status()
		if err == nil {
			err = wire.WriteMessage(server, hello)
		}
		if err == nil {
			_, err = wire.ReadMessage(server)
		}
		if err == nil {
			err = wire.WriteMessage(server, wire.Peers{Version: wire.Version0, Records: [][]byte{
				valid.CanonicalBytes(), foreign.CanonicalBytes(),
			}})
		}
		serverDone <- err
	}()
	if _, err := destination.node.Discover(ctx, client, wire.MaxPeerRecords); !errors.Is(err, discovery.ErrCapabilities) {
		t.Fatalf("foreign activation discovery error=%v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := destinationBook.Len(now); got != 0 {
		t.Fatalf("foreign activation batch partially applied records=%d", got)
	}
}

func TestSessionBindsReplayedTipToHelloWork(t *testing.T) {
	t.Parallel()

	config := DefaultSessionConfig()
	source := newChainFixture(t, 734, 3, config)
	destination := newChainFixture(t, 734, 3, config)
	defer source.ledger.Close()
	defer destination.ledger.Close()
	mineLegacy(t, source, "lying-status-source")

	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		defer server.Close()
		if _, err := wire.ReadMessage(server); err != nil {
			serverDone <- err
			return
		}
		hello, err := source.node.Status()
		if err != nil {
			serverDone <- err
			return
		}
		hello.CumulativeWork = append([]byte{1}, hello.CumulativeWork...)
		if err := wire.WriteMessage(server, hello); err != nil {
			serverDone <- err
			return
		}
		message, err := wire.ReadMessage(server)
		headerRequest, ok := message.(wire.GetVersionedHeaders)
		if err != nil || !ok {
			serverDone <- err
			return
		}
		headers, err := source.node.HeadersAfter(headerRequest)
		if err == nil {
			err = wire.WriteMessage(server, headers)
		}
		if err != nil {
			serverDone <- err
			return
		}
		message, err = wire.ReadMessage(server)
		blockRequest, ok := message.(wire.GetVersionedBlocks)
		if err != nil || !ok {
			serverDone <- err
			return
		}
		blocks, done, err := source.node.BlocksAfter(blockRequest)
		if err != nil {
			serverDone <- err
			return
		}
		for _, candidate := range blocks {
			if err := wire.WriteMessage(server, wire.VersionedBlock{Version: wire.Version1, Value: candidate}); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- wire.WriteMessage(server, done)
	}()

	if _, err := destination.node.Synchronize(ctx, client); !errors.Is(err, ErrHeaderMismatch) {
		t.Fatalf("lying hello work error=%v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestServeRequiresHeaderRequestBeforeBodies(t *testing.T) {
	t.Parallel()

	source := newChainFixture(t, 735, 2, DefaultSessionConfig())
	peer := newChainFixture(t, 735, 2, DefaultSessionConfig())
	defer source.ledger.Close()
	defer peer.ledger.Close()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- source.node.Serve(ctx, server) }()
	hello, err := peer.node.Status()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadMessage(client); err != nil {
		t.Fatal(err)
	}
	locators, err := peer.node.Locators()
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, wire.GetVersionedBlocks{
		Version: wire.Version1, Locators: locators, Limit: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; !errors.Is(err, ErrUnexpected) {
		t.Fatalf("body-first request error=%v", err)
	}
	_ = client.Close()
}

func newChainFixture(
	t testing.TB,
	networkID uint32,
	activationHeight uint64,
	sessionConfig SessionConfig,
) chainFixture {
	t.Helper()
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version: genesis.Version0, NetworkID: networkID, Timestamp: 1_700_000_000,
		Target: target, BlockSubsidy: 10_220,
	}
	ledger, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyblock.ParametersFromGenesis(document)
	activationConfig := activation.Config{
		Legacy: legacy,
		Work: workblock.Parameters{
			NetworkID: networkID, BlockSubsidy: document.BlockSubsidy,
			RewardMaturity: legacy.RewardMaturity, ActivationHeight: activationHeight,
			DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
			TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: 3,
		},
		Now: func() uint64 { return document.Timestamp + 100_000 },
	}
	router, err := activation.New(ledger, activationConfig)
	if err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	node, err := NewNode(router, document, sessionConfig)
	if err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	return chainFixture{document: document, ledger: ledger, router: router, node: node, config: activationConfig}
}

func extendChain(t testing.TB, fixture chainFixture, label string, workBlocks int) {
	t.Helper()
	mineLegacy(t, fixture, label+"-base")
	for index := 0; index < workBlocks; index++ {
		mineWork(t, fixture, label+string(rune('a'+index)))
	}
}

func mineLegacy(t testing.TB, fixture chainFixture, label string) types.Hash {
	t.Helper()
	parent, err := fixture.router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	preState, err := fixture.ledger.SnapshotAt(parent.ID)
	if err != nil {
		t.Fatal(err)
	}
	parentContext, err := storage.ParentContext(fixture.ledger, parent)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := legacyblock.Prepare(
		preState, parentContext, nil, chainAddress(label),
		parent.Timestamp+fixture.config.Legacy.TargetSpacing, fixture.config.Legacy,
	)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err = legacyblock.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := activation.Legacy(candidate, fixture.config.Work.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.router.Submit(routed); err != nil {
		t.Fatal(err)
	}
	id, _ := routed.ID()
	return id
}

func mineWork(t testing.TB, fixture chainFixture, label string) types.Hash {
	t.Helper()
	parent, err := fixture.router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := fixture.router.PrepareWork(
		parent.ID, parent.Timestamp+fixture.config.Work.TargetSpacing, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	template, err := payload.SealTemplate(chainAddress(label), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	seal, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := payload.Finalize(seal, nil)
	if err != nil {
		t.Fatal(err)
	}
	routed, err := activation.Work(candidate, fixture.config.Work.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.router.Submit(routed); err != nil {
		t.Fatal(err)
	}
	id, _ := routed.ID()
	return id
}

func sourceChainIDAt(t testing.TB, fixture chainFixture, height uint64) types.Hash {
	t.Helper()
	path, err := fixture.node.canonicalPath()
	if err != nil {
		t.Fatal(err)
	}
	return path.nodes[height-1].id
}

func chainAddress(label string) types.Address {
	return types.Address(types.DomainHash("test/chainsession/miner", []byte(label)))
}
