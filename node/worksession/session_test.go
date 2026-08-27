package worksession

import (
	"context"
	"errors"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/node/workpool"
)

func TestRelayNegotiatesAndResolvesOutOfOrderDAG(t *testing.T) {
	t.Parallel()

	validation := testContext()
	sourcePool, _ := workpool.New(validation)
	destinationPool, _ := workpool.New(validation)
	parent := mineWeak(t, testShare(validation, "parent", nil), true)
	parentID, _ := parent.ID()
	child := mineWeak(t, testShare(validation, "child", []types.Hash{parentID}), true)
	if _, err := sourcePool.Add(child); err != nil {
		t.Fatal(err)
	}
	if _, err := sourcePool.Add(parent); err != nil {
		t.Fatal(err)
	}
	source := newNode(t, sourcePool, DefaultConfig())
	destination := newNode(t, destinationPool, DefaultConfig())

	stats, serverErr := exchange(t, source, destination)
	if serverErr != nil {
		t.Fatal(serverErr)
	}
	if stats.Announced != 2 || stats.Requested != 2 || stats.Accepted != 2 || stats.Rejected != 0 {
		t.Fatalf("relay stats=%+v", stats)
	}
	status := destinationPool.Status()
	if status.Shares != 2 || status.Accepted != 2 || status.Pending != 0 || status.Tips != 1 {
		t.Fatalf("destination status=%+v", status)
	}
}

func TestMaximumRelayApplicationByteBudget(t *testing.T) {
	t.Parallel()

	if got := MaximumRelayApplicationBytes(); got != 630_258 {
		t.Fatalf("maximum relay application bytes=%d", got)
	}
}

func TestRelayClampsBatchesToNegotiatedFrame(t *testing.T) {
	t.Parallel()

	validation := testContext()
	sourcePool, _ := workpool.New(validation)
	destinationPool, _ := workpool.New(validation)
	for index := 0; index < 3; index++ {
		share := mineWeak(t, testShare(validation, string(rune('a'+index)), nil), true)
		if _, err := sourcePool.Add(share); err != nil {
			t.Fatal(err)
		}
	}
	source := newNode(t, sourcePool, DefaultConfig())
	limited := DefaultConfig()
	limited.MaxFrameBytes = wire.MinWorkFrameBodyBytes
	destination := newNode(t, destinationPool, limited)

	stats, serverErr := exchange(t, source, destination)
	if serverErr != nil {
		t.Fatal(serverErr)
	}
	if stats.Batches != 3 || stats.Accepted != 3 {
		t.Fatalf("negotiated batches=%+v", stats)
	}
}

func TestRelaySelectedInventoryReportsNegotiatedPrefix(t *testing.T) {
	validation := testContext()
	sourcePool, _ := workpool.New(validation)
	destinationPool, _ := workpool.New(validation)
	for index := 0; index < 3; index++ {
		share := mineWeak(t, testShare(validation, string(rune('k'+index)), nil), true)
		if _, err := sourcePool.Add(share); err != nil {
			t.Fatal(err)
		}
	}
	ids := sourcePool.Inventory(3)
	source := newNode(t, sourcePool, DefaultConfig())
	destinationConfig := DefaultConfig()
	destinationConfig.MaxInventory = 2
	destination := newNode(t, destinationPool, destinationConfig)
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- destination.Serve(ctx, server) }()
	stats, err := source.RelayInventory(ctx, client, ids)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if stats.Announced != 2 || stats.Accepted != 2 || destinationPool.Status().Shares != 2 {
		t.Fatalf("selected relay stats=%+v pool=%+v", stats, destinationPool.Status())
	}
	unknown := append([]types.Hash(nil), ids[:1]...)
	unknown[0] = types.DomainHash("test/worksession/unknown-selection")
	left, right := net.Pipe()
	defer right.Close()
	if _, err := source.RelayInventory(ctx, left, unknown); !errors.Is(err, workpool.ErrUnknownParent) {
		t.Fatalf("unknown selected inventory error=%v", err)
	}
}

func TestHandshakeRejectsDifferentMiningContext(t *testing.T) {
	t.Parallel()

	leftContext := testContext()
	rightContext := leftContext
	rightContext.PayloadRoot = types.DomainHash("test/worksession/other-payload")
	leftPool, _ := workpool.New(leftContext)
	rightPool, _ := workpool.New(rightContext)
	left := newNode(t, leftPool, DefaultConfig())
	right := newNode(t, rightPool, DefaultConfig())
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- right.Serve(ctx, server) }()
	_, _ = left.Relay(ctx, client)
	if err := <-serverDone; !errors.Is(err, ErrContext) {
		t.Fatalf("context mismatch error=%v", err)
	}
}

func TestServeCountsInvalidWeakProofAsRejected(t *testing.T) {
	t.Parallel()

	validation := testContext()
	destinationPool, _ := workpool.New(validation)
	destination := newNode(t, destinationPool, DefaultConfig())
	invalid := mineWeak(t, testShare(validation, "invalid-pow", nil), false)
	invalidID, _ := invalid.ID()
	contextValue := shareContext(validation)
	hello := wire.WorkHello{
		Version: wire.Version1, Context: contextValue, Features: wire.WorkFeatureShareRelayV1,
		MaxFrameBytes: wire.MaxWorkFrameBodyBytes, MaxInventory: wire.MaxShareInventoryIDs,
		MaxShareBodies: wire.MaxSharesPerMessage,
	}
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- destination.Serve(ctx, server) }()
	if err := wire.WriteMessage(client, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadMessage(client); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, wire.ShareInventory{
		Version: wire.Version1, Context: contextValue, IDs: []types.Hash{invalidID},
	}); err != nil {
		t.Fatal(err)
	}
	message, err := wire.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := message.(wire.GetShares)
	if !ok || len(request.IDs) != 1 || request.IDs[0] != invalidID {
		t.Fatalf("request=%+v", message)
	}
	if err := wire.WriteMessage(client, wire.Shares{
		Version: wire.Version1, Context: contextValue, Values: []workgraph.Share{invalid},
	}); err != nil {
		t.Fatal(err)
	}
	message, err = wire.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := message.(wire.ShareResult)
	if !ok || result.Accepted != 0 || result.Rejected != 1 {
		t.Fatalf("result=%+v", message)
	}
	_ = client.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if status := destinationPool.Status(); status.Shares != 0 {
		t.Fatalf("invalid proof entered pool: %+v", status)
	}
}

func TestServeAccountsForAdvertisedButWithheldBody(t *testing.T) {
	t.Parallel()

	validation := testContext()
	destinationPool, _ := workpool.New(validation)
	destination := newNode(t, destinationPool, DefaultConfig())
	values := []workgraph.Share{
		mineWeak(t, testShare(validation, "withheld-a", nil), true),
		mineWeak(t, testShare(validation, "withheld-b", nil), true),
	}
	sort.Slice(values, func(left, right int) bool {
		leftID, _ := values[left].ID()
		rightID, _ := values[right].ID()
		return types.CompareHash(leftID, rightID) < 0
	})
	ids := make([]types.Hash, len(values))
	for index := range values {
		ids[index], _ = values[index].ID()
	}
	contextValue := shareContext(validation)
	hello := wire.WorkHello{
		Version: wire.Version1, Context: contextValue, Features: wire.WorkFeatureShareRelayV1,
		MaxFrameBytes: wire.MaxWorkFrameBodyBytes, MaxInventory: wire.MaxShareInventoryIDs,
		MaxShareBodies: wire.MaxSharesPerMessage,
	}
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- destination.Serve(ctx, server) }()
	if err := wire.WriteMessage(client, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadMessage(client); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(client, wire.ShareInventory{
		Version: wire.Version1, Context: contextValue, IDs: ids,
	}); err != nil {
		t.Fatal(err)
	}
	message, err := wire.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := message.(wire.GetShares)
	if !ok || len(request.IDs) != 2 {
		t.Fatalf("request=%+v", message)
	}
	if err := wire.WriteMessage(client, wire.Shares{
		Version: wire.Version1, Context: contextValue, Values: values[:1],
	}); err != nil {
		t.Fatal(err)
	}
	message, err = wire.ReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := message.(wire.ShareResult)
	if !ok || result.Accepted != 1 || result.Rejected != 1 {
		t.Fatalf("withheld result=%+v", message)
	}
	_ = client.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestRelayRejectsRepeatedRequest(t *testing.T) {
	t.Parallel()

	validation := testContext()
	sourcePool, _ := workpool.New(validation)
	share := mineWeak(t, testShare(validation, "repeat", nil), true)
	shareID, err := sourcePool.Add(share)
	if err != nil {
		t.Fatal(err)
	}
	source := newNode(t, sourcePool, DefaultConfig())
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peerDone := make(chan error, 1)
	go func() {
		message, err := wire.ReadMessage(server)
		hello, ok := message.(wire.WorkHello)
		if err != nil || !ok {
			peerDone <- err
			return
		}
		if err := wire.WriteMessage(server, hello); err != nil {
			peerDone <- err
			return
		}
		if _, err := wire.ReadMessage(server); err != nil {
			peerDone <- err
			return
		}
		request := wire.GetShares{Version: wire.Version1, Context: hello.Context, IDs: []types.Hash{shareID}}
		if err := wire.WriteMessage(server, request); err != nil {
			peerDone <- err
			return
		}
		if _, err := wire.ReadMessage(server); err != nil {
			peerDone <- err
			return
		}
		peerDone <- wire.WriteMessage(server, request)
	}()
	if _, err := source.Relay(ctx, client); !errors.Is(err, ErrNoProgress) {
		t.Fatalf("repeated request error=%v", err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func exchange(t testing.TB, source, destination *Node) (Stats, error) {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- destination.Serve(ctx, server) }()
	stats, err := source.Relay(ctx, client)
	if err != nil {
		return Stats{}, err
	}
	return stats, <-serverDone
}

func newNode(t testing.TB, pool *workpool.Pool, config Config) *Node {
	t.Helper()
	node, err := New(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func testContext() workgraph.Context {
	var target types.Hash
	target[2] = 0x7f
	for index := 3; index < len(target); index++ {
		target[index] = 0xff
	}
	return workgraph.Context{
		NetworkID: 81, Height: 9, AnchorParent: types.DomainHash("test/worksession/anchor"),
		AnchorTarget: target, PayloadRoot: types.DomainHash("test/worksession/payload"),
		AnchorTimestamp: 1_700_000_100, MedianTimePast: 1_700_000_000,
	}
}

func testShare(validation workgraph.Context, label string, parents []types.Hash) workgraph.Share {
	inclusion, _ := workgraph.InclusionRoot(nil)
	return workgraph.Share{
		Version: workgraph.Version0, NetworkID: validation.NetworkID, Height: validation.Height,
		AnchorParent: validation.AnchorParent, Timestamp: validation.AnchorTimestamp,
		Target: validation.AnchorTarget, PayloadRoot: validation.PayloadRoot,
		Miner:         types.Address(types.DomainHash("test/worksession/miner", []byte(label))),
		InclusionRoot: inclusion, Parents: append([]types.Hash(nil), parents...),
	}
}

func mineWeak(t testing.TB, template workgraph.Share, valid bool) workgraph.Share {
	t.Helper()
	for nonce := uint64(0); ; nonce++ {
		candidate := template
		candidate.Nonce = nonce
		err := workgraph.ValidateShare(testContext(), candidate)
		if valid && err == nil {
			hard, hardErr := workgraph.MeetsAnchor(candidate)
			if hardErr == nil && !hard {
				return candidate
			}
		}
		if !valid && err != nil {
			return candidate
		}
	}
}
