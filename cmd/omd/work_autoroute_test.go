package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"

	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/peers"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workround"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

func TestAutomaticWorkPeersProbeCapabilityAndStopAtRequestedCount(t *testing.T) {
	const networkID uint32 = 20260828
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	round := testAutomaticWorkRound(t, networkID, 0)

	unsupportedKey, unsupportedHost := testAutomaticWorkHost(t, ctx, "unsupported", nil)
	firstKey, firstHost := testAutomaticWorkHost(t, ctx, "compatible-a", testAutomaticWorkRound(t, networkID, 30))
	secondKey, secondHost := testAutomaticWorkHost(t, ctx, "compatible-b", testAutomaticWorkRound(t, networkID, 300))
	unusedKey, unusedHost := testAutomaticWorkHost(t, ctx, "unused", testAutomaticWorkRound(t, networkID, 600))
	clientKey := testAutomaticWorkKey("client")
	client, err := libp2ptransport.New(ctx, clientKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	now := uint64(time.Now().Unix())
	records := []discovery.Record{
		testAutomaticWorkRecord(t, unsupportedKey, networkID, now, unsupportedHost),
		testAutomaticWorkRecord(t, firstKey, networkID, now, firstHost),
		testAutomaticWorkRecord(t, secondKey, networkID, now, secondHost),
		testAutomaticWorkRecord(t, unusedKey, networkID, now, unusedHost),
	}
	book, err := discovery.NewBookWithPolicy(networkID, discovery.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := book.AddBatch(records, now); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	if err := discovery.SaveFile(filepath.Join(data, peerbookFilename), book, now); err != nil {
		t.Fatal(err)
	}
	asnPath := filepath.Join(data, "asn.csv")
	if err := os.WriteFile(asnPath, []byte("127.0.0.0/8,64500\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := peers.New(peers.DefaultPolicy(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index, record := range records {
		id, _ := record.PeerID()
		for range len(records) - index {
			if err := manager.Record(id, peers.EventValidMessage); err != nil {
				t.Fatal(err)
			}
		}
	}
	selected, results, err := selectAutomaticWorkPeers(
		ctx, data, networkID, client, round, manager, nil,
		workAutoPeerConfig{
			Count: 2, AttemptLimit: 4, ActivationHeight: 5, ASNMapPath: asnPath,
			ASNMaxAge: time.Hour, MaxPerASN: 4,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedID, _ := records[0].PeerID()
	unusedID, _ := records[3].PeerID()
	if len(results) != 3 || results[0].PeerID != unsupportedID || results[0].Err == nil || len(selected) != 2 {
		t.Fatalf("automatic results=%+v selected=%+v", results, selected)
	}
	for _, target := range selected {
		if target.id == unsupportedID || target.id == unusedID {
			t.Fatalf("selected incompatible or unnecessary peer %s", target.id)
		}
	}
	if snapshot, ok := manager.Get(unsupportedID); !ok || snapshot.DialFailures != 1 || snapshot.NextDial.IsZero() {
		t.Fatalf("unsupported peer did not enter backoff: %+v present=%t", snapshot, ok)
	}
}

func testAutomaticWorkHost(
	t testing.TB,
	ctx context.Context,
	label string,
	round *workround.Round,
) (ed25519.PrivateKey, *libp2ptransport.Host) {
	t.Helper()
	key := testAutomaticWorkKey(label)
	host, err := libp2ptransport.New(ctx, key, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	if round != nil {
		if err := host.SetWorkGraphHandler(func(handlerContext context.Context, _ types.Hash, stream libp2pnetwork.Stream) {
			_ = round.Serve(handlerContext, stream)
		}); err != nil {
			t.Fatal(err)
		}
	}
	return key, host
}

func testAutomaticWorkRecord(
	t testing.TB,
	key ed25519.PrivateKey,
	networkID uint32,
	now uint64,
	host *libp2ptransport.Host,
) discovery.Record {
	t.Helper()
	record, err := discovery.SignActivation(
		key, networkID, 1, now+600, 5,
		discovery.FeatureVersionedChainV1|discovery.FeatureWorkGraphV1|discovery.FeaturePeerExchangeV1,
		host.Addresses(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testAutomaticWorkKey(label string) ed25519.PrivateKey {
	seed := types.DomainHash("test/omd/work-auto/key", []byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func testAutomaticWorkRound(t testing.TB, networkID uint32, timestampDelta uint64) *workround.Round {
	t.Helper()
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	parameters := workblock.Parameters{
		NetworkID: networkID, BlockSubsidy: 10_220, RewardMaturity: 100, ActivationHeight: 1,
		DifficultyAnchorTimestamp: 1_699_999_940, DifficultyAnchorTarget: target,
		TargetSpacing: 60, ASERTHalfLife: 7_200, FeeDelay: 3,
	}
	position := workblock.Position{
		Height: 1, ParentID: types.DomainHash("test/omd/work-auto/parent"),
		ParentTimestamp: parameters.DifficultyAnchorTimestamp,
		MedianTimePast:  parameters.DifficultyAnchorTimestamp,
		Timestamp:       parameters.DifficultyAnchorTimestamp + parameters.TargetSpacing + timestampDelta,
		Target:          target,
	}
	payload, err := workblock.PreparePayload(state.Empty(), position, nil, nil, parameters)
	if err != nil {
		t.Fatal(err)
	}
	round, err := workround.New(payload, worksession.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return round
}
