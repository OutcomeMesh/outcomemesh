package workgraphmodel

import (
	"errors"
	"testing"
)

func TestBandwidthFullMeshKeepsAllPriorSharesVisible(t *testing.T) {
	t.Parallel()

	config := bandwidthFullMesh(6, 500, 512, 183, 183*8, 183*16)
	result, err := RunBandwidth(config)
	if err != nil {
		t.Fatal(err)
	}
	if result.IncludedShares != result.PublishedShares || result.UnseenAtWinner != 0 ||
		result.KnownButUncommitted != 0 || result.QueueDropMessages != 0 ||
		result.MaxLinkQueuedBytes > config.ShareBytes*5 {
		t.Fatalf("provisioned full mesh lost work: %+v", result)
	}
	t.Logf("bandwidth_full_mesh shares=%d first_deliveries=%d duplicates=%d max_total_queue=%d",
		result.IncludedShares, result.DeliveredFirstCopies, result.DuplicateDeliveries,
		result.MaxTotalQueuedBytes)
}

func TestBandwidthBottleneckQuantifiesQueueLossAndRemoteBias(t *testing.T) {
	t.Parallel()

	config := bandwidthBidirectionalLine(8, 1_000, 512, 183, 32, 183*4)
	result, err := RunBandwidth(config)
	if err != nil {
		t.Fatal(err)
	}
	if result.QueueDropMessages == 0 || result.UnseenAtWinner == 0 ||
		result.IncludedShares >= result.PublishedShares || result.StaleQueuedBytes == 0 {
		t.Fatalf("bottleneck did not expose bounded-queue loss: %+v", result)
	}
	if result.MaxLinkQueuedBytes > 183*4 || result.MaxTotalQueuedBytes > uint64(len(config.Links))*183*4 {
		t.Fatalf("queue bound exceeded: %+v", result)
	}
	t.Logf("bandwidth_line published=%d included=%d unseen=%d drops=%d max_link_queue=%d stale_queue=%d stale_flight=%d",
		result.PublishedShares, result.IncludedShares, result.UnseenAtWinner,
		result.QueueDropMessages, result.MaxLinkQueuedBytes, result.StaleQueuedBytes,
		result.StaleInFlightBytes)
}

func TestBandwidthHeterogeneousLinksOutperformUniformBottleneck(t *testing.T) {
	t.Parallel()

	slow := bandwidthBidirectionalLine(8, 1_000, 512, 183, 32, 183*4)
	heterogeneous := slow
	heterogeneous.Links = append([]BandwidthLink(nil), slow.Links...)
	for index := range heterogeneous.Links {
		link := &heterogeneous.Links[index]
		if link.From >= 2 && link.From <= 5 && link.To >= 2 && link.To <= 5 {
			link.BytesPerEvent = 183
			link.QueueLimitBytes = 183 * 16
		}
	}
	slowResult, err := RunBandwidth(slow)
	if err != nil {
		t.Fatal(err)
	}
	heterogeneousResult, err := RunBandwidth(heterogeneous)
	if err != nil {
		t.Fatal(err)
	}
	if heterogeneousResult.IncludedShares <= slowResult.IncludedShares ||
		heterogeneousResult.UnseenAtWinner >= slowResult.UnseenAtWinner {
		t.Fatalf("faster core links did not improve propagation slow=%+v heterogeneous=%+v",
			slowResult, heterogeneousResult)
	}
	t.Logf("bandwidth_upgrade included=%d->%d drops=%d->%d",
		slowResult.IncludedShares, heterogeneousResult.IncludedShares,
		slowResult.QueueDropMessages, heterogeneousResult.QueueDropMessages)
}

func TestBandwidthRejectsUnboundedOrDisconnectedLinks(t *testing.T) {
	t.Parallel()

	_, err := RunBandwidth(BandwidthConfig{
		Rounds: 1, Seed: 1, ShareRatio: 2, ShareBytes: 183,
		Miners: []BandwidthMiner{{HashUnits: 1}, {HashUnits: 1}},
		Links:  []BandwidthLink{{From: 0, To: 1, LatencyEvents: 1, BytesPerEvent: 183, QueueLimitBytes: 183}},
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("disconnected link error = %v", err)
	}
}

func bandwidthFullMesh(
	count int,
	rounds int,
	ratio uint64,
	shareBytes uint64,
	bytesPerEvent uint64,
	queueBytes uint64,
) BandwidthConfig {
	config := BandwidthConfig{
		Rounds: rounds, Seed: 0x428a2f98d728ae22, ShareRatio: ratio, ShareBytes: shareBytes,
		Miners: make([]BandwidthMiner, count),
	}
	for source := range count {
		config.Miners[source].HashUnits = 1
		for destination := range count {
			if source == destination {
				continue
			}
			config.Links = append(config.Links, BandwidthLink{
				From: source, To: destination, LatencyEvents: 1,
				BytesPerEvent: bytesPerEvent, QueueLimitBytes: queueBytes,
			})
		}
	}
	return config
}

func bandwidthBidirectionalLine(
	count int,
	rounds int,
	ratio uint64,
	shareBytes uint64,
	bytesPerEvent uint64,
	queueBytes uint64,
) BandwidthConfig {
	config := BandwidthConfig{
		Rounds: rounds, Seed: 0x7137449123ef65cd, ShareRatio: ratio, ShareBytes: shareBytes,
		Miners: make([]BandwidthMiner, count),
	}
	for index := range count {
		config.Miners[index].HashUnits = 1
		if index+1 == count {
			continue
		}
		config.Links = append(config.Links,
			BandwidthLink{From: index, To: index + 1, LatencyEvents: 1, BytesPerEvent: bytesPerEvent, QueueLimitBytes: queueBytes},
			BandwidthLink{From: index + 1, To: index, LatencyEvents: 1, BytesPerEvent: bytesPerEvent, QueueLimitBytes: queueBytes},
		)
	}
	return config
}
