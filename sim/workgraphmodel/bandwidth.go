package workgraphmodel

import (
	"math"

	"github.com/outcomemesh/outcomemesh/core/workgraph"
)

const MaxBandwidthLinks = MaxTopologyMiners * (MaxTopologyMiners - 1)

type BandwidthMiner struct {
	HashUnits uint64
}

// BandwidthLink is a directed store-and-forward gossip link. BytesPerEvent is
// serialization capacity; LatencyEvents starts after a complete share leaves
// the queue. QueueLimitBytes bounds unsent bytes on this link.
type BandwidthLink struct {
	From            int
	To              int
	LatencyEvents   uint64
	BytesPerEvent   uint64
	QueueLimitBytes uint64
}

type BandwidthConfig struct {
	Rounds     int
	Seed       uint64
	ShareRatio uint64
	ShareBytes uint64
	Miners     []BandwidthMiner
	Links      []BandwidthLink
}

type BandwidthMinerResult struct {
	DiscoveredShares uint64
	IncludedShares   uint64
	AnchorWins       uint64
}

type BandwidthResult struct {
	Rounds               uint64
	PublishedShares      uint64
	IncludedShares       uint64
	DeliveredFirstCopies uint64
	DuplicateDeliveries  uint64
	QueueDropMessages    uint64
	QueueDropBytes       uint64
	UnseenAtWinner       uint64
	KnownButUncommitted  uint64
	RoundsOverFourTips   uint64
	MaxWinnerTips        uint64
	MaxLinkQueuedBytes   uint64
	MaxTotalQueuedBytes  uint64
	StaleQueuedBytes     uint64
	StaleInFlightBytes   uint64
	Miners               []BandwidthMinerResult
}

type bandwidthPacket struct {
	share     int
	remaining uint64
}

type bandwidthLinkState struct {
	config      BandwidthLink
	queue       []bandwidthPacket
	head        int
	queuedBytes uint64
}

type bandwidthDelivery struct {
	source      int
	destination int
	share       int
}

// RunBandwidth models bounded FIFO serialization and store-and-forward gossip
// between local WorkGraph views. A node forwards only the first copy it sees;
// already queued duplicates may still consume capacity. Queues are discarded
// at the anchor boundary because shares are candidate-specific.
func RunBandwidth(config BandwidthConfig) (BandwidthResult, error) {
	totalHash, outgoing, linkTemplates, err := validateBandwidthConfig(config)
	if err != nil {
		return BandwidthResult{}, err
	}
	random := prng{state: config.Seed}
	if random.state == 0 {
		random.state = 0x13198a2e03707344
	}
	result := BandwidthResult{
		Rounds: uint64(config.Rounds), Miners: make([]BandwidthMinerResult, len(config.Miners)),
	}
	maxEvents := config.ShareRatio * 128
	for range config.Rounds {
		shares := make([]topologyShare, 0, config.ShareRatio)
		views := make([]topologyView, len(config.Miners))
		received := make([][]bool, len(config.Miners))
		for index := range views {
			views[index] = topologyView{tips: make(map[int]struct{}), pending: make(map[int]struct{})}
		}
		links := make([]bandwidthLinkState, len(linkTemplates))
		for index := range links {
			links[index].config = linkTemplates[index]
		}
		deliveries := make(map[uint64][]bandwidthDelivery)
		var totalQueued uint64
		var inFlightBytes uint64
		anchorMiner := -1

		for event := uint64(0); event < maxEvents; event++ {
			serviceBandwidthLinks(event, config.ShareBytes, links, deliveries, &totalQueued, &inFlightBytes)
			if err := deliverBandwidthAt(
				views, received, shares, deliveries[event], outgoing, links, config.ShareBytes,
				&totalQueued, &inFlightBytes, &result,
			); err != nil {
				return BandwidthResult{}, err
			}
			delete(deliveries, event)

			miner := chooseBandwidthMiner(random.next(), totalHash, config.Miners)
			if random.next()%config.ShareRatio == 0 {
				anchorMiner = miner
				result.Miners[miner].AnchorWins++
				winnerTips := len(views[miner].tips)
				if uint64(winnerTips) > result.MaxWinnerTips {
					result.MaxWinnerTips = uint64(winnerTips)
				}
				if winnerTips > workgraph.MaxParents {
					result.RoundsOverFourTips++
				}
				selected := selectTopologyTips(views[miner], shares, workgraph.MaxParents)
				included := topologyClosure(selected, shares)
				known := countKnown(views[miner].known)
				if known < len(included) {
					return BandwidthResult{}, ErrConfiguration
				}
				result.IncludedShares += uint64(len(included))
				result.UnseenAtWinner += uint64(len(shares) - known)
				result.KnownButUncommitted += uint64(known - len(included))
				for share := range included {
					result.Miners[shares[share].miner].IncludedShares++
				}
				result.StaleQueuedBytes += totalQueued
				result.StaleInFlightBytes += inFlightBytes
				break
			}

			parents := selectTopologyTips(views[miner], shares, workgraph.MaxParents)
			shareID := len(shares)
			shares = append(shares, topologyShare{
				miner: miner, parents: append([]int(nil), parents...), order: random.next(),
			})
			for index := range views {
				views[index].known = append(views[index].known, false)
				received[index] = append(received[index], false)
			}
			received[miner][shareID] = true
			acceptTopologyShare(&views[miner], shares, shareID)
			result.PublishedShares++
			result.Miners[miner].DiscoveredShares++
			for _, link := range outgoing[miner] {
				enqueueBandwidth(link, shareID, config.ShareBytes, links, &totalQueued, &result)
			}
			measureBandwidthQueues(links, totalQueued, &result)
		}
		if anchorMiner < 0 {
			return BandwidthResult{}, ErrConfiguration
		}
	}
	return result, nil
}

func validateBandwidthConfig(
	config BandwidthConfig,
) (uint64, [][]int, []BandwidthLink, error) {
	if config.Rounds <= 0 || config.Rounds > 100_000 || config.ShareRatio == 0 ||
		config.ShareRatio > 1_000_000 || config.ShareBytes == 0 ||
		config.ShareBytes > workgraph.MaxShareCanonicalBytes || len(config.Miners) == 0 ||
		len(config.Miners) > MaxTopologyMiners || len(config.Links) == 0 ||
		len(config.Links) > MaxBandwidthLinks {
		return 0, nil, nil, ErrConfiguration
	}
	var totalHash uint64
	for _, miner := range config.Miners {
		if miner.HashUnits == 0 || totalHash > math.MaxUint64-miner.HashUnits {
			return 0, nil, nil, ErrConfiguration
		}
		totalHash += miner.HashUnits
	}
	outgoing := make([][]int, len(config.Miners))
	reachable := make([][]bool, len(config.Miners))
	for index := range reachable {
		reachable[index] = make([]bool, len(config.Miners))
		reachable[index][index] = true
	}
	seen := make(map[[2]int]struct{}, len(config.Links))
	links := append([]BandwidthLink(nil), config.Links...)
	for index, link := range links {
		key := [2]int{link.From, link.To}
		if link.From < 0 || link.From >= len(config.Miners) || link.To < 0 ||
			link.To >= len(config.Miners) || link.From == link.To || link.LatencyEvents == 0 ||
			link.LatencyEvents > 1_000_000 || link.BytesPerEvent == 0 ||
			link.BytesPerEvent > workgraph.MaxBatchCanonicalBytes ||
			link.QueueLimitBytes < config.ShareBytes ||
			link.QueueLimitBytes > workgraph.MaxBatchCanonicalBytes {
			return 0, nil, nil, ErrConfiguration
		}
		if _, exists := seen[key]; exists {
			return 0, nil, nil, ErrConfiguration
		}
		seen[key] = struct{}{}
		outgoing[link.From] = append(outgoing[link.From], index)
		reachable[link.From][link.To] = true
	}
	for middle := range config.Miners {
		for source := range config.Miners {
			for destination := range config.Miners {
				reachable[source][destination] = reachable[source][destination] ||
					(reachable[source][middle] && reachable[middle][destination])
			}
		}
	}
	for source := range config.Miners {
		for destination := range config.Miners {
			if !reachable[source][destination] {
				return 0, nil, nil, ErrConfiguration
			}
		}
	}
	return totalHash, outgoing, links, nil
}

func chooseBandwidthMiner(value, total uint64, miners []BandwidthMiner) int {
	selected := value % total
	var cumulative uint64
	for index, miner := range miners {
		cumulative += miner.HashUnits
		if selected < cumulative {
			return index
		}
	}
	return len(miners) - 1
}

func serviceBandwidthLinks(
	event uint64,
	shareBytes uint64,
	links []bandwidthLinkState,
	deliveries map[uint64][]bandwidthDelivery,
	totalQueued *uint64,
	inFlightBytes *uint64,
) {
	for index := range links {
		link := &links[index]
		budget := link.config.BytesPerEvent
		for budget > 0 && link.head < len(link.queue) {
			packet := &link.queue[link.head]
			sent := min(budget, packet.remaining)
			packet.remaining -= sent
			budget -= sent
			link.queuedBytes -= sent
			*totalQueued -= sent
			if packet.remaining != 0 {
				continue
			}
			at := event + link.config.LatencyEvents - 1
			deliveries[at] = append(deliveries[at], bandwidthDelivery{
				source: link.config.From, destination: link.config.To, share: packet.share,
			})
			*inFlightBytes += shareBytes
			link.head++
		}
		if link.head == len(link.queue) {
			link.queue = link.queue[:0]
			link.head = 0
		} else if link.head > 256 && link.head*2 > len(link.queue) {
			link.queue = append([]bandwidthPacket(nil), link.queue[link.head:]...)
			link.head = 0
		}
	}
}

func deliverBandwidthAt(
	views []topologyView,
	received [][]bool,
	shares []topologyShare,
	deliveries []bandwidthDelivery,
	outgoing [][]int,
	links []bandwidthLinkState,
	shareBytes uint64,
	totalQueued *uint64,
	inFlightBytes *uint64,
	result *BandwidthResult,
) error {
	touched := make(map[int]struct{}, len(deliveries))
	for _, item := range deliveries {
		if *inFlightBytes < shareBytes || item.share < 0 || item.share >= len(shares) {
			return ErrConfiguration
		}
		*inFlightBytes -= shareBytes
		if received[item.destination][item.share] {
			result.DuplicateDeliveries++
			continue
		}
		received[item.destination][item.share] = true
		views[item.destination].pending[item.share] = struct{}{}
		touched[item.destination] = struct{}{}
		result.DeliveredFirstCopies++
		for _, link := range outgoing[item.destination] {
			if links[link].config.To == item.source {
				continue
			}
			enqueueBandwidth(link, item.share, shareBytes, links, totalQueued, result)
		}
	}
	for destination := range touched {
		resolveTopologyPending(&views[destination], shares)
	}
	measureBandwidthQueues(links, *totalQueued, result)
	return nil
}

func enqueueBandwidth(
	linkIndex int,
	share int,
	shareBytes uint64,
	links []bandwidthLinkState,
	totalQueued *uint64,
	result *BandwidthResult,
) {
	link := &links[linkIndex]
	if link.queuedBytes > link.config.QueueLimitBytes-shareBytes {
		result.QueueDropMessages++
		result.QueueDropBytes += shareBytes
		return
	}
	link.queue = append(link.queue, bandwidthPacket{share: share, remaining: shareBytes})
	link.queuedBytes += shareBytes
	*totalQueued += shareBytes
}

func measureBandwidthQueues(links []bandwidthLinkState, totalQueued uint64, result *BandwidthResult) {
	if totalQueued > result.MaxTotalQueuedBytes {
		result.MaxTotalQueuedBytes = totalQueued
	}
	for index := range links {
		if links[index].queuedBytes > result.MaxLinkQueuedBytes {
			result.MaxLinkQueuedBytes = links[index].queuedBytes
		}
	}
}
