package workgraphmodel

import (
	"math"
	"sort"
)

const MaxTopologyMiners = 64

type TopologyMiner struct {
	HashUnits          uint64
	WithholdPPM        uint32
	OmitForeignTipsPPM uint32
	Links              []int
}

type TopologyConfig struct {
	Rounds          int
	Seed            uint64
	ShareRatio      uint64
	LinkDelayEvents uint64
	Miners          []TopologyMiner
}

type TopologyMinerResult struct {
	DiscoveredShares uint64
	PublishedShares  uint64
	IncludedShares   uint64
	AnchorWins       uint64
}

type TopologyResult struct {
	Rounds                   uint64
	DiscoveredShares         uint64
	PublishedShares          uint64
	IncludedShares           uint64
	UnseenAtWinner           uint64
	KnownButUncommitted      uint64
	StrategicTipOmissions    uint64
	RoundsOverFourWinnerTips uint64
	MaxWinnerTips            uint64
	Miners                   []TopologyMinerResult
}

type topologyShare struct {
	miner   int
	parents []int
	order   uint64
}

type topologyView struct {
	known   []bool
	tips    map[int]struct{}
	pending map[int]struct{}
}

type delivery struct {
	destination int
	share       int
}

// RunTopology is a discrete-event model of share-DAG propagation. A miner
// builds each share on at most four tips in its local view. Published bodies
// arrive after shortest-path link delay; children whose parents are missing
// remain pending. The hard-anchor winner can only commit tips it actually
// knows, so the result exposes both propagation loss and four-tip truncation.
func RunTopology(config TopologyConfig) (TopologyResult, error) {
	distances, totalHash, err := topologyDistances(config)
	if err != nil {
		return TopologyResult{}, err
	}
	random := prng{state: config.Seed}
	if random.state == 0 {
		random.state = 0x243f6a8885a308d3
	}
	result := TopologyResult{
		Rounds: uint64(config.Rounds), Miners: make([]TopologyMinerResult, len(config.Miners)),
	}
	maxEvents := config.ShareRatio * 128
	for range config.Rounds {
		shares := make([]topologyShare, 0, config.ShareRatio)
		views := make([]topologyView, len(config.Miners))
		for index := range views {
			views[index] = topologyView{tips: make(map[int]struct{}), pending: make(map[int]struct{})}
		}
		deliveries := make(map[uint64][]delivery)
		anchorMiner := -1
		for event := uint64(0); event < maxEvents; event++ {
			deliverAt(views, shares, deliveries[event])
			delete(deliveries, event)
			miner := chooseTopologyMiner(random.next(), totalHash, config.Miners)
			if random.next()%config.ShareRatio == 0 {
				anchorMiner = miner
				result.Miners[miner].AnchorWins++
				winnerTips := len(views[miner].tips)
				if uint64(winnerTips) > result.MaxWinnerTips {
					result.MaxWinnerTips = uint64(winnerTips)
				}
				if winnerTips > 4 {
					result.RoundsOverFourWinnerTips++
				}
				selected := selectTopologyTips(views[miner], shares, 4)
				selected = applyStrategicOmission(
					selected, shares, miner, config.Miners[miner].OmitForeignTipsPPM, &random, &result,
				)
				included := topologyClosure(selected, shares)
				known := countKnown(views[miner].known)
				if known < len(included) {
					return TopologyResult{}, ErrConfiguration
				}
				result.UnseenAtWinner += uint64(len(shares) - known)
				result.KnownButUncommitted += uint64(known - len(included))
				result.IncludedShares += uint64(len(included))
				for share := range included {
					result.Miners[shares[share].miner].IncludedShares++
				}
				break
			}

			parents := selectTopologyTips(views[miner], shares, 4)
			shareID := len(shares)
			shares = append(shares, topologyShare{
				miner: miner, parents: append([]int(nil), parents...), order: random.next(),
			})
			for index := range views {
				views[index].known = append(views[index].known, false)
			}
			acceptTopologyShare(&views[miner], shares, shareID)
			result.DiscoveredShares++
			result.Miners[miner].DiscoveredShares++
			if uint32(random.next()%uint64(PartsPerMillion)) < config.Miners[miner].WithholdPPM {
				continue
			}
			result.PublishedShares++
			result.Miners[miner].PublishedShares++
			for destination := range config.Miners {
				if destination == miner {
					continue
				}
				delay := uint64(distances[miner][destination]) * config.LinkDelayEvents
				if event > math.MaxUint64-delay {
					return TopologyResult{}, ErrConfiguration
				}
				at := event + delay
				deliveries[at] = append(deliveries[at], delivery{destination: destination, share: shareID})
			}
		}
		if anchorMiner < 0 {
			return TopologyResult{}, ErrConfiguration
		}
	}
	return result, nil
}

func topologyDistances(config TopologyConfig) ([][]int, uint64, error) {
	if config.Rounds <= 0 || config.Rounds > 100_000 || config.ShareRatio == 0 ||
		config.ShareRatio > 1_000_000 || config.LinkDelayEvents == 0 ||
		len(config.Miners) == 0 || len(config.Miners) > MaxTopologyMiners {
		return nil, 0, ErrConfiguration
	}
	const unreachable = int(^uint(0) >> 2)
	distances := make([][]int, len(config.Miners))
	var totalHash uint64
	for index, miner := range config.Miners {
		if miner.HashUnits == 0 || miner.WithholdPPM > PartsPerMillion ||
			miner.OmitForeignTipsPPM > PartsPerMillion || totalHash > math.MaxUint64-miner.HashUnits {
			return nil, 0, ErrConfiguration
		}
		totalHash += miner.HashUnits
		distances[index] = make([]int, len(config.Miners))
		for destination := range distances[index] {
			distances[index][destination] = unreachable
		}
		distances[index][index] = 0
		seen := make(map[int]struct{}, len(miner.Links))
		for _, destination := range miner.Links {
			if destination < 0 || destination >= len(config.Miners) || destination == index {
				return nil, 0, ErrConfiguration
			}
			if _, exists := seen[destination]; exists {
				return nil, 0, ErrConfiguration
			}
			seen[destination] = struct{}{}
			distances[index][destination] = 1
		}
	}
	for middle := range config.Miners {
		for source := range config.Miners {
			for destination := range config.Miners {
				if distances[source][middle] == unreachable || distances[middle][destination] == unreachable {
					continue
				}
				candidate := distances[source][middle] + distances[middle][destination]
				if candidate < distances[source][destination] {
					distances[source][destination] = candidate
				}
			}
		}
	}
	for source := range config.Miners {
		for destination := range config.Miners {
			if distances[source][destination] == unreachable {
				return nil, 0, ErrConfiguration
			}
		}
	}
	return distances, totalHash, nil
}

func chooseTopologyMiner(value, total uint64, miners []TopologyMiner) int {
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

func deliverAt(views []topologyView, shares []topologyShare, deliveries []delivery) {
	touched := make(map[int]struct{}, len(deliveries))
	for _, item := range deliveries {
		if item.share >= 0 && item.share < len(shares) && !views[item.destination].known[item.share] {
			views[item.destination].pending[item.share] = struct{}{}
			touched[item.destination] = struct{}{}
		}
	}
	for destination := range touched {
		resolveTopologyPending(&views[destination], shares)
	}
}

func resolveTopologyPending(view *topologyView, shares []topologyShare) {
	for {
		progress := false
		for share := range view.pending {
			ready := true
			for _, parent := range shares[share].parents {
				if parent >= len(view.known) || !view.known[parent] {
					ready = false
					break
				}
			}
			if ready {
				delete(view.pending, share)
				acceptTopologyShare(view, shares, share)
				progress = true
			}
		}
		if !progress {
			return
		}
	}
}

func acceptTopologyShare(view *topologyView, shares []topologyShare, share int) {
	if view.known[share] {
		return
	}
	view.known[share] = true
	for _, parent := range shares[share].parents {
		delete(view.tips, parent)
	}
	view.tips[share] = struct{}{}
}

func selectTopologyTips(view topologyView, shares []topologyShare, limit int) []int {
	tips := make([]int, 0, len(view.tips))
	for tip := range view.tips {
		tips = append(tips, tip)
	}
	sort.Slice(tips, func(left, right int) bool {
		leftCoverage := len(topologyClosure([]int{tips[left]}, shares))
		rightCoverage := len(topologyClosure([]int{tips[right]}, shares))
		if leftCoverage != rightCoverage {
			return leftCoverage > rightCoverage
		}
		if shares[tips[left]].order != shares[tips[right]].order {
			return shares[tips[left]].order < shares[tips[right]].order
		}
		return tips[left] < tips[right]
	})
	if len(tips) > limit {
		tips = tips[:limit]
	}
	return tips
}

func applyStrategicOmission(
	tips []int,
	shares []topologyShare,
	winner int,
	probability uint32,
	random *prng,
	result *TopologyResult,
) []int {
	if probability == 0 {
		return tips
	}
	selected := tips[:0]
	for _, tip := range tips {
		if shares[tip].miner != winner && uint32(random.next()%uint64(PartsPerMillion)) < probability {
			result.StrategicTipOmissions++
			continue
		}
		selected = append(selected, tip)
	}
	return selected
}

func topologyClosure(tips []int, shares []topologyShare) map[int]struct{} {
	visited := make(map[int]struct{}, len(tips))
	stack := append([]int(nil), tips...)
	for len(stack) > 0 {
		last := len(stack) - 1
		share := stack[last]
		stack = stack[:last]
		if _, exists := visited[share]; exists {
			continue
		}
		visited[share] = struct{}{}
		stack = append(stack, shares[share].parents...)
	}
	return visited
}

func countKnown(known []bool) int {
	var result int
	for _, value := range known {
		if value {
			result++
		}
	}
	return result
}
