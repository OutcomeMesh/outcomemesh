package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"

	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/discovery"
	"github.com/outcomemesh/outcomemesh/node/peers"
)

var ErrConfiguration = errors.New("invalid peer router configuration")

const discoveryAttemptLimit = discovery.MaxBookRecords

type Connector func(context.Context, discovery.Record) error

type Result struct {
	PeerID types.Hash
	Err    error
}

type Router struct {
	book    *discovery.Book
	manager *peers.Manager
	self    types.Hash
	now     func() uint64
	policy  Policy
}

type Policy struct {
	ASNResolver ASNResolver
	MaxPerASN   int
}

func DefaultPolicy() Policy {
	return Policy{MaxPerASN: 2}
}

func New(book *discovery.Book, manager *peers.Manager, self types.Hash, now func() uint64) (*Router, error) {
	return NewWithPolicy(book, manager, self, now, DefaultPolicy())
}

func NewWithPolicy(book *discovery.Book, manager *peers.Manager, self types.Hash, now func() uint64, policy Policy) (*Router, error) {
	if book == nil || manager == nil || self.IsZero() || now == nil || policy.MaxPerASN <= 0 || policy.MaxPerASN > discovery.MaxBookRecords {
		return nil, ErrConfiguration
	}
	return &Router{book: book, manager: manager, self: self, now: now, policy: policy}, nil
}

// RunOnce ranks live records by local score, reserves at most limit attempts,
// and always releases their dial state. Authentication and protocol handshake
// remain the connector's responsibility.
func (router *Router) RunOnce(ctx context.Context, limit int, connector Connector) []Result {
	if router == nil || ctx == nil || ctx.Err() != nil || limit <= 0 || connector == nil {
		return nil
	}
	records := router.book.List(router.now(), discovery.MaxBookRecords)
	type candidate struct {
		record         discovery.Record
		id             types.Hash
		score          int
		latencyMillis  uint64
		latencySamples uint64
		asns           []uint32
	}
	candidates := make([]candidate, 0, len(records))
	for _, record := range records {
		id, err := record.PeerID()
		if err != nil || id == router.self {
			continue
		}
		snapshot, _ := router.manager.Get(id)
		candidates = append(candidates, candidate{
			record: record, id: id, score: snapshot.Score, latencyMillis: snapshot.LatencyMillis,
			latencySamples: snapshot.LatencySamples, asns: recordASNs(record, router.policy.ASNResolver),
		})
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].score != candidates[right].score {
			return candidates[left].score > candidates[right].score
		}
		leftMeasured := candidates[left].latencySamples > 0
		rightMeasured := candidates[right].latencySamples > 0
		if leftMeasured != rightMeasured {
			return leftMeasured
		}
		if leftMeasured && candidates[left].latencyMillis != candidates[right].latencyMillis {
			return candidates[left].latencyMillis < candidates[right].latencyMillis
		}
		return types.CompareHash(candidates[left].id, candidates[right].id) < 0
	})
	results := make([]Result, 0, min(limit, len(candidates)))
	asnAttempts := make(map[uint32]int)
	for _, candidate := range candidates {
		if len(results) == limit || ctx.Err() != nil {
			break
		}
		allowed := true
		for _, asn := range candidate.asns {
			if asnAttempts[asn] >= router.policy.MaxPerASN {
				allowed = false
				break
			}
		}
		if !allowed {
			continue
		}
		if err := router.manager.BeginDial(candidate.id); err != nil {
			continue
		}
		for _, asn := range candidate.asns {
			asnAttempts[asn]++
		}
		err := connector(ctx, candidate.record)
		_ = router.manager.EndDial(candidate.id, err == nil)
		results = append(results, Result{PeerID: candidate.id, Err: err})
	}
	return results
}

func recordASNs(record discovery.Record, resolver ASNResolver) []uint32 {
	if resolver == nil {
		return nil
	}
	set := make(map[uint32]struct{})
	for _, address := range record.Addresses {
		ip, ok := recordAddressIP(address)
		if !ok {
			continue
		}
		if asn, found := resolver.Lookup(ip); found && asn != 0 {
			set[asn] = struct{}{}
		}
	}
	result := make([]uint32, 0, len(set))
	for asn := range set {
		result = append(result, asn)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func recordAddressIP(address string) (netip.Addr, bool) {
	if len(address) == 0 {
		return netip.Addr{}, false
	}
	if address[0] != '/' {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return netip.Addr{}, false
		}
		value, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, false
		}
		return value.Unmap(), true
	}
	parsed, err := multiaddr.NewMultiaddr(address)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, code := range []int{multiaddr.P_IP4, multiaddr.P_IP6} {
		value, err := parsed.ValueForProtocol(code)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Addr{}, false
		}
		return ip.Unmap(), true
	}
	return netip.Addr{}, false
}
