package libp2ptransport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	libcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	multiaddr "github.com/multiformats/go-multiaddr"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/discovery"
)

const (
	SessionProtocol        protocol.ID = "/outcomemesh/session/0"
	WorkGraphProtocol      protocol.ID = "/outcomemesh/workgraph/1"
	VersionedChainProtocol protocol.ID = "/outcomemesh/chain/1"
	ChainNotifyProtocol    protocol.ID = "/outcomemesh/chain-notify/1"
	TiePairProtocol        protocol.ID = "/outcomemesh/tie-pair/1"
	maxListenAddresses                 = 8
	maxAddressBytes                    = 256
	// MaxConnectionLimit and MaxStreamsPerPeerLimit are hard implementation
	// bounds. Callers may choose lower operational limits, but cannot silently
	// expand the resource-manager scopes past these values.
	MaxConnectionLimit                           = 1_024
	MaxStreamsPerPeerLimit                       = 32
	MaxWorkStreamsPerPeerLimit                   = 4
	MaxWorkStreamsPerMinuteLimit                 = 60
	MaxWorkStreamsGlobalPerMinuteLimit           = 4_096
	MaxVersionedChainStreamsLimit                = 64
	MaxVersionedChainStreamsPerPeerLimit         = 2
	MaxVersionedChainStreamsPerMinuteLimit       = 30
	MaxVersionedChainStreamsGlobalPerMinuteLimit = 1_024
	MaxTiePairStreamsLimit                       = 16
	MaxTiePairStreamsPerPeerLimit                = 1
	MaxTiePairStreamsPerMinuteLimit              = 4
	MaxTiePairStreamsGlobalPerMinuteLimit        = 128
	MaxFileDescriptorLimit                       = 4_096
)

var (
	ErrConfiguration  = errors.New("invalid libp2p transport configuration")
	ErrIdentity       = errors.New("invalid libp2p Ed25519 identity")
	ErrAddress        = errors.New("invalid libp2p QUIC address")
	ErrUnexpectedPeer = errors.New("unexpected OutcomeMesh peer identity")
)

type Handler func(context.Context, types.Hash, network.Stream)

type Config struct {
	Listen                                  []string
	MaxConnections                          int
	MaxStreamsPerPeer                       int
	MaxWorkStreamsPerPeer                   int
	MaxWorkStreamsPerMinute                 int
	MaxWorkStreamsGlobalPerMinute           int
	MaxVersionedChainStreams                int
	MaxVersionedChainStreamsPerPeer         int
	MaxVersionedChainStreamsPerMinute       int
	MaxVersionedChainStreamsGlobalPerMinute int
	MaxTiePairStreams                       int
	MaxTiePairStreamsPerPeer                int
	MaxTiePairStreamsPerMinute              int
	MaxTiePairStreamsGlobalPerMinute        int
	MemoryBytes                             int64
	MaxFileDescriptors                      int
	GracePeriod                             time.Duration
}

func DefaultConfig() Config {
	return Config{
		Listen:                                  []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		MaxConnections:                          64,
		MaxStreamsPerPeer:                       4,
		MaxWorkStreamsPerPeer:                   1,
		MaxWorkStreamsPerMinute:                 8,
		MaxWorkStreamsGlobalPerMinute:           512,
		MaxVersionedChainStreams:                4,
		MaxVersionedChainStreamsPerPeer:         1,
		MaxVersionedChainStreamsPerMinute:       4,
		MaxVersionedChainStreamsGlobalPerMinute: 128,
		MaxTiePairStreams:                       2,
		MaxTiePairStreamsPerPeer:                1,
		MaxTiePairStreamsPerMinute:              2,
		MaxTiePairStreamsGlobalPerMinute:        32,
		MemoryBytes:                             64 << 20,
		MaxFileDescriptors:                      128,
		GracePeriod:                             30 * time.Second,
	}
}

type Host struct {
	inner                                   host.Host
	id                                      types.Hash
	context                                 context.Context
	cancel                                  context.CancelFunc
	once                                    sync.Once
	workMu                                  sync.Mutex
	workWindowStart                         time.Time
	workGlobalCount                         int
	workPeerCounts                          map[types.Hash]int
	maxWorkStreamsPerMinute                 int
	maxGlobalWorkStreamsPerMinute           int
	versionedChainMu                        sync.Mutex
	versionedChainWindowStart               time.Time
	versionedChainGlobalCount               int
	versionedChainPeerCounts                map[types.Hash]int
	maxVersionedChainStreamsPerMinute       int
	maxGlobalVersionedChainStreamsPerMinute int
	tiePairMu                               sync.Mutex
	tiePairWindowStart                      time.Time
	tiePairGlobalCount                      int
	tiePairPeerCounts                       map[types.Hash]int
	maxTiePairStreamsPerMinute              int
	maxGlobalTiePairStreamsPerMinute        int
}

func New(ctx context.Context, privateKey ed25519.PrivateKey, config Config, handler Handler) (*Host, error) {
	if err := validateConfig(ctx, privateKey, config); err != nil {
		return nil, err
	}
	key, err := libcrypto.UnmarshalEd25519PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentity, err)
	}
	id, err := outcomeIDFromPublicKey(key.GetPublic())
	if err != nil {
		return nil, err
	}
	connectionManager, err := connmgr.NewConnManager(
		max(1, config.MaxConnections*3/4),
		config.MaxConnections,
		connmgr.WithGracePeriod(config.GracePeriod),
	)
	if err != nil {
		return nil, err
	}
	resourceManager, err := newResourceManager(config)
	if err != nil {
		return nil, err
	}
	hostContext, cancel := context.WithCancel(ctx)
	inner, err := libp2p.New(
		libp2p.Identity(key),
		libp2p.ListenAddrStrings(config.Listen...),
		libp2p.Transport(libp2pquic.NewTransport),
		// QUIC-v1 performs libp2p identity authentication inside TLS 1.3.
		// Noise is explicitly registered for protocol compatibility, although
		// it is not layered over QUIC by the libp2p transport model.
		libp2p.Security(noise.ID, noise.New),
		libp2p.ConnectionManager(connectionManager),
		libp2p.ResourceManager(resourceManager),
		libp2p.DisableRelay(),
	)
	if err != nil {
		cancel()
		_ = resourceManager.Close()
		return nil, err
	}
	result := &Host{
		inner: inner, id: id, context: hostContext, cancel: cancel,
		workPeerCounts:                          make(map[types.Hash]int),
		maxWorkStreamsPerMinute:                 config.MaxWorkStreamsPerMinute,
		maxGlobalWorkStreamsPerMinute:           config.MaxWorkStreamsGlobalPerMinute,
		versionedChainPeerCounts:                make(map[types.Hash]int),
		maxVersionedChainStreamsPerMinute:       config.MaxVersionedChainStreamsPerMinute,
		maxGlobalVersionedChainStreamsPerMinute: config.MaxVersionedChainStreamsGlobalPerMinute,
		tiePairPeerCounts:                       make(map[types.Hash]int),
		maxTiePairStreamsPerMinute:              config.MaxTiePairStreamsPerMinute,
		maxGlobalTiePairStreamsPerMinute:        config.MaxTiePairStreamsGlobalPerMinute,
	}
	result.setHandler(SessionProtocol, handler)
	return result, nil
}

// SetWorkGraphHandler explicitly enables the isolated version-1 WorkGraph
// stream. Hosts that never call it do not negotiate the prototype protocol.
func (value *Host) SetWorkGraphHandler(handler Handler) error {
	if value == nil || value.inner == nil || handler == nil {
		return ErrConfiguration
	}
	value.setHandler(WorkGraphProtocol, handler)
	return nil
}

// SetVersionedChainHandler explicitly enables the activation-aware chain
// session. Hosts that never call it do not negotiate the prototype protocol.
func (value *Host) SetVersionedChainHandler(handler Handler) error {
	if value == nil || value.inner == nil || handler == nil {
		return ErrConfiguration
	}
	value.setHandler(VersionedChainProtocol, handler)
	return nil
}

// SetChainNotifyHandler enables an inverted versioned-chain stream: the
// inbound side runs the existing synchronizer while the dialing winner serves
// its fully validated header/body history. It is only a prompt, never a trusted
// block push.
func (value *Host) SetChainNotifyHandler(handler Handler) error {
	if value == nil || value.inner == nil || handler == nil {
		return ErrConfiguration
	}
	value.setHandler(ChainNotifyProtocol, handler)
	return nil
}

// SetTiePairHandler explicitly enables bounded controlled-tie artifact
// delivery for one preconfigured coordinator transport identity. Unlisted
// authenticated peers are rejected before consuming the protocol rate budget.
func (value *Host) SetTiePairHandler(expectedRemote types.Hash, handler Handler) error {
	if value == nil || value.inner == nil || expectedRemote.IsZero() || handler == nil {
		return ErrConfiguration
	}
	value.inner.SetStreamHandler(TiePairProtocol, func(stream network.Stream) {
		remoteID, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || remoteID != expectedRemote || !value.allowTiePairStream(remoteID, time.Now()) {
			_ = stream.Reset()
			return
		}
		handler(value.context, remoteID, stream)
	})
	return nil
}

func (value *Host) setHandler(protocolID protocol.ID, handler Handler) {
	value.inner.SetStreamHandler(protocolID, func(stream network.Stream) {
		remoteID, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || handler == nil {
			_ = stream.Reset()
			return
		}
		if protocolID == WorkGraphProtocol && !value.allowWorkStream(remoteID, time.Now()) {
			_ = stream.Reset()
			return
		}
		if (protocolID == VersionedChainProtocol || protocolID == ChainNotifyProtocol) &&
			!value.allowVersionedChainStream(remoteID, time.Now()) {
			_ = stream.Reset()
			return
		}
		handler(value.context, remoteID, stream)
	})
}

func (value *Host) allowTiePairStream(remoteID types.Hash, now time.Time) bool {
	value.tiePairMu.Lock()
	defer value.tiePairMu.Unlock()
	if value.tiePairWindowStart.IsZero() ||
		now.Sub(value.tiePairWindowStart) >= time.Minute || now.Before(value.tiePairWindowStart) {
		value.tiePairWindowStart = now
		value.tiePairGlobalCount = 0
		clear(value.tiePairPeerCounts)
	}
	if value.tiePairGlobalCount >= value.maxGlobalTiePairStreamsPerMinute ||
		value.tiePairPeerCounts[remoteID] >= value.maxTiePairStreamsPerMinute {
		return false
	}
	value.tiePairGlobalCount++
	value.tiePairPeerCounts[remoteID]++
	return true
}

func (value *Host) allowVersionedChainStream(remoteID types.Hash, now time.Time) bool {
	value.versionedChainMu.Lock()
	defer value.versionedChainMu.Unlock()
	if value.versionedChainWindowStart.IsZero() ||
		now.Sub(value.versionedChainWindowStart) >= time.Minute || now.Before(value.versionedChainWindowStart) {
		value.versionedChainWindowStart = now
		value.versionedChainGlobalCount = 0
		clear(value.versionedChainPeerCounts)
	}
	if value.versionedChainGlobalCount >= value.maxGlobalVersionedChainStreamsPerMinute ||
		value.versionedChainPeerCounts[remoteID] >= value.maxVersionedChainStreamsPerMinute {
		return false
	}
	value.versionedChainGlobalCount++
	value.versionedChainPeerCounts[remoteID]++
	return true
}

func (value *Host) allowWorkStream(remoteID types.Hash, now time.Time) bool {
	value.workMu.Lock()
	defer value.workMu.Unlock()
	if value.workWindowStart.IsZero() || now.Sub(value.workWindowStart) >= time.Minute || now.Before(value.workWindowStart) {
		value.workWindowStart = now
		value.workGlobalCount = 0
		clear(value.workPeerCounts)
	}
	if value.workGlobalCount >= value.maxGlobalWorkStreamsPerMinute ||
		value.workPeerCounts[remoteID] >= value.maxWorkStreamsPerMinute {
		return false
	}
	value.workGlobalCount++
	value.workPeerCounts[remoteID]++
	return true
}

func (value *Host) ID() types.Hash { return value.id }

func (value *Host) Libp2pID() peer.ID {
	if value == nil || value.inner == nil {
		return ""
	}
	return value.inner.ID()
}

func (value *Host) Addresses() []string {
	if value == nil || value.inner == nil {
		return nil
	}
	peerComponent, err := multiaddr.NewMultiaddr("/p2p/" + value.inner.ID().String())
	if err != nil {
		return nil
	}
	addresses := make([]string, 0, len(value.inner.Addrs()))
	for _, address := range value.inner.Addrs() {
		if !isDirectQUIC(address) {
			continue
		}
		addresses = append(addresses, multiaddr.Join(address, peerComponent).String())
	}
	return addresses
}

// PeerIDFromAddress validates one direct QUIC-v1 peer multiaddress and derives
// the OutcomeMesh identity committed by its /p2p component. Callers can use it
// to reject duplicate or mismatched explicit peers before opening a stream.
func PeerIDFromAddress(address string) (types.Hash, error) {
	if len(address) == 0 || len(address) > maxAddressBytes {
		return types.Hash{}, ErrAddress
	}
	info, err := peer.AddrInfoFromString(address)
	if err != nil || len(info.Addrs) == 0 {
		return types.Hash{}, ErrAddress
	}
	for _, candidate := range info.Addrs {
		if !isDirectQUIC(candidate) {
			return types.Hash{}, ErrAddress
		}
	}
	result, err := outcomeIDFromPeerID(info.ID)
	if err != nil {
		return types.Hash{}, err
	}
	return result, nil
}

func (value *Host) OpenStream(ctx context.Context, address string, expected *types.Hash) (network.Stream, types.Hash, error) {
	return value.openStream(ctx, address, expected, SessionProtocol)
}

// OpenWorkGraphStream opens only the explicitly versioned WorkGraph protocol.
// Peer pinning and direct-QUIC checks are identical to the chain session.
func (value *Host) OpenWorkGraphStream(ctx context.Context, address string, expected *types.Hash) (network.Stream, types.Hash, error) {
	return value.openStream(ctx, address, expected, WorkGraphProtocol)
}

// OpenVersionedChainStream opens only the activation-aware chain protocol.
// It cannot fall back to the active version-0 session on negotiation failure.
func (value *Host) OpenVersionedChainStream(ctx context.Context, address string, expected *types.Hash) (network.Stream, types.Hash, error) {
	return value.openStream(ctx, address, expected, VersionedChainProtocol)
}

// OpenChainNotifyStream opens only the inverted chain-notification protocol.
func (value *Host) OpenChainNotifyStream(ctx context.Context, address string, expected *types.Hash) (network.Stream, types.Hash, error) {
	return value.openStream(ctx, address, expected, ChainNotifyProtocol)
}

// OpenTiePairStream opens only the authenticated controlled-tie artifact
// protocol. The expected observer transport identity should always be pinned.
func (value *Host) OpenTiePairStream(ctx context.Context, address string, expected *types.Hash) (network.Stream, types.Hash, error) {
	return value.openStream(ctx, address, expected, TiePairProtocol)
}

// DisconnectPeer closes the authenticated connection behind a pinned direct
// address. The next Open*Stream call must perform a fresh QUIC handshake. This
// is intentionally explicit: ordinary streams keep their connection reuse,
// while restart-aware protocols can discard a session proven stale by I/O.
func (value *Host) DisconnectPeer(address string, expected types.Hash) error {
	if value == nil || value.inner == nil || expected.IsZero() {
		return ErrAddress
	}
	advertisedID, err := PeerIDFromAddress(address)
	if err != nil {
		return err
	}
	info, err := peer.AddrInfoFromString(address)
	if err != nil {
		return ErrAddress
	}
	if advertisedID != expected {
		return ErrUnexpectedPeer
	}
	return value.inner.Network().ClosePeer(info.ID)
}

func (value *Host) openStream(
	ctx context.Context,
	address string,
	expected *types.Hash,
	protocolID protocol.ID,
) (network.Stream, types.Hash, error) {
	if value == nil || value.inner == nil {
		return nil, types.Hash{}, ErrAddress
	}
	advertisedID, err := PeerIDFromAddress(address)
	if err != nil {
		return nil, types.Hash{}, err
	}
	info, err := peer.AddrInfoFromString(address)
	if err != nil {
		return nil, types.Hash{}, ErrAddress
	}
	if expected != nil && advertisedID != *expected {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	if err := value.inner.Connect(ctx, *info); err != nil {
		return nil, types.Hash{}, err
	}
	stream, err := value.inner.NewStream(ctx, info.ID, protocolID)
	if err != nil {
		return nil, types.Hash{}, err
	}
	remoteID, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
	if err != nil || remoteID != advertisedID || (expected != nil && remoteID != *expected) {
		_ = stream.Reset()
		if err != nil {
			return nil, types.Hash{}, err
		}
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	if !isDirectQUIC(stream.Conn().RemoteMultiaddr()) {
		_ = stream.Reset()
		return nil, types.Hash{}, ErrAddress
	}
	return stream, remoteID, nil
}

// OpenRecord validates a signed discovery record, enforces its network and
// OutcomeMesh identity, and tries its canonical QUIC endpoints in order.
func (value *Host) OpenRecord(ctx context.Context, record discovery.Record, networkID uint32, now uint64) (network.Stream, types.Hash, error) {
	if record.NetworkID != networkID {
		return nil, types.Hash{}, discovery.ErrNetwork
	}
	if err := record.Validate(now); err != nil {
		return nil, types.Hash{}, err
	}
	expected, err := record.PeerID()
	if err != nil {
		return nil, types.Hash{}, err
	}
	var attempts []error
	for _, address := range record.Addresses {
		if len(address) == 0 || address[0] != '/' {
			continue
		}
		stream, remote, err := value.OpenStream(ctx, address, &expected)
		if err == nil {
			return stream, remote, nil
		}
		attempts = append(attempts, err)
	}
	if len(attempts) == 0 {
		return nil, types.Hash{}, ErrAddress
	}
	return nil, types.Hash{}, errors.Join(attempts...)
}

func (value *Host) Close() error {
	if value == nil {
		return nil
	}
	var result error
	value.once.Do(func() {
		value.cancel()
		result = value.inner.Close()
	})
	return result
}

func outcomeIDFromPeerID(id peer.ID) (types.Hash, error) {
	publicKey, err := id.ExtractPublicKey()
	if err != nil {
		return types.Hash{}, fmt.Errorf("%w: %v", ErrIdentity, err)
	}
	return outcomeIDFromPublicKey(publicKey)
}

func outcomeIDFromPublicKey(publicKey libcrypto.PubKey) (types.Hash, error) {
	if publicKey == nil {
		return types.Hash{}, ErrIdentity
	}
	raw, err := publicKey.Raw()
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return types.Hash{}, ErrIdentity
	}
	return types.DomainHash("OMESH/p2p/ed25519/v0", raw), nil
}

func isDirectQUIC(address multiaddr.Multiaddr) bool {
	if address == nil {
		return false
	}
	protocols := address.Protocols()
	return len(protocols) == 3 &&
		(protocols[0].Code == multiaddr.P_IP4 || protocols[0].Code == multiaddr.P_IP6) &&
		protocols[1].Code == multiaddr.P_UDP && protocols[2].Code == multiaddr.P_QUIC_V1
}

func validateConfig(ctx context.Context, privateKey ed25519.PrivateKey, config Config) error {
	if ctx == nil || ctx.Err() != nil || len(privateKey) != ed25519.PrivateKeySize ||
		len(config.Listen) == 0 || len(config.Listen) > maxListenAddresses ||
		config.MaxConnections <= 0 || config.MaxConnections > MaxConnectionLimit ||
		config.MaxStreamsPerPeer <= 0 || config.MaxStreamsPerPeer > MaxStreamsPerPeerLimit ||
		config.MaxWorkStreamsPerPeer <= 0 || config.MaxWorkStreamsPerPeer > MaxWorkStreamsPerPeerLimit ||
		config.MaxWorkStreamsPerMinute <= 0 || config.MaxWorkStreamsPerMinute > MaxWorkStreamsPerMinuteLimit ||
		config.MaxWorkStreamsGlobalPerMinute < config.MaxWorkStreamsPerMinute ||
		config.MaxWorkStreamsGlobalPerMinute > MaxWorkStreamsGlobalPerMinuteLimit ||
		config.MaxVersionedChainStreams <= 0 || config.MaxVersionedChainStreams > MaxVersionedChainStreamsLimit ||
		config.MaxVersionedChainStreamsPerPeer <= 0 ||
		config.MaxVersionedChainStreamsPerPeer > MaxVersionedChainStreamsPerPeerLimit ||
		config.MaxVersionedChainStreams < config.MaxVersionedChainStreamsPerPeer ||
		config.MaxVersionedChainStreamsPerMinute <= 0 ||
		config.MaxVersionedChainStreamsPerMinute > MaxVersionedChainStreamsPerMinuteLimit ||
		config.MaxVersionedChainStreamsGlobalPerMinute < config.MaxVersionedChainStreamsPerMinute ||
		config.MaxVersionedChainStreamsGlobalPerMinute > MaxVersionedChainStreamsGlobalPerMinuteLimit ||
		config.MaxTiePairStreams <= 0 || config.MaxTiePairStreams > MaxTiePairStreamsLimit ||
		config.MaxTiePairStreamsPerPeer <= 0 ||
		config.MaxTiePairStreamsPerPeer > MaxTiePairStreamsPerPeerLimit ||
		config.MaxTiePairStreams < config.MaxTiePairStreamsPerPeer ||
		config.MaxTiePairStreamsPerMinute <= 0 ||
		config.MaxTiePairStreamsPerMinute > MaxTiePairStreamsPerMinuteLimit ||
		config.MaxTiePairStreamsGlobalPerMinute < config.MaxTiePairStreamsPerMinute ||
		config.MaxTiePairStreamsGlobalPerMinute > MaxTiePairStreamsGlobalPerMinuteLimit ||
		config.MemoryBytes < 16<<20 || config.MemoryBytes > 2<<30 ||
		config.MaxFileDescriptors < config.MaxConnections || config.MaxFileDescriptors > MaxFileDescriptorLimit ||
		config.GracePeriod < 0 {
		return ErrConfiguration
	}
	for _, address := range config.Listen {
		if len(address) == 0 || len(address) > maxAddressBytes {
			return ErrAddress
		}
		parsed, err := multiaddr.NewMultiaddr(address)
		if err != nil || !isDirectQUIC(parsed) {
			return ErrAddress
		}
	}
	return nil
}

func newResourceManager(config Config) (network.ResourceManager, error) {
	// libp2p uses a small number of internal identify/management streams. The
	// peer scope reserves room for those, while the OutcomeMesh protocol scope
	// below enforces the exact application-stream limit.
	const internalStreamsPerPeer = 8
	peerStreams := config.MaxStreamsPerPeer + config.MaxWorkStreamsPerPeer +
		2*config.MaxVersionedChainStreamsPerPeer + config.MaxTiePairStreamsPerPeer + internalStreamsPerPeer
	totalStreams := config.MaxConnections*(config.MaxStreamsPerPeer+config.MaxWorkStreamsPerPeer+internalStreamsPerPeer) +
		2*config.MaxVersionedChainStreams + config.MaxTiePairStreams
	system := rcmgr.ResourceLimits{
		Streams:         rcmgr.LimitVal(totalStreams),
		StreamsInbound:  rcmgr.LimitVal(totalStreams),
		StreamsOutbound: rcmgr.LimitVal(totalStreams),
		Conns:           rcmgr.LimitVal(config.MaxConnections),
		ConnsInbound:    rcmgr.LimitVal(config.MaxConnections),
		ConnsOutbound:   rcmgr.LimitVal(config.MaxConnections),
		FD:              rcmgr.LimitVal(config.MaxFileDescriptors),
		Memory:          rcmgr.LimitVal64(config.MemoryBytes),
	}
	perPeer := rcmgr.ResourceLimits{
		Streams:         rcmgr.LimitVal(peerStreams),
		StreamsInbound:  rcmgr.LimitVal(peerStreams),
		StreamsOutbound: rcmgr.LimitVal(peerStreams),
		Conns:           2,
		ConnsInbound:    2,
		ConnsOutbound:   2,
		FD:              2,
		Memory:          8 << 20,
	}
	applicationPerPeer := rcmgr.ResourceLimits{
		Streams:         rcmgr.LimitVal(config.MaxStreamsPerPeer),
		StreamsInbound:  rcmgr.LimitVal(config.MaxStreamsPerPeer),
		StreamsOutbound: rcmgr.LimitVal(config.MaxStreamsPerPeer),
		Memory:          4 << 20,
	}
	workGraphPerPeer := rcmgr.ResourceLimits{
		Streams:         rcmgr.LimitVal(config.MaxWorkStreamsPerPeer),
		StreamsInbound:  rcmgr.LimitVal(config.MaxWorkStreamsPerPeer),
		StreamsOutbound: rcmgr.LimitVal(config.MaxWorkStreamsPerPeer),
		Memory:          512 << 10,
	}
	versionedChainPerPeer := rcmgr.ResourceLimits{
		Streams:         rcmgr.LimitVal(config.MaxVersionedChainStreamsPerPeer),
		StreamsInbound:  rcmgr.LimitVal(config.MaxVersionedChainStreamsPerPeer),
		StreamsOutbound: rcmgr.LimitVal(config.MaxVersionedChainStreamsPerPeer),
		Memory:          4 << 20,
	}
	tiePairPerPeer := rcmgr.ResourceLimits{
		Streams:         rcmgr.LimitVal(config.MaxTiePairStreamsPerPeer),
		StreamsInbound:  rcmgr.LimitVal(config.MaxTiePairStreamsPerPeer),
		StreamsOutbound: rcmgr.LimitVal(config.MaxTiePairStreamsPerPeer),
		Memory:          32 << 20,
	}
	partial := rcmgr.PartialLimitConfig{
		System:      system,
		Transient:   system,
		PeerDefault: perPeer,
		Protocol: map[protocol.ID]rcmgr.ResourceLimits{
			SessionProtocol: {
				Streams:         rcmgr.LimitVal(config.MaxConnections * config.MaxStreamsPerPeer),
				StreamsInbound:  rcmgr.LimitVal(config.MaxConnections * config.MaxStreamsPerPeer),
				StreamsOutbound: rcmgr.LimitVal(config.MaxConnections * config.MaxStreamsPerPeer),
				Memory:          rcmgr.LimitVal64(config.MemoryBytes / 2),
			},
			WorkGraphProtocol: {
				Streams:         rcmgr.LimitVal(config.MaxConnections * config.MaxWorkStreamsPerPeer),
				StreamsInbound:  rcmgr.LimitVal(config.MaxConnections * config.MaxWorkStreamsPerPeer),
				StreamsOutbound: rcmgr.LimitVal(config.MaxConnections * config.MaxWorkStreamsPerPeer),
				Memory:          rcmgr.LimitVal64(config.MemoryBytes / 8),
			},
			VersionedChainProtocol: {
				Streams:         rcmgr.LimitVal(config.MaxVersionedChainStreams),
				StreamsInbound:  rcmgr.LimitVal(config.MaxVersionedChainStreams),
				StreamsOutbound: rcmgr.LimitVal(config.MaxVersionedChainStreams),
				Memory:          rcmgr.LimitVal64(config.MemoryBytes / 2),
			},
			ChainNotifyProtocol: {
				Streams:         rcmgr.LimitVal(config.MaxVersionedChainStreams),
				StreamsInbound:  rcmgr.LimitVal(config.MaxVersionedChainStreams),
				StreamsOutbound: rcmgr.LimitVal(config.MaxVersionedChainStreams),
				Memory:          rcmgr.LimitVal64(config.MemoryBytes / 2),
			},
			TiePairProtocol: {
				Streams:         rcmgr.LimitVal(config.MaxTiePairStreams),
				StreamsInbound:  rcmgr.LimitVal(config.MaxTiePairStreams),
				StreamsOutbound: rcmgr.LimitVal(config.MaxTiePairStreams),
				Memory:          rcmgr.LimitVal64(config.MemoryBytes / 2),
			},
		},
		ProtocolPeer: map[protocol.ID]rcmgr.ResourceLimits{
			SessionProtocol:        applicationPerPeer,
			WorkGraphProtocol:      workGraphPerPeer,
			VersionedChainProtocol: versionedChainPerPeer,
			ChainNotifyProtocol:    versionedChainPerPeer,
			TiePairProtocol:        tiePairPerPeer,
		},
		Conn: rcmgr.ResourceLimits{
			Conns: 1, ConnsInbound: 1, ConnsOutbound: 1, FD: 1, Memory: 4 << 20,
		},
		Stream: rcmgr.ResourceLimits{
			Streams: 1, StreamsInbound: 1, StreamsOutbound: 1, Memory: 2 << 20,
		},
	}
	defaults := rcmgr.DefaultLimits.Scale(config.MemoryBytes, config.MaxFileDescriptors)
	limits := partial.Build(defaults)
	return rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits), rcmgr.WithMetricsDisabled())
}
