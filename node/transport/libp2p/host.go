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
	SessionProtocol    protocol.ID = "/outcomemesh/session/0"
	maxListenAddresses             = 8
	maxAddressBytes                = 256
	// MaxConnectionLimit and MaxStreamsPerPeerLimit are hard implementation
	// bounds. Callers may choose lower operational limits, but cannot silently
	// expand the resource-manager scopes past these values.
	MaxConnectionLimit     = 1_024
	MaxStreamsPerPeerLimit = 32
	MaxFileDescriptorLimit = 4_096
)

var (
	ErrConfiguration  = errors.New("invalid libp2p transport configuration")
	ErrIdentity       = errors.New("invalid libp2p Ed25519 identity")
	ErrAddress        = errors.New("invalid libp2p QUIC address")
	ErrUnexpectedPeer = errors.New("unexpected OutcomeMesh peer identity")
)

type Handler func(context.Context, types.Hash, network.Stream)

type Config struct {
	Listen             []string
	MaxConnections     int
	MaxStreamsPerPeer  int
	MemoryBytes        int64
	MaxFileDescriptors int
	GracePeriod        time.Duration
}

func DefaultConfig() Config {
	return Config{
		Listen:             []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		MaxConnections:     64,
		MaxStreamsPerPeer:  4,
		MemoryBytes:        64 << 20,
		MaxFileDescriptors: 128,
		GracePeriod:        30 * time.Second,
	}
}

type Host struct {
	inner  host.Host
	id     types.Hash
	cancel context.CancelFunc
	once   sync.Once
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
	result := &Host{inner: inner, id: id, cancel: cancel}
	inner.SetStreamHandler(SessionProtocol, func(stream network.Stream) {
		remoteID, err := outcomeIDFromPublicKey(stream.Conn().RemotePublicKey())
		if err != nil || handler == nil {
			_ = stream.Reset()
			return
		}
		handler(hostContext, remoteID, stream)
	})
	return result, nil
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

func (value *Host) OpenStream(ctx context.Context, address string, expected *types.Hash) (network.Stream, types.Hash, error) {
	if value == nil || value.inner == nil || len(address) == 0 || len(address) > maxAddressBytes {
		return nil, types.Hash{}, ErrAddress
	}
	info, err := peer.AddrInfoFromString(address)
	if err != nil || len(info.Addrs) == 0 {
		return nil, types.Hash{}, ErrAddress
	}
	for _, candidate := range info.Addrs {
		if !isDirectQUIC(candidate) {
			return nil, types.Hash{}, ErrAddress
		}
	}
	advertisedID, err := outcomeIDFromPeerID(info.ID)
	if err != nil {
		return nil, types.Hash{}, err
	}
	if expected != nil && advertisedID != *expected {
		return nil, types.Hash{}, ErrUnexpectedPeer
	}
	if err := value.inner.Connect(ctx, *info); err != nil {
		return nil, types.Hash{}, err
	}
	stream, err := value.inner.NewStream(ctx, info.ID, SessionProtocol)
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
	peerStreams := config.MaxStreamsPerPeer + internalStreamsPerPeer
	totalStreams := config.MaxConnections * peerStreams
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
		},
		ProtocolPeer: map[protocol.ID]rcmgr.ResourceLimits{
			SessionProtocol: applicationPerPeer,
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
