package chainsession

import (
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
)

func TestHelloDetachesTipAndNegotiatesSmallerFrame(t *testing.T) {
	t.Parallel()

	protocol := testProtocol(t)
	tip := testTip("local", 4, []byte{9})
	hello, err := protocol.Hello(tip)
	if err != nil {
		t.Fatal(err)
	}
	tip.CumulativeWork[0] = 1
	if hello.CumulativeWork[0] != 9 {
		t.Fatal("hello retained caller-owned cumulative work")
	}
	if hello.Features != wire.ChainFeatureVersionedSyncV1|wire.ChainFeaturePeerDiscoveryV1 {
		t.Fatalf("default features=%x", hello.Features)
	}
	hello.MaxFrameBytes = wire.MinVersionedChainFrameBodyBytes
	hello.Features = wire.ChainFeatureVersionedSyncV1
	limits, err := protocol.Negotiate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxFrameBytes != wire.MinVersionedChainFrameBodyBytes ||
		limits.Features != wire.ChainFeatureVersionedSyncV1 {
		t.Fatalf("negotiated limits=%+v", limits)
	}
}

func TestNegotiationRejectsEveryImmutableBoundaryMismatch(t *testing.T) {
	t.Parallel()

	protocol := testProtocol(t)
	hello, err := protocol.Hello(testTip("remote", 4, []byte{9}))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*wire.ChainHello)
		want error
	}{
		{name: "network", edit: func(value *wire.ChainHello) { value.NetworkID++ }, want: ErrNetwork},
		{name: "genesis", edit: func(value *wire.ChainHello) { value.GenesisID = types.DomainHash("test/chainsession/other-genesis") }, want: ErrGenesis},
		{name: "activation", edit: func(value *wire.ChainHello) { value.ActivationHeight++ }, want: ErrActivation},
		{name: "feature", edit: func(value *wire.ChainHello) { value.Features = 1 << 63 }, want: ErrNegotiation},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := hello
			test.edit(&candidate)
			if _, err := protocol.Negotiate(candidate); !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPeerChoiceUsesWorkThenVersionScopedTiePolicy(t *testing.T) {
	t.Parallel()

	protocol := testProtocol(t)
	local := testTip("z-local", 7, []byte{10})
	remote, err := protocol.Hello(testTip("remote", 3, []byte{11}))
	if err != nil {
		t.Fatal(err)
	}
	better, err := protocol.PeerIsBetter(local, remote)
	if err != nil || !better {
		t.Fatalf("higher-work peer better=%v err=%v", better, err)
	}
	remote.CumulativeWork = []byte{10}
	remote.TipID = types.Hash{}
	remote.TipID[31] = 1
	local.ID = types.Hash{}
	local.ID[31] = 2
	better, err = protocol.PeerIsBetter(local, remote)
	if err != nil || better {
		t.Fatalf("version-1 equal-work peer displaced incumbent better=%v err=%v", better, err)
	}
	local.Height = protocol.config.ActivationHeight - 1
	remote.TipHeight = protocol.config.ActivationHeight - 1
	better, err = protocol.PeerIsBetter(local, remote)
	if err != nil || !better {
		t.Fatalf("version-0 smaller-ID peer better=%v err=%v", better, err)
	}
	remote.TipID[31] = 3
	better, err = protocol.PeerIsBetter(local, remote)
	if err != nil || better {
		t.Fatalf("version-0 larger-ID peer better=%v err=%v", better, err)
	}
}

func TestConfigurationRejectsMissingChainIdentity(t *testing.T) {
	t.Parallel()

	if _, err := New(Config{}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("empty configuration error=%v", err)
	}
	config := DefaultConfig(71, types.DomainHash("test/chainsession/genesis"), 5)
	config.MaxFrameBytes = wire.MinVersionedChainFrameBodyBytes - 1
	if _, err := New(config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("small frame configuration error=%v", err)
	}
}

func testProtocol(t testing.TB) *Protocol {
	t.Helper()
	protocol, err := New(DefaultConfig(71, types.DomainHash("test/chainsession/genesis"), 5))
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func testTip(label string, height uint64, work []byte) storage.Tip {
	var target types.Hash
	target[0] = 1
	return storage.Tip{
		ID: types.DomainHash("test/chainsession/tip", []byte(label)), Height: height,
		Timestamp: 1_700_000_000 + height, Target: target,
		StateRoot:      types.DomainHash("test/chainsession/state", []byte(label)),
		CumulativeWork: append([]byte(nil), work...),
	}
}
