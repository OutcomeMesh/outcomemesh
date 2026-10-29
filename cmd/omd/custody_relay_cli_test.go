package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lpcrypto "github.com/libp2p/go-libp2p/core/crypto"
	lppeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/transport"
)

func TestGatewayRelayCLIReviewPinsInputsWithoutOpeningKeysOrNetwork(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "omesh-relay-review-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	key := filepath.Join(root, "network.seed")
	// Deliberately invalid seed: review must not load it.
	if e := os.WriteFile(key, []byte("not a seed"), 0600); e != nil {
		t.Fatal(e)
	}
	d, e := (wire.Descriptor{RootID: f.Hash("root"), SourceID: f.Hash("source"), GenesisID: f.Hash("genesis"), GenesisDescriptorID: f.Hash("descriptor"), EnrollmentID: f.Hash("enrollment"), Gateway: f.Public(1), Issuer: f.Public(2), Clients: [][32]byte{f.Public(3)}, OwnerUID: 0, ParticipantUID: 65534, EventLimit: 16}).Sign(f.Key(2))
	if e != nil {
		t.Fatal(e)
	}
	dr, _ := d.CanonicalBytes()
	dp := filepath.Join(root, "descriptor")
	os.WriteFile(dp, dr, 0644)
	id, _ := d.ID()
	payload, e := (v2.ProtectedCommand{Kind: v2.ProtectedEndorse, Data: []byte("public preparation"), Now: 1}).CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	q, e := (wire.Request{DescriptorID: id, Nonce: f.Hash("attempt"), Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(payload)}).Sign(f.Key(3))
	if e != nil {
		t.Fatal(e)
	}
	packet, _ := wire.EncodeRuntimeRequest(q, payload)
	rp := filepath.Join(root, "request")
	os.WriteFile(rp, packet, 0644)
	pub := f.Public(46)
	networkKey, e := lpcrypto.UnmarshalEd25519PublicKey(pub[:])
	if e != nil {
		t.Fatal(e)
	}
	pid, e := lppeer.IDFromPublicKey(networkKey)
	if e != nil {
		t.Fatal(e)
	}
	address := "/ip4/127.0.0.1/udp/1234/quic-v1/p2p/" + pid.String()
	networkID, e := transport.PeerIDFromPublicKey(pub[:])
	if e != nil {
		t.Fatal(e)
	}
	base := []string{custodyRelayCommand, "--descriptor", dp, "--descriptor-id", id.String(), "--key", key}
	for _, extra := range [][]string{
		{"--action", "call", "--address", address, "--peer", networkID.String(), "--request", rp, "--out", filepath.Join(root, "response")},
		{"--action", "serve", "--socket", filepath.Join(root, "gateway.sock"), "--listen", "/ip4/127.0.0.1/udp/0/quic-v1", "--clients", f.Hash("client").String()},
	} {
		args := append(append([]string{}, base...), extra...)
		var out bytes.Buffer
		if e := runCustodyRelay(t.Context(), args, &out); e != nil {
			t.Fatal(e)
		}
		fields := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
		if fields["keys_loaded"] != "false" || fields["network_opened"] != "false" || fields["review_id"] == "" {
			t.Fatal(fields)
		}
		run := append(append([]string{}, args...), "--mode", "run", "--expected-review-id", fields["review_id"])
		mutated := replaceRemoteCLIFlag(run, "--descriptor-id", types.Hash{}.String())
		if e := runCustodyRelay(t.Context(), mutated, &bytes.Buffer{}); e == nil {
			t.Fatal("changed descriptor")
		}
		mutated = replaceRemoteCLIFlag(run, "--key", dp)
		if e := runCustodyRelay(t.Context(), mutated, &bytes.Buffer{}); e == nil {
			t.Fatal("changed key path")
		}
		mutated = replaceRemoteCLIFlag(run, "--timeout", "5s")
		if e := runCustodyRelay(t.Context(), mutated, &bytes.Buffer{}); e == nil {
			t.Fatal("changed timeout")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if e := runCustodyRelay(ctx, run, &bytes.Buffer{}); e == nil {
			t.Fatal("canceled run")
		}
		if e := runCustodyRelay(t.Context(), run, &bytes.Buffer{}); e == nil {
			t.Fatal("invalid actual key")
		}
	}
	if _, e := os.Stat(filepath.Join(root, "response")); !os.IsNotExist(e) {
		t.Fatal("review wrote response")
	}
	if _, e := os.Stat(filepath.Join(root, "gateway.sock")); !os.IsNotExist(e) {
		t.Fatal("review opened socket")
	}
	call := append(append([]string{}, base...), "--action", "call", "--address", address, "--peer", networkID.String(), "--request", rp, "--out", filepath.Join(root, "response"))
	for _, args := range [][]string{append(append([]string{}, call...), "--root", root), replaceRemoteCLIFlag(call, "--timeout", "11s"), replaceRemoteCLIFlag(call, "--address", "/ip4/127.0.0.1/tcp/1234"), replaceRemoteCLIFlag(call, "--out", key), replaceRemoteCLIFlag(call, "--peer", f.Hash("wrong-peer").String()), replaceRemoteCLIFlag(call, "--address", "/ip4/127.0.0.1/udp/1234/quic-v1")} {
		if e := runCustodyRelay(t.Context(), args, &bytes.Buffer{}); e == nil {
			t.Fatal("unsafe/irrelevant selector accepted", args)
		}
	}
	packet[len(packet)-1] ^= 1
	os.WriteFile(rp, packet, 0644)
	if e := runCustodyRelay(t.Context(), call, &bytes.Buffer{}); e == nil {
		t.Fatal("changed payload accepted")
	}
}
