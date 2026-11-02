//go:build linux || darwin

package main

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	relay "github.com/outcomemesh/outcomemesh/node/pruneservice/servicerelay"
)

func TestPruneServiceRemoteCLIReviewRejectsForeignRolesAndMalformedOptions(t *testing.T) {
	f := preparePruneServiceOwnerCLI(t)
	did, _ := f.descriptor.ID()
	pub := func(k byte) string { return hex.EncodeToString(pruneCLIKey(k)[32:]) }
	seed := filepath.Join(f.public, "missing-transport.seed")
	args := []string{pruneServiceCommand, "--action", "remote-call", "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--request", f.requestPath, "--address", "/ip4/127.0.0.1/udp/1/quic-v1", "--transport-key", seed, "--transport-public-key", pub(190), "--relay-public-key", pub(191), "--key", f.consumerPath, "--challenge-out", filepath.Join(f.public, "net.challenge"), "--approval-out", filepath.Join(f.public, "net.approval"), "--out", filepath.Join(f.public, "net.response")}
	pruneServiceCLIReview(t, args)
	if _, err := os.Stat(seed); !os.IsNotExist(err) {
		t.Fatal("review loaded or created private seed", err)
	}
	for _, extra := range [][]string{{"--timeout", "0s"}, {"--timeout", "99ms"}, {"--timeout", "121s"}, {"--listen", "/ip4/0.0.0.0/udp/0/quic-v1"}, {"--client-transport-keys", pub(192)}, {"--mode", "run"}} {
		if err := runPruneServiceCLIContext(t.Context(), append(append([]string(nil), args...), extra...), io.Discard); err == nil {
			t.Fatal("malformed network flags accepted", extra)
		}
	}
	for _, key := range [][32]byte{f.descriptor.Transport, f.descriptor.Policy.Owner, f.descriptor.Policy.Controller, f.descriptor.Policy.Guard, f.descriptor.Policy.Service.Service, f.descriptor.Policy.Service.Issuer, f.descriptor.Policy.Witnesses[0]} {
		if relay.ValidateTransport(f.descriptor, key) == nil {
			t.Fatal("transport shares privileged role")
		}
	}
	a := pruneServiceCLIFlags{Action: "relay-serve", TransportPublic: pub(190)}
	for _, peers := range []string{"", pub(191) + "," + pub(191), pub(190), pub(191) + ",", hex.EncodeToString(f.descriptor.Transport[:])} {
		a.Clients = peers
		if _, _, _, err := pruneServiceTransportKeys(a, f.descriptor); err == nil {
			t.Fatal("invalid explicit allowlist accepted")
		}
	}
	a.Action = "remote-call"
	a.RelayPublic = pub(190)
	if _, _, _, err := pruneServiceTransportKeys(a, f.descriptor); err == nil {
		t.Fatal("same client and relay identity accepted")
	}
}
