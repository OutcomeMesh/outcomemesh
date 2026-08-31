package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

func TestCampaignObserverRoutesRequireCompleteCanonicalPlanSet(t *testing.T) {
	coordinatorSeed := types.DomainHash("test/omd/campaign-routes/coordinator")
	coordinator := ed25519.NewKeyFromSeed(coordinatorSeed[:])
	observers := make([][ed25519.PublicKeySize]byte, 2)
	for index, label := range []string{"a", "b"} {
		seed := types.DomainHash("test/omd/campaign-routes/observer", []byte(label))
		key := ed25519.NewKeyFromSeed(seed[:])
		copy(observers[index][:], key.Public().(ed25519.PublicKey))
	}
	sort.Slice(observers, func(left, right int) bool {
		return bytes.Compare(observers[left][:], observers[right][:]) < 0
	})
	plan, err := calibration.SignTiePlan(coordinator, calibration.TiePlan{
		Version: calibration.TiePlanVersion2, NetworkID: 301,
		GenesisID: types.DomainHash("test/omd/campaign-routes/genesis"), ActivationHeight: 2,
		TestedMiner:             types.Address(types.DomainHash("test/omd/campaign-routes/tested")),
		ControlMiner:            types.Address(types.DomainHash("test/omd/campaign-routes/control")),
		MaximumPairDelaySeconds: 5, ObserverPublicKeys: observers,
		Slots: []calibration.TiePlanSlot{{StartedAt: 100, EndedAt: 110, FirstRole: calibration.TieRoleTested}},
	})
	if err != nil {
		t.Fatal(err)
	}
	peerA := types.DomainHash("test/omd/campaign-routes/peer-a")
	peerB := types.DomainHash("test/omd/campaign-routes/peer-b")
	lines := []string{
		bytesToLowerHex(observers[0][:]) + " " + peerA.String() + " /ip4/127.0.0.1/udp/9001/quic-v1/p2p/a",
		bytesToLowerHex(observers[1][:]) + " " + peerB.String() + " /ip4/127.0.0.1/udp/9002/quic-v1/p2p/b",
	}
	path := filepath.Join(t.TempDir(), "observers.txt")
	writeRoutes := func(lines []string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeRoutes(lines)
	routes, err := loadCampaignObserverRoutes(path, plan)
	if err != nil || len(routes) != 2 || routes[observers[0]].TransportPeerID != peerA ||
		routes[observers[1]].TransportPeerID != peerB {
		t.Fatalf("routes=%+v err=%v", routes, err)
	}
	writeRoutes([]string{lines[1], lines[0]})
	if _, err := loadCampaignObserverRoutes(path, plan); err == nil {
		t.Fatal("noncanonical observer route order was accepted")
	}
	duplicatePeer := strings.Replace(lines[1], peerB.String(), peerA.String(), 1)
	writeRoutes([]string{lines[0], duplicatePeer})
	if _, err := loadCampaignObserverRoutes(path, plan); err == nil {
		t.Fatal("duplicate observer transport peer ID was accepted")
	}
}
