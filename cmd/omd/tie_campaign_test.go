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

	auditPath := filepath.Join(t.TempDir(), "audit-observers.txt")
	auditLines := []string{
		bytesToLowerHex(observers[0][:]) + " /evidence/a.omtr /evidence/a-confirmed",
		bytesToLowerHex(observers[1][:]) + " /evidence/b.omtr /evidence/b-confirmed",
	}
	writeAudit := func(lines []string, newline bool) {
		t.Helper()
		encoded := strings.Join(lines, "\n")
		if newline {
			encoded += "\n"
		}
		if err := os.WriteFile(auditPath, []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeAudit(auditLines, true)
	auditObservers, err := loadCampaignAuditObservers(auditPath, plan)
	if err != nil || len(auditObservers) != 2 ||
		auditObservers[0].ObserverPublicKey != observers[0] ||
		auditObservers[1].ReceiptPath != "/evidence/b.omtr" ||
		auditObservers[1].ConfirmationDirectory != "/evidence/b-confirmed" {
		t.Fatalf("audit observers=%+v err=%v", auditObservers, err)
	}
	writeAudit([]string{auditLines[1], auditLines[0]}, true)
	if _, err := loadCampaignAuditObservers(auditPath, plan); err == nil {
		t.Fatal("noncanonical audit observer order was accepted")
	}
	writeAudit(auditLines, false)
	if _, err := loadCampaignAuditObservers(auditPath, plan); err == nil {
		t.Fatal("audit observer list without final newline was accepted")
	}
}
