//go:build integration

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func checkProcessLocalCustodyRetirement(t *testing.T, f processArchiveObjectFixture, args []string, proposalID,
	aJournal, artifacts, rJournal, initialPath string, replicaKey, auditorKey ed25519.PrivateKey, challenge workarchive.CustodyChallenge,
) {
	t.Helper()
	retire := append(append([]string(nil), args...), "--mode", "retire-local", "--expected-id", proposalID,
		"--auditor-journal", aJournal, "--auditor-artifacts", artifacts, "--replica-journal", rJournal)
	for _, extra := range [][]string{{"--mode", "verify-local-retirement"}, {"--mode", "verify"},
		{"--expected-id", types.Hash{9}.String()}, {"--replica-journal", aJournal}, {"--auditor-journal", f.archive},
		{"--retirement-id", proposalID}, {"--review-lifetime-seconds", "60"}} {
		if output, err := runProcessCommandError(20*time.Second, append(append([]string(nil), retire...), extra...)...); err == nil {
			t.Fatalf("bad local retirement accepted: %s", output)
		}
		if _, err := os.Lstat(filepath.Join(aJournal, "retirement.omcrt")); !os.IsNotExist(err) {
			t.Fatal("bad flags retired auditor")
		}
		if _, err := os.Lstat(filepath.Join(rJournal, "retirement.omcrt")); !os.IsNotExist(err) {
			t.Fatal("bad flags retired replica")
		}
	}
	oldReplicaPath, oldAuditorPath := filepath.Join(f.root, "old-replica.key"), filepath.Join(f.root, "old-auditor.key")
	writeProcessCustodyKey(t, oldReplicaPath, replicaKey)
	writeProcessCustodyKey(t, oldAuditorPath, auditorKey)
	var auditorPublic [ed25519.PublicKeySize]byte
	copy(auditorPublic[:], auditorKey.Public().(ed25519.PublicKey))
	fixture := processCustodyFixture{root: f.root, replicaTransport: f.serverKey, auditorTransport: f.clientKey,
		replicaEvidence: oldReplicaPath, auditorEvidence: oldAuditorPath, auditorPublicKey: types.Hash(auditorPublic).String(),
		manifestPath: f.manifestPath, receiptPath: initialPath, objectStorePath: f.sourceStore}
	// This real replica process has already loaded its journal and cached the
	// historical response BEFORE retirement. Startup-only checks cannot stop it.
	server, peerText, address := startProcessCustodyJournalServer(t, fixture, rJournal, "--rotate-every", "0")
	var pairID string
	for index := range 2 {
		output, err := runProcessCommandError(30*time.Second, retire...)
		fields := outputFields(output, "work_archive_custody_retirement")
		if err != nil || fields["id"] == "" || fields["proposal"] != proposalID || fields["changed"] != strconv.FormatBool(index == 0) ||
			fields["local_pair_retired"] != "true" || fields["global_participants_fenced"] != "false" || fields["active_cutover"] != "false" {
			t.Fatalf("retire/retry: %v\n%s", err, output)
		}
		if pairID != "" && pairID != fields["id"] {
			t.Fatal("retry changed retirement ID")
		}
		pairID = fields["id"]
	}
	verify := append(append([]string(nil), retire...), "--mode", "verify-local-retirement", "--retirement-id", pairID)
	if output, err := runProcessCommandError(30*time.Second, verify...); err != nil {
		t.Fatalf("verify retirement: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transportKey, err := loadPrivateKey(f.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := libp2ptransport.New(ctx, transportKey, libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peerID, err := parseHash(peerText)
	if err != nil {
		t.Fatal(err)
	}
	stream, _, err := client.OpenArchiveCustodyStream(ctx, address, peerID)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	encoded, _ := challenge.CanonicalBytes()
	frame := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(frame, uint32(len(encoded)))
	copy(frame[4:], encoded)
	if err := writeCommandBytes(stream, frame); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if n, err := io.ReadFull(stream, prefix[:]); n != 0 || err == nil {
		t.Fatalf("retired in-memory session wrote response bytes: n=%d %v", n, err)
	}
	_ = stream.Close()
	exited := make(chan error, 1)
	go func() { exited <- server.command.Wait() }()
	select {
	case err := <-exited:
		if err == nil || !strings.Contains(server.stderr.String(), workarchive.ErrCustodyJournalRetired.Error()) {
			t.Fatalf("live process retirement: %v\n%s", err, server.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("retired replica did not stop after request")
	}
	if output, err := runProcessCustodyJournalChallenge(t, fixture, address, peerText, aJournal, artifacts, 7_200, 0); err == nil || !strings.Contains(output, workarchive.ErrCustodyJournalRetired.Error()) {
		t.Fatalf("old auditor restarted: %v\n%s", err, output)
	}
	if output, err := runProcessCommandError(15*time.Second, "work-archive-custody-serve-quic", "--key", f.serverKey,
		"--auditor-peer-id", f.clientPeerID.String(), "--replica-key", oldReplicaPath, "--auditor-public-key", fixture.auditorPublicKey,
		"--manifest", f.manifestPath, "--receipt", initialPath, "--object-store", f.sourceStore, "--journal", rJournal); err == nil || !strings.Contains(output, workarchive.ErrCustodyJournalRetired.Error()) {
		t.Fatalf("old replica restarted: %v\n%s", err, output)
	}
	if output, err := runProcessCommandError(30*time.Second, verify...); err != nil {
		t.Fatalf("refused restarts changed evidence: %v\n%s", err, output)
	}
}
