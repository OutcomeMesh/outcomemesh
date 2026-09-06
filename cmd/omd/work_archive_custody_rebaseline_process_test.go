//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestProcessArchiveCustodyRebaselineProposesWithoutCutover(t *testing.T) {
	f := newProcessArchiveObjectFixture(t)
	ctx := context.Background()
	replicaKey, auditorKey := processCustodyKey("old-rebaseline-replica"), processCustodyKey("old-rebaseline-auditor")
	public := func(key ed25519.PrivateKey) [ed25519.PublicKeySize]byte {
		var value [ed25519.PublicKeySize]byte
		copy(value[:], key.Public().(ed25519.PublicKey))
		return value
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: [][ed25519.PublicKeySize]byte{public(auditorKey)},
		MaximumChallengeLifetime: 120, MaximumProofAge: 120, MaximumRenewalTerm: defaultCustodyRenewalTerm}
	now := unixNow()
	// Everything before this proposal happened during an old, now expired term.
	initial, err := workarchive.CreateReplicaReceipt(f.archive, f.checkpoint, f.policy, f.base, f.parameters,
		workarchive.DefaultLimits(), replicaKey, types.Hash{31}, now-10_000, now-5_000)
	if err != nil {
		t.Fatal(err)
	}
	store, err := workarchive.OpenObjectStore(f.sourceStore, workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveDirectory(f.archive, f.checkpoint, f.policy, f.base, f.parameters, workarchive.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	challenge, err := workarchive.CreateCustodyChallenge(f.manifest, initial, auditorKey, now-9_000, 60, 1, now-1_000)
	if err != nil {
		t.Fatal(err)
	}
	batch, proof, err := workarchive.AnswerCustodyChallenge(store, f.manifest, initial, challenge, policy, replicaKey, now-8_999)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := workarchive.RenewReplicaReceipt(f.manifest, initial, challenge, batch, proof, policy, replicaKey, now-8_999)
	if err != nil {
		t.Fatal(err)
	}
	record := workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}
	aJournal, rJournal, artifacts := filepath.Join(f.root, "old-auditor"), filepath.Join(f.root, "old-replica"), filepath.Join(f.root, "old-artifacts")
	if _, _, err := workarchive.OpenOrCreateCustodyJournal(aJournal, f.manifest, initial, policy); err != nil {
		t.Fatal(err)
	}
	replica, _, err := workarchive.OpenOrCreateCustodyJournal(rJournal, f.manifest, initial, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := replica.Append(record); err != nil {
		t.Fatal(err)
	}
	lock, err := workarchive.AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	challengePath, _, _ := custodyCycleArtifactPaths(artifacts, 1)
	encodedChallenge, _ := challenge.CanonicalBytes()
	if err := publishImmutableArtifact(challengePath, encodedChallenge); err != nil {
		t.Fatal(err)
	}
	aBackup, rBackup := filepath.Join(f.root, "auditor-backup"), filepath.Join(f.root, "replica-backup")
	a, _, err := workarchive.CreateCustodyBackup(ctx, aBackup, aJournal, artifacts, f.manifest, initial, policy)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := workarchive.CreateCustodyBackup(ctx, rBackup, rJournal, "", f.manifest, initial, policy)
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := a.ID()
	rID, _ := r.ID()
	transfer, err := workarchive.PrepareCustodyHistoricalTransfer(aBackup, rBackup, aID, rID, f.manifest, initial, policy)
	if err != nil {
		t.Fatal(err)
	}
	transferID, _ := transfer.ID()
	packagePath, recovery := filepath.Join(f.root, "handoff"), filepath.Join(f.root, "recovery")
	if _, _, err := workarchive.CreateCustodyHistoricalTransferPackage(ctx, packagePath, transferID, aBackup, rBackup, aID, rID, f.manifest, initial, policy); err != nil {
		t.Fatal(err)
	}
	application, _, err := workarchive.CreateCustodyHistoricalApplication(ctx, recovery, packagePath, transferID, aBackup, rBackup, aID, rID,
		f.manifest, initial, policy, workarchive.DefaultCustodyJournalLimits())
	if err != nil {
		t.Fatal(err)
	}
	applicationID, _ := application.ID()
	initialPath := filepath.Join(f.root, "initial.omrr")
	encodedInitial, _ := initial.CanonicalBytes()
	writeProcessCustodyCanonical(t, initialPath, encodedInitial)
	nextKey, nextAuditor := processCustodyKey("next-rebaseline-replica"), public(processCustodyKey("next-rebaseline-auditor"))
	nextKeyPath := filepath.Join(f.root, "next-replica.key")
	writeProcessCustodyKey(t, nextKeyPath, nextKey)
	proposalPath := filepath.Join(f.root, "proposal.omcrb")
	args := []string{"work-archive-custody-rebaseline", "--proposal", proposalPath,
		"--data", f.data, "--archive", f.archive, "--manifest", f.manifestPath, "--checkpoint", f.checkpointPath,
		"--receipt", initialPath, "--auditor-public-key", types.Hash(public(auditorKey)).String(),
		"--next-auditor-public-key", types.Hash(nextAuditor).String(), "--next-replica-public-key", types.Hash(public(nextKey)).String(),
		"--location-id", types.Hash{32}.String(), "--recovery", recovery, "--package", packagePath,
		"--application-id", applicationID.String(), "--transfer-id", transferID.String(),
		"--auditor-backup", aBackup, "--replica-backup", rBackup, "--auditor-checkpoint-id", aID.String(), "--replica-checkpoint-id", rID.String()}
	for _, key := range f.attestorPublicKey {
		args = append(args, "--attestor-public-key", key)
	}
	creation := append(append([]string(nil), args...), "--mode", "create", "--next-replica-key", nextKeyPath, "--retain-until", strconv.FormatUint(now+3_600, 10))
	for _, extra := range [][]string{{"--mode", "activate"}, {"--resume"}, {"--application-id", transferID.String()},
		{"--next-replica-public-key", types.Hash(public(replicaKey)).String()}, {"--review-lifetime-seconds", "601"},
		{"--proposal", filepath.Join(recovery, "must-not-appear")}, {"--at", strconv.FormatUint(now, 10)}} {
		invalid := append(append([]string(nil), creation...), extra...)
		if output, err := runProcessCommandError(20*time.Second, invalid...); err == nil {
			t.Fatalf("bad proposal accepted: %s", output)
		}
		if _, err := os.Lstat(proposalPath); !os.IsNotExist(err) {
			t.Fatal("invalid proposal wrote output")
		}
	}
	output, err := runProcessCommandError(30*time.Second, creation...)
	fields := outputFields(output, "work_archive_custody_rebaseline")
	if err != nil || fields["id"] == "" || fields["application"] != applicationID.String() || fields["proposal_only"] != "true" ||
		fields["archive_replayed"] != "true" || fields["participant_fenced"] != "false" || fields["automatic_resume"] != "false" || fields["availability_attested"] != "false" {
		t.Fatalf("create: %v\n%s", err, output)
	}
	before := mustReadProcessRebaseline(t, proposalPath)
	proposal, err := workarchive.DecodeCustodyRebaselineProposal(before)
	if err != nil || proposal.ReplayedAt < now {
		t.Fatal("incorrect proposal time", err)
	}
	if output, err := runProcessCommandError(20*time.Second, creation...); err == nil {
		t.Fatalf("creation silently refreshed proposal: %s", output)
	}
	verify := append(append([]string(nil), args...), "--expected-id", fields["id"])
	if output, err := runProcessCommandError(30*time.Second, verify...); err != nil {
		t.Fatalf("verify: %v\n%s", err, output)
	}
	for _, extra := range [][]string{{"--expected-id", transferID.String()}, {"--next-replica-key", nextKeyPath},
		{"--retain-until", strconv.FormatUint(now+7_200, 10)}, {"--location-id", types.Hash{33}.String()}} {
		if output, err := runProcessCommandError(20*time.Second, append(append([]string(nil), verify...), extra...)...); err == nil {
			t.Fatalf("bad review accepted: %s", output)
		}
	}
	if !bytes.Equal(before, mustReadProcessRebaseline(t, proposalPath)) {
		t.Fatal("review or retry changed proposal")
	}
	liveJournal := filepath.Join(f.root, "must-not-start")
	if output, err := runProcessCommandError(15*time.Second, "work-archive-custody-serve-quic",
		"--key", f.serverKey, "--auditor-peer-id", f.clientPeerID.String(), "--replica-key", nextKeyPath,
		"--auditor-public-key", types.Hash(nextAuditor).String(), "--manifest", f.manifestPath,
		"--receipt", proposalPath, "--object-store", f.sourceStore, "--journal", liveJournal); err == nil {
		t.Fatalf("proposal started a live replica: %s", output)
	}
	if _, err := os.Lstat(liveJournal); !os.IsNotExist(err) {
		t.Fatal("proposal initialized a live journal")
	}
	if _, _, err := workarchive.OpenOrCreateCustodyJournal(filepath.Join(recovery, "journal"), f.manifest, initial, policy); err != workarchive.ErrCustodyJournalHistoricalOnly {
		t.Fatal("proposal activated reconstruction", err)
	}
	if _, err := workarchive.VerifyCustodyHistoricalApplication(recovery, applicationID, packagePath, transferID, aBackup, rBackup, aID, rID, f.manifest, initial, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := workarchive.VerifyCustodyBackup(aBackup, aID, f.manifest, initial, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := workarchive.VerifyCustodyBackup(rBackup, rID, f.manifest, initial, policy); err != nil {
		t.Fatal(err)
	}
	checkProcessLocalCustodyRetirement(t, f, args, fields["id"], aJournal, artifacts, rJournal, initialPath,
		replicaKey, auditorKey, challenge)
}

func mustReadProcessRebaseline(t testing.TB, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
