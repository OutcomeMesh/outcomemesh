package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type managedCustodyServeCLIFixture struct {
	root                                                                            string
	assignmentPath, admissionPath, manifestPath, receiptPath, serverKey, replicaKey string
	config                                                                          authoritystore.ManagedCustodyServeServiceConfig
	challenge                                                                       workarchive.CustodyChallenge
	journal                                                                         *workarchive.CustodyJournal
}

// Reuse the real archive generator, but give custody its own original owner,
// initial receipt, journal and objects. No prune owner participates in serving.
func newManagedCustodyServeCLIFixture(t testing.TB, lifetimes ...uint64) *managedCustodyServeCLIFixture {
	t.Helper()
	lifetime := uint64(60)
	if len(lifetimes) > 1 {
		t.Fatal("one fixture challenge lifetime expected")
	}
	if len(lifetimes) == 1 {
		lifetime = lifetimes[0]
	}
	if lifetime == 0 || lifetime > 600 {
		t.Fatal("fixture lifetime exceeds the existing protocol limit")
	}
	archive := newPruneEffectCLIFixture(t, false)
	f := &managedCustodyServeCLIFixture{root: archive.root, manifestPath: archive.manifestPath}
	manifest, err := loadArchiveManifest(f.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix())
	replicaKey := pruneCLIKey(61)
	replicaPath := archive.config.Replicas[0].Directory
	receipt, err := workarchive.CreateReplicaReceipt(replicaPath, archive.inventory.Policy.Checkpoint, archive.inventory.Policy.CheckpointPolicy,
		archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits(), replicaKey, pruneCLIHash(113), now-10, now+10_000)
	if err != nil {
		t.Fatal(err)
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: [][ed25519.PublicKeySize]byte{pruneCLIPublic(3)},
		MaximumChallengeLifetime: lifetime, MaximumProofAge: 100, MaximumRenewalTerm: 20_000}
	assignment, err := workarchive.CreateCustodyAuthorityAssignment(manifest, receipt, policy, pruneCLIHash(114), pruneCLIPublic(1),
		[]custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.AllPurposes}}, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	assignmentID, _ := assignment.ID()
	f.challenge, err = workarchive.CreateCustodyChallenge(manifest, receipt, pruneCLIKey(3), now, lifetime, 1, receipt.RetainUntil+1)
	if err != nil {
		t.Fatal(err)
	}
	challengeID, _ := f.challenge.ID()
	admission := signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: assignmentID, ExpectedHead: assignmentID,
		Kind: custodyauthority.Admit, Purpose: custodyauthority.Serve, OperationID: challengeID})
	f.config = authoritystore.ManagedCustodyServeServiceConfig{
		AuthorityPath: filepath.Join(f.root, "managed-authority"), AuthorityPinsPath: filepath.Join(f.root, "managed-authority-pins"),
		ObjectPath: filepath.Join(f.root, "managed-objects"), ObjectPolicy: workarchive.DefaultObjectStorePolicy(),
		Assignment: assignment, ServerPeerID: pruneCLIPeer(45),
		Session: authoritystore.ManagedCustodyServeConfig{AssignmentID: assignmentID, Admission: admission, ChallengeID: challengeID,
			AuditorPeerID: pruneCLIPeer(46), JournalPath: filepath.Join(f.root, "managed-journal"), Manifest: manifest, InitialReceipt: receipt,
			CustodyPolicy: policy, JournalLimits: workarchive.DefaultCustodyJournalLimits(), ReplicaPrivateKey: replicaKey,
			SessionConfig: workarchive.DefaultCustodySessionConfig()}}
	f.config.Session.SessionConfig.RequestTimeout = 2 * time.Second
	coordinator, err := authoritystore.CreateCoordinatedAuthority(f.config.AuthorityPath, f.config.AuthorityPinsPath, assignment, assignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Append(t.Context(), admission); err != nil {
		_ = coordinator.Close()
		t.Fatal(err)
	}
	if err := coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	objects, err := workarchive.OpenObjectStore(f.config.ObjectPath, f.config.ObjectPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.ImportArchiveDirectory(replicaPath, archive.inventory.Policy.Checkpoint, archive.inventory.Policy.CheckpointPolicy,
		archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	f.journal, _, err = workarchive.OpenOrCreateCustodyJournal(f.config.Session.JournalPath, manifest, receipt, policy)
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(f.root, "managed-metadata")
	if err := os.Mkdir(metadata, 0o700); err != nil {
		t.Fatal(err)
	}
	f.assignmentPath, f.admissionPath, f.receiptPath = filepath.Join(metadata, "assignment.omcaa"), filepath.Join(metadata, "admission.omcae"), filepath.Join(metadata, "initial.omrr")
	f.serverKey, f.replicaKey = filepath.Join(metadata, "server.key"), filepath.Join(metadata, "replica.key")
	assignmentBytes, _ := assignment.CanonicalBytes()
	admissionBytes, _ := admission.CanonicalBytes()
	receiptBytes, _ := receipt.CanonicalBytes()
	writePruneCLIFile(t, f.assignmentPath, assignmentBytes)
	writePruneCLIFile(t, f.admissionPath, admissionBytes)
	writePruneCLIFile(t, f.receiptPath, receiptBytes)
	writePruneCLIFile(t, f.serverKey, pruneCLIKey(45).Seed())
	writePruneCLIFile(t, f.replicaKey, replicaKey.Seed())
	return f
}

func (f *managedCustodyServeCLIFixture) args(mode string) []string {
	c, s := f.config, f.config.Session
	ticketID, _ := s.Admission.ID()
	args := []string{managedCustodyServeCommand, "--assignment", f.assignmentPath, "--assignment-id", s.AssignmentID.String(),
		"--admission", f.admissionPath, "--ticket-id", ticketID.String(), "--challenge-id", s.ChallengeID.String(),
		"--manifest", f.manifestPath, "--receipt", f.receiptPath, "--authority", c.AuthorityPath, "--authority-pins", c.AuthorityPinsPath,
		"--journal", s.JournalPath, "--objects", c.ObjectPath, "--key", f.serverKey, "--replica-key", f.replicaKey,
		"--server-peer-id", c.ServerPeerID.String(), "--auditor-peer-id", s.AuditorPeerID.String(), "--timeout", "2s",
		"--max-challenge-lifetime-seconds", strconv.FormatUint(s.CustodyPolicy.MaximumChallengeLifetime, 10),
		"--max-proof-age-seconds", strconv.FormatUint(s.CustodyPolicy.MaximumProofAge, 10),
		"--max-renewal-term-seconds", strconv.FormatUint(s.CustodyPolicy.MaximumRenewalTerm, 10)}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	return args
}

func (f *managedCustodyServeCLIFixture) snapshot(t testing.TB) authoritystore.Coordination {
	t.Helper()
	owner, err := authoritystore.OpenCoordinator(f.config.AuthorityPath, f.config.AuthorityPinsPath, f.config.Assignment, f.config.Session.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.Snapshot()
	if closeErr := owner.Close(); err != nil || closeErr != nil {
		t.Fatal("original owner snapshot/close", err, closeErr)
	}
	return state
}

func (f *managedCustodyServeCLIFixture) assertBusy(t testing.TB) {
	t.Helper()
	owner, err := authoritystore.OpenCoordinator(f.config.AuthorityPath, f.config.AuthorityPinsPath, f.config.Assignment, f.config.Session.AssignmentID)
	if owner != nil {
		_ = owner.Close()
	}
	if !errors.Is(err, authoritystore.ErrBusy) {
		t.Fatal("managed server released the original owner", err)
	}
}
