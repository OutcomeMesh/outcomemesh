package main

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type managedCustodyAuditCLIFixture struct {
	serve                                               *managedCustodyServeCLIFixture
	config                                              authoritystore.ManagedCustodyAuditRuntimeConfig
	intent                                              workarchive.CustodyAuditIntent
	intentPath, admissionPath, auditorKey, transportKey string
}

func newManagedCustodyAuditCLIFixture(t testing.TB) *managedCustodyAuditCLIFixture {
	t.Helper()
	s := newManagedCustodyServeCLIFixture(t)
	c := s.config.Session
	initialID, _ := c.InitialReceipt.ID()
	i := workarchive.CustodyAuditIntent{AssignmentID: c.AssignmentID, ConsumerPublicKey: pruneCLIPublic(4), AuditorPublicKey: pruneCLIPublic(3), ReplicaPeerID: s.config.ServerPeerID,
		PriorReceiptID: initialID, IssuedAt: s.challenge.IssuedAt, ExpiresAt: s.challenge.ExpiresAt, RenewUntil: s.challenge.RenewUntil, RequestedSamples: s.challenge.RequestedSamples, Nonce: s.challenge.Nonce}
	root := t.TempDir()
	f := &managedCustodyAuditCLIFixture{serve: s, intent: i, intentPath: filepath.Join(root, "intent.omcai"), admissionPath: filepath.Join(root, "audit.omcae"), auditorKey: filepath.Join(root, "auditor.seed"), transportKey: filepath.Join(root, "transport.seed")}
	// The intent must have its own real parent, separate from metadata/artifacts.
	f.intentPath = filepath.Join(t.TempDir(), "intent.omcai")
	if err := workarchive.PublishCustodyAuditIntent(t.Context(), f.intentPath, i); err != nil {
		t.Fatal(err)
	}
	intentID, _ := i.ID()
	owner, err := authoritystore.OpenCoordinator(s.config.AuthorityPath, s.config.AuthorityPinsPath, s.config.Assignment, c.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.Snapshot()
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	admission := signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: c.AssignmentID, ExpectedSequence: state.Authority.Sequence, ExpectedHead: state.Authority.HeadID, Kind: custodyauthority.Admit, Purpose: custodyauthority.Audit, OperationID: intentID})
	if _, err := owner.Append(t.Context(), admission); err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "auditor-journal")
	if _, _, err := workarchive.OpenOrCreateCustodyJournal(journalPath, c.Manifest, c.InitialReceipt, c.CustodyPolicy); err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(t.TempDir(), "artifacts")
	lock, err := workarchive.AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	f.config = authoritystore.ManagedCustodyAuditRuntimeConfig{AuthorityPath: s.config.AuthorityPath, AuthorityPinsPath: s.config.AuthorityPinsPath, Assignment: s.config.Assignment, AuditorPeerID: c.AuditorPeerID,
		Audit: authoritystore.ManagedCustodyAuditConfig{AssignmentID: c.AssignmentID, IntentID: intentID, Admission: admission, IntentPath: f.intentPath, JournalPath: journalPath, ArtifactsPath: artifacts, Manifest: c.Manifest, InitialReceipt: c.InitialReceipt, CustodyPolicy: c.CustodyPolicy, JournalLimits: c.JournalLimits, AuditorPrivateKey: pruneCLIKey(3), SessionConfig: c.SessionConfig}}
	encoded, _ := admission.CanonicalBytes()
	writePruneCLIFile(t, f.admissionPath, encoded)
	writePruneCLIFile(t, f.auditorKey, pruneCLIKey(3).Seed())
	writePruneCLIFile(t, f.transportKey, pruneCLIKey(46).Seed())
	return f
}

func (f *managedCustodyAuditCLIFixture) args(mode string) []string {
	c, a := f.config, f.config.Audit
	ticket, _ := a.Admission.ID()
	args := []string{managedCustodyAuditCommand, "--assignment", f.serve.assignmentPath, "--assignment-id", a.AssignmentID.String(), "--admission", f.admissionPath, "--ticket-id", ticket.String(),
		"--intent", f.intentPath, "--intent-id", a.IntentID.String(), "--manifest", f.serve.manifestPath, "--receipt", f.serve.receiptPath, "--authority", c.AuthorityPath, "--authority-pins", c.AuthorityPinsPath,
		"--journal", a.JournalPath, "--artifacts", a.ArtifactsPath, "--auditor-key", f.auditorKey, "--auditor-peer-id", c.AuditorPeerID.String(), "--timeout", "2s",
		"--max-challenge-lifetime-seconds", strconv.FormatUint(a.CustodyPolicy.MaximumChallengeLifetime, 10), "--max-proof-age-seconds", strconv.FormatUint(a.CustodyPolicy.MaximumProofAge, 10), "--max-renewal-term-seconds", strconv.FormatUint(a.CustodyPolicy.MaximumRenewalTerm, 10)}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	return args
}

func (f *managedCustodyAuditCLIFixture) snapshot(t testing.TB) authoritystore.Coordination {
	return f.serve.snapshot(t)
}
func (f *managedCustodyAuditCLIFixture) assertBusy(t testing.TB) { f.serve.assertBusy(t) }
