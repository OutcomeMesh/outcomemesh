package main

import (
	"strconv"
	"testing"

	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type managedCustodyPairCLIFixture struct {
	audit  *managedCustodyAuditCLIFixture
	config authoritystore.ManagedCustodyPairRuntimeConfig
}

func newManagedCustodyPairCLIFixture(t testing.TB) *managedCustodyPairCLIFixture {
	t.Helper()
	a := newManagedCustodyAuditCLIFixture(t)
	owner, err := authoritystore.OpenCoordinator(a.config.AuthorityPath, a.config.AuthorityPinsPath, a.config.Assignment, a.config.Audit.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	session, err := authoritystore.NewManagedCustodyAuditSession(t.Context(), owner, a.config.Audit)
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	challenge, err := session.PrepareChallenge(t.Context())
	if closeErr := owner.Close(); err != nil || closeErr != nil {
		t.Fatal("prepare exact admitted challenge", err, closeErr)
	}
	id, _ := challenge.ID()
	if id != a.serve.config.Session.ChallengeID {
		t.Fatal("audit intent changed the existing Serve challenge")
	}
	return &managedCustodyPairCLIFixture{audit: a, config: authoritystore.ManagedCustodyPairRuntimeConfig{
		AuthorityPath: a.config.AuthorityPath, AuthorityPinsPath: a.config.AuthorityPinsPath, Assignment: a.config.Assignment, Audit: a.config.Audit,
		Serve: a.serve.config.Session, ObjectPath: a.serve.config.ObjectPath, ObjectPolicy: a.serve.config.ObjectPolicy,
		AuditorPeerID: a.config.AuditorPeerID, ReplicaPeerID: a.serve.config.ServerPeerID}}
}

func (f *managedCustodyPairCLIFixture) args(mode string) []string {
	c, a, s := f.config, f.config.Audit, f.config.Serve
	auditTicket, _ := a.Admission.ID()
	serveTicket, _ := s.Admission.ID()
	args := []string{managedCustodyPairCommand, "--assignment", f.audit.serve.assignmentPath, "--assignment-id", a.AssignmentID.String(),
		"--audit-admission", f.audit.admissionPath, "--audit-ticket-id", auditTicket.String(), "--serve-admission", f.audit.serve.admissionPath, "--serve-ticket-id", serveTicket.String(),
		"--intent", a.IntentPath, "--intent-id", a.IntentID.String(), "--challenge-id", s.ChallengeID.String(), "--manifest", f.audit.serve.manifestPath, "--receipt", f.audit.serve.receiptPath,
		"--authority", c.AuthorityPath, "--authority-pins", c.AuthorityPinsPath, "--audit-journal", a.JournalPath, "--replica-journal", s.JournalPath, "--artifacts", a.ArtifactsPath, "--objects", c.ObjectPath,
		"--auditor-key", f.audit.auditorKey, "--replica-key", f.audit.serve.replicaKey, "--auditor-transport-key", f.audit.transportKey, "--replica-transport-key", f.audit.serve.serverKey,
		"--auditor-peer-id", c.AuditorPeerID.String(), "--replica-peer-id", c.ReplicaPeerID.String(), "--timeout", "2s",
		"--max-challenge-lifetime-seconds", strconv.FormatUint(a.CustodyPolicy.MaximumChallengeLifetime, 10), "--max-proof-age-seconds", strconv.FormatUint(a.CustodyPolicy.MaximumProofAge, 10),
		"--max-renewal-term-seconds", strconv.FormatUint(a.CustodyPolicy.MaximumRenewalTerm, 10)}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	return args
}

func (f *managedCustodyPairCLIFixture) snapshot(t testing.TB) authoritystore.Coordination {
	return f.audit.snapshot(t)
}
func (f *managedCustodyPairCLIFixture) assertBusy(t testing.TB) { f.audit.assertBusy(t) }

type managedCustodyPairCLIHeads struct {
	Audit, Replica workarchive.CustodyJournalState
}

func (f *managedCustodyPairCLIFixture) heads(t testing.TB) managedCustodyPairCLIHeads {
	t.Helper()
	a := f.config.Audit
	_, audit, err := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), a.JournalPath, a.Manifest, a.InitialReceipt, a.CustodyPolicy, a.JournalLimits)
	if err != nil {
		t.Fatal(err)
	}
	s := f.config.Serve
	_, replica, err := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), s.JournalPath, s.Manifest, s.InitialReceipt, s.CustodyPolicy, s.JournalLimits)
	if err != nil {
		t.Fatal(err)
	}
	return managedCustodyPairCLIHeads{Audit: audit, Replica: replica}
}
