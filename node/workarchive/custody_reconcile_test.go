package workarchive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCustodyReconciliationSeparatesHistoricalResponseFromFreshness(t *testing.T) {
	fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, false, false)
	if _, _, err := replica.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	if _, err := replica.Rotate(); err != nil {
		t.Fatal(err)
	}
	aPath, aCheckpoint := createPinTestBackup(t, fixture, auditor.path, artifacts)
	rPath, rCheckpoint := createPinTestBackup(t, fixture, replica.path, "")
	for _, at := range []uint64{fixture.record.Proof.RespondedAt, fixture.record.Proof.RespondedAt + fixture.policy.MaximumProofAge, fixture.record.Proof.RespondedAt + fixture.policy.MaximumProofAge + 1, 30_000, ^uint64(0)} {
		report, err := InspectCustodyReconciliation(aPath, rPath, mustCheckpointID(t, aCheckpoint), mustCheckpointID(t, rCheckpoint), fixture.manifest, fixture.receipt, fixture.policy, at)
		if err != nil {
			t.Fatal(err)
		}
		if report.Relation != "replica-ahead" || report.CommonSequence != 0 || report.AuditorSequence != 0 || report.ReplicaSequence != 1 || report.Pending.RecordSource != "replica-slot" || report.Pending.State != "historical-response" || report.NextStep != "review-historical-response" || report.AutomaticResumeAllowed {
			t.Fatalf("bad historical report: %+v", report)
		}
		wantFresh := at-fixture.record.Proof.RespondedAt <= fixture.policy.MaximumProofAge
		if report.ReplicaProofWithinAge != wantFresh || report.ReplicaRespondedAt != fixture.record.Proof.RespondedAt || report.AuditorProofWithinAge || report.AuditorRespondedAt != 0 {
			t.Fatal("incorrect head proof freshness")
		}
		if report.Pending.ProofWithinAge != wantFresh || report.Pending.ReceiptUnexpired != (at < fixture.record.RenewedReceipt.RetainUntil) {
			t.Fatalf("wrong freshness at %d: %+v", at, report.Pending)
		}
		if wantFresh != (VerifyReplicaRenewal(fixture.manifest, fixture.receipt, fixture.record.RenewedReceipt, fixture.record.Challenge, fixture.record.Batch, fixture.record.Proof, fixture.policy, at) == nil) {
			t.Fatal("assessment bypassed live proof-age check")
		}
	}
	assertReconciliationBackupsUnchanged(t, fixture, aPath, aCheckpoint, rPath, rCheckpoint)
	if state, err := auditor.State(); err != nil || state.Sequence != 0 {
		t.Fatalf("inspection appended a response: %v", err)
	}
}

func TestCustodyReconciliationDoesNotReplaceExpiredUnansweredIntent(t *testing.T) {
	fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, false, false)
	for _, test := range []struct {
		at          uint64
		state, next string
	}{
		{1_000, "future-request", "review-clock"},
		{1_001, "unanswered-open", "review-exact-retry"},
		{fixture.record.Challenge.ExpiresAt, "unanswered-open", "review-exact-retry"},
		{fixture.record.Challenge.ExpiresAt + 1, "unanswered-expired", "review-rebaseline"},
		{30_000, "unanswered-expired", "review-rebaseline"},
	} {
		report := inspectReconciliationTestCopies(t, fixture, auditor, replica, artifacts, test.at)
		if report.Pending.State != test.state || report.Pending.RecordSource != "none" || report.NextStep != test.next || report.Pending.ProofWithinAge {
			t.Fatalf("at %d: %+v", test.at, report)
		}
	}
	if _, _, err := AnswerCustodyChallenge(fixture.store, fixture.manifest, fixture.receipt, fixture.record.Challenge, fixture.policy, fixture.replicaKey, 30_000); err == nil {
		t.Fatal("outage assessment enabled a new proof for an expired request")
	}
	encoded, _ := fixture.record.Challenge.CanonicalBytes()
	actual, err := os.ReadFile(filepath.Join(artifacts, "cycle-00000000000000000001", "challenge.omcc"))
	if err != nil || !bytes.Equal(actual, encoded) {
		t.Fatal("inspection replaced pending intent")
	}
}

func TestCustodyReconciliationFindsDivergenceWithoutChoosingLongerChain(t *testing.T) {
	fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	for _, journal := range []*CustodyJournal{auditor, replica} {
		if _, _, err := journal.Append(fixture.record); err != nil {
			t.Fatal(err)
		}
	}
	writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, true, true)
	left := nextCustodyJournalRecord(t, fixture, fixture.record.RenewedReceipt, 211, 1_004, 1_005, 30_000)
	right := nextCustodyJournalRecord(t, fixture, fixture.record.RenewedReceipt, 212, 1_004, 1_005, 30_000)
	if _, _, err := auditor.Append(left); err != nil {
		t.Fatal(err)
	}
	writeReconciliationArtifacts(t, artifacts, 2, left, true, true, true)
	if _, _, err := replica.Append(right); err != nil {
		t.Fatal(err)
	}
	third := nextCustodyJournalRecord(t, fixture, right.RenewedReceipt, 213, 1_008, 1_009, 35_000)
	if _, _, err := replica.Append(third); err != nil {
		t.Fatal(err)
	}
	report := inspectReconciliationTestCopies(t, fixture, auditor, replica, artifacts, 40_000)
	if report.Relation != "diverged" || report.CommonSequence != 1 || report.FirstDivergence != 2 || report.AuditorSequence != 2 || report.ReplicaSequence != 3 || report.NextStep != "review-divergent-history" {
		t.Fatalf("divergence lost: %+v", report)
	}
}

func TestCustodyReconciliationClassifiesPrefixesAndExpiredReceipts(t *testing.T) {
	fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	for _, test := range []struct {
		at   uint64
		next string
	}{{999, "review-clock"}, {1_002, "review-next-cycle"}, {fixture.receipt.RetainUntil, "review-rebaseline"}} {
		report := inspectReconciliationTestCopies(t, fixture, auditor, replica, artifacts, test.at)
		if report.Relation != "aligned" || report.NextStep != test.next || report.Pending.State != "none" {
			t.Fatalf("empty journals: %+v", report)
		}
	}
	if _, _, err := auditor.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, true, true)
	report := inspectReconciliationTestCopies(t, fixture, auditor, replica, artifacts, 1_003)
	if report.Relation != "auditor-ahead" || report.NextStep != "review-participant-prefix" {
		t.Fatalf("auditor prefix: %+v", report)
	}
	if _, _, err := replica.Append(fixture.record); err != nil {
		t.Fatal(err)
	}
	if _, err := auditor.Rotate(); err != nil {
		t.Fatal(err)
	}
	report = inspectReconciliationTestCopies(t, fixture, auditor, replica, artifacts, 1_003)
	if report.Relation != "aligned" || report.CommonSequence != 1 || report.NextStep != "review-next-cycle" {
		t.Fatalf("rotation changed history comparison: %+v", report)
	}
}

func TestCustodyReconciliationMatchesFullPendingResponseAndChallenge(t *testing.T) {
	for _, mode := range []string{"local-record-only", "both", "different-challenge", "different-response", "local-challenge-conflict", "receipt-only", "wrong-output-receipt", "no-local-intent"} {
		t.Run(mode, func(t *testing.T) {
			fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
			peerRecord := fixture.record
			wantSource, wantState, wantStep := "auditor-artifact", "historical-response", "review-historical-response"
			switch mode {
			case "local-record-only":
				writeReconciliationArtifacts(t, artifacts, 1, fixture.record, false, true, false)
			case "both":
				writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, true, true)
				wantSource = "both"
			case "different-challenge":
				writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, false, false)
				peerRecord = fixture.buildRecord(t, 215, 1_003)
				wantSource, wantState, wantStep = "none", "conflict", "review-conflicting-evidence"
			case "different-response":
				writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, true, false)
				peerRecord = fixture.answerChallenge(t, fixture.record.Challenge, 1_003)
				wantState, wantStep = "conflict", "review-conflicting-evidence"
			case "local-challenge-conflict":
				writeReconciliationArtifacts(t, artifacts, 1, fixture.record, false, true, false)
				writeReconciliationArtifacts(t, artifacts, 1, fixture.buildRecord(t, 216, 1_003), true, false, false)
				wantState, wantStep = "conflict", "review-conflicting-evidence"
			case "receipt-only":
				writeReconciliationArtifacts(t, artifacts, 1, fixture.record, false, false, true)
				wantSource, wantState, wantStep = "none", "conflict", "review-conflicting-evidence"
			case "wrong-output-receipt":
				writeReconciliationArtifacts(t, artifacts, 1, fixture.record, true, false, false)
				writeReconciliationArtifacts(t, artifacts, 1, fixture.buildRecord(t, 217, 1_003), false, false, true)
				wantSource, wantState, wantStep = "replica-slot", "conflict", "review-conflicting-evidence"
			case "no-local-intent":
				wantSource, wantState, wantStep = "none", "none", "review-participant-prefix"
			}
			if mode != "local-record-only" {
				if _, _, err := replica.Append(peerRecord); err != nil {
					t.Fatal(err)
				}
			}
			report := inspectReconciliationTestCopies(t, fixture, auditor, replica, artifacts, 30_000)
			if report.Pending.State != wantState || report.Pending.RecordSource != wantSource || report.NextStep != wantStep {
				t.Fatalf("unexpected assessment: %+v", report)
			}
		})
	}
}

func TestCustodyReconciliationKeepsUnknownPartialAndOrphanEvidenceForReview(t *testing.T) {
	for _, mode := range []string{"orphan", "journal-temporary", "artifact-temporary", "future-cycle", "missing-artifact", "conflicting-artifact"} {
		t.Run(mode, func(t *testing.T) {
			fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
			want := "review-retained-evidence"
			switch mode {
			case "orphan":
				mustPanicCustodyJournal(t, func() {
					_, _, _ = replica.append(fixture.record, custodyJournalHooks{afterBody: panicCustodyJournalHook})
				})
			case "journal-temporary":
				writeCheckpointTestFile(t, filepath.Join(auditor.path, "pending", ".outcomemesh-custody-journal-retained"), []byte{1})
			case "artifact-temporary":
				writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000001", ".outcomemesh-work-artifact-retained"), nil)
			case "future-cycle":
				writeReconciliationArtifacts(t, artifacts, 2, fixture.record, true, false, false)
			case "missing-artifact", "conflicting-artifact":
				for _, journal := range []*CustodyJournal{auditor, replica} {
					if _, _, err := journal.Append(fixture.record); err != nil {
						t.Fatal(err)
					}
				}
				want = "review-missing-artifacts"
				if mode == "conflicting-artifact" {
					writeReconciliationArtifacts(t, artifacts, 1, fixture.buildRecord(t, 219, 1_003), true, true, true)
					want = "review-conflicting-evidence"
				}
			}
			report := inspectReconciliationTestCopies(t, fixture, auditor, replica, artifacts, 30_000)
			if report.NextStep != want {
				t.Fatalf("retained evidence ignored: %+v", report)
			}
			if mode == "orphan" && (report.ReplicaOrphanBodies != 1 || report.Pending.RecordSource != "none") {
				t.Fatal("orphan promoted to a committed response")
			}
			if mode == "missing-artifact" && report.MissingCommittedArtifacts != 3 {
				t.Fatal("missing cycle not counted")
			}
		})
	}
}

func TestCustodyReconciliationRequiresPinsTrustAndCompleteScope(t *testing.T) {
	fixture, auditor, replica, artifacts := newCustodyReconciliationFixture(t)
	aPath, aCheckpoint := createPinTestBackup(t, fixture, auditor.path, artifacts)
	rPath, rCheckpoint := createPinTestBackup(t, fixture, replica.path, "")
	aID, rID := mustCheckpointID(t, aCheckpoint), mustCheckpointID(t, rCheckpoint)
	if _, err := InspectCustodyReconciliation(aPath, rPath, aID, rID, fixture.manifest, fixture.receipt, fixture.policy, 0); err == nil {
		t.Fatal("zero time accepted")
	}
	if _, err := InspectCustodyReconciliation(aPath, aPath, aID, aID, fixture.manifest, fixture.receipt, fixture.policy, 1_002); err == nil {
		t.Fatal("same bundle for both roles accepted")
	}
	if _, err := InspectCustodyReconciliation(rPath, aPath, rID, aID, fixture.manifest, fixture.receipt, fixture.policy, 1_002); err == nil {
		t.Fatal("reversed scope accepted")
	}
	wrong := aID
	wrong[0] ^= 1
	if _, err := InspectCustodyReconciliation(aPath, rPath, wrong, rID, fixture.manifest, fixture.receipt, fixture.policy, 1_002); err == nil {
		t.Fatal("wrong pin accepted")
	}
	policy := fixture.policy
	policy.MaximumProofAge++
	if _, err := InspectCustodyReconciliation(aPath, rPath, aID, rID, fixture.manifest, fixture.receipt, policy, 1_002); err == nil {
		t.Fatal("policy drift accepted")
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := InspectCustodyReconciliation(aPath, missing, aID, rID, fixture.manifest, fixture.receipt, fixture.policy, 1_002); err == nil {
		t.Fatal("missing backup accepted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection initialized a backup")
	}
	assertReconciliationBackupsUnchanged(t, fixture, aPath, aCheckpoint, rPath, rCheckpoint)
	writeCheckpointTestFile(t, filepath.Join(artifacts, "cycle-00000000000000000001", "challenge.omcc"), []byte("malformed"))
	badPath, badCheckpoint := createPinTestBackup(t, fixture, auditor.path, artifacts)
	if _, err := InspectCustodyReconciliation(badPath, rPath, mustCheckpointID(t, badCheckpoint), rID, fixture.manifest, fixture.receipt, fixture.policy, 1_002); err == nil {
		t.Fatal("malformed pending challenge treated as no intent")
	}
	assertReconciliationBackupsUnchanged(t, fixture, badPath, badCheckpoint, rPath, rCheckpoint)
}

func newCustodyReconciliationFixture(t testing.TB) (custodyRecordFixture, *CustodyJournal, *CustodyJournal, string) {
	t.Helper()
	fixture := newCustodyRecordFixture(t)
	root := t.TempDir()
	auditor, _, err := OpenOrCreateCustodyJournal(filepath.Join(root, "auditor"), fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	replica, _, err := OpenOrCreateCustodyJournal(filepath.Join(root, "replica"), fixture.manifest, fixture.receipt, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(root, "artifacts")
	lock, err := AcquireCustodyArtifacts(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	return fixture, auditor, replica, artifacts
}

func writeReconciliationArtifacts(t testing.TB, root string, sequence uint64, record CustodyRecord, challenge, response, receipt bool) {
	t.Helper()
	directory := filepath.Join(root, fmt.Sprintf("cycle-%020d", sequence))
	if challenge {
		encoded, _ := record.Challenge.CanonicalBytes()
		writeCheckpointTestFile(t, filepath.Join(directory, "challenge.omcc"), encoded)
	}
	if response {
		encoded, _ := record.CanonicalBytes()
		writeCheckpointTestFile(t, filepath.Join(directory, "record.omcr"), encoded)
	}
	if receipt {
		encoded, _ := record.RenewedReceipt.CanonicalBytes()
		writeCheckpointTestFile(t, filepath.Join(directory, "receipt.omrr"), encoded)
	}
}

func inspectReconciliationTestCopies(t testing.TB, fixture custodyRecordFixture, auditor, replica *CustodyJournal, artifacts string, at uint64) CustodyReconciliationReport {
	t.Helper()
	aPath, aCheckpoint := createPinTestBackup(t, fixture, auditor.path, artifacts)
	rPath, rCheckpoint := createPinTestBackup(t, fixture, replica.path, "")
	report, err := InspectCustodyReconciliation(aPath, rPath, mustCheckpointID(t, aCheckpoint), mustCheckpointID(t, rCheckpoint), fixture.manifest, fixture.receipt, fixture.policy, at)
	if err != nil {
		t.Fatal(err)
	}
	if report.AutomaticResumeAllowed || report.AssessedAt != at || report.AuditorCheckpointID != mustCheckpointID(t, aCheckpoint) || report.ReplicaCheckpointID != mustCheckpointID(t, rCheckpoint) {
		t.Fatal("unbound assessment or recovery authorized")
	}
	assertReconciliationBackupsUnchanged(t, fixture, aPath, aCheckpoint, rPath, rCheckpoint)
	return report
}

func assertReconciliationBackupsUnchanged(t testing.TB, fixture custodyRecordFixture, aPath string, a CustodyCheckpoint, rPath string, r CustodyCheckpoint) {
	t.Helper()
	for path, checkpoint := range map[string]CustodyCheckpoint{aPath: a, rPath: r} {
		if _, err := VerifyCustodyBackup(path, mustCheckpointID(t, checkpoint), fixture.manifest, fixture.receipt, fixture.policy); err != nil {
			t.Fatalf("inspection changed evidence: %v", err)
		}
	}
}

func FuzzCustodyReconciliationPendingNeverPanics(f *testing.F) {
	fixture := newCustodyRecordFixture(f)
	challenge, _ := fixture.record.Challenge.CanonicalBytes()
	record, _ := fixture.record.CanonicalBytes()
	receipt, _ := fixture.record.RenewedReceipt.CanonicalBytes()
	// Mutate small intent/output fields and the source combination. The large
	// canonical response is fixed here; its decoder has its own fuzz target.
	f.Add(challenge, receipt, uint8(3), uint64(30_000))
	f.Add(challenge, []byte{}, uint8(0), uint64(1_002))
	f.Add([]byte{}, []byte{}, uint8(1), ^uint64(0))
	f.Fuzz(func(t *testing.T, challenge, receipt []byte, sources uint8, at uint64) {
		if at == 0 || len(challenge) > MaximumCustodyChallengeBytes || len(receipt) > MaximumReplicaReceiptBytes {
			return
		}
		artifacts := [3][]byte{challenge, nil, receipt}
		if sources&1 != 0 {
			artifacts[1] = record
		}
		var peer *CustodyRecord
		if sources&2 != 0 {
			peer = &fixture.record
		}
		for index := range artifacts {
			if len(artifacts[index]) == 0 {
				artifacts[index] = nil
			}
		}
		report := CustodyReconciliationReport{AssessedAt: at, Pending: CustodyReconciliationPending{Sequence: 1, State: "none", RecordSource: "none"}}
		if err := inspectCustodyReconciliationPending(artifacts, peer, fixture.manifest, fixture.receipt, fixture.policy, &report); err != nil {
			return
		}
		if report.AutomaticResumeAllowed {
			t.Fatal("pending inspection authorized recovery")
		}
		if report.Pending.ProofWithinAge && (report.Pending.RecordSource == "none" || at < report.Pending.RespondedAt || at-report.Pending.RespondedAt > fixture.policy.MaximumProofAge) {
			t.Fatal("stale or absent proof marked within age")
		}
	})
}
