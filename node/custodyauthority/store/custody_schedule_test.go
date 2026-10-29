package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func managedScheduleFixture(t testing.TB, f *managedAuditFixture) (CustodyScheduleContext, custodyauthority.Entry) {
	t.Helper()
	a := f.serve.archive
	next, statement, err := workarchive.PrepareRadixArchiveMigration(a.replicas[0].Directory, a.policy.Checkpoint, a.policy.CheckpointPolicy, a.f.base, a.f.parameters, f.config.Manifest.Anchor.Height+10, workarchive.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var attestations []workarchive.Attestation
	for _, key := range []byte{51, 52} {
		v, err := workarchive.Attest(testKey(key), statement)
		if err != nil {
			t.Fatal(err)
		}
		attestations = append(attestations, v)
	}
	cp, err := workarchive.NewCheckpoint(statement, attestations)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := f.config.Manifest.CanonicalBytes()
	target, _ := next.CanonicalBytes()
	state, err := f.serve.journal.State()
	if err != nil {
		t.Fatal(err)
	}
	proof := workarchive.CustodyScheduleProof{AssignmentID: f.config.AssignmentID, OriginalManifest: original, TargetManifest: target, OriginalCheckpoint: a.policy.Checkpoint, TargetCheckpoint: cp, InitialReceipt: f.config.InitialReceipt, SelectedReceipt: state.CurrentReceipt, JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID}
	id, err := proof.ID()
	if err != nil {
		t.Fatal(err)
	}
	p := testCoordination(t, a.f.coordinator).Authority
	command, err := (custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, ScheduleID: id, AssignmentID: p.AssignmentID, ExpectedSequence: p.Sequence, ExpectedHead: p.HeadID, Kind: custodyauthority.MigrateSchedule}).Sign(f.serve.config.ReplicaPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(command, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return CustodyScheduleContext{Proof: proof, Policy: a.policy.CheckpointPolicy, ExpectedID: id}, entry
}
func migrateManagedSchedule(t testing.TB, f *managedAuditFixture, s CustodyScheduleContext, e custodyauthority.Entry) Commit {
	t.Helper()
	result, err := f.serve.archive.f.coordinator.MigrateCustodySchedule(t.Context(), e, s, f.serve.config.JournalPath, f.config.CustodyPolicy, f.config.JournalLimits)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func scheduledLineage(t testing.TB, f *managedAuditFixture) workarchive.CustodyReceiptLineage {
	t.Helper()
	head, found, err := f.serve.journal.Head()
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := f.config.Manifest.CanonicalBytes()
	l := workarchive.CustodyReceiptLineage{AssignmentID: f.config.AssignmentID, Manifest: manifest, InitialReceipt: f.config.InitialReceipt, Policy: f.config.CustodyPolicy}
	if found {
		if head.Sequence != 1 {
			t.Fatal("fixture supports one entry")
		}
		b, err := head.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		l.Entries = [][]byte{b}
	}
	return l
}
func TestCustodyScheduleLivePairPreservesTicketsAcrossRestart(t *testing.T) {
	f, oldPair := newManagedCustodyPair(t)
	owner := f.serve.archive.f.coordinator
	before := testCoordination(t, owner).Authority
	s, e := managedScheduleFixture(t, f)
	if _, err := owner.Append(t.Context(), e); !errors.Is(err, custodyauthority.ErrCommand) {
		t.Fatal("generic append bypassed source validation", err)
	}
	result := migrateManagedSchedule(t, f, s, e)
	if !result.Appended || result.Snapshot.Pending != before.Pending || !reflect.DeepEqual(before.Operations, result.Snapshot.Operations) {
		t.Fatal("reset obligations")
	}
	if _, err := oldPair.audit.PrepareChallenge(t.Context()); err == nil {
		t.Fatal("old live adapter survived transition")
	}
	if _, err := NewManagedCustodyServeSession(t.Context(), owner, f.serve.config); err == nil {
		t.Fatal("legacy reopen adopted schedule implicitly")
	}
	f.config.Schedule = &s
	f.serve.config.Schedule = &s
	pair := openManagedCustodyPair(t, f)
	first := exchangeManagedCustodyPair(t, f, pair)
	if got := migrateManagedSchedule(t, f, s, e); got.Appended || got.Snapshot.Pending != before.Pending {
		t.Fatal("retry reset or released tickets")
	}
	lineage := scheduledLineage(t, f)
	receipt := first.Audit.Record.RenewedReceipt
	assignment := f.serve.archive.policy.Assignments[0]
	wrapped, err := workarchive.CreateScheduledReplicaReceipt(t.Context(), s.Proof, assignment, s.Policy, lineage, receipt, f.serve.config.ReplicaPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.Original != receipt || wrapped.Original.RetainUntil != receipt.RetainUntil || wrapped.Original.StoredAt != receipt.StoredAt {
		t.Fatal("migration refreshed receipt")
	}
	encoded, _ := wrapped.CanonicalBytes()
	decoded, err := workarchive.DecodeScheduledReplicaReceipt(encoded)
	if err != nil || decoded != wrapped {
		t.Fatal("wrapper roundtrip", err)
	}
	if err := decoded.Verify(t.Context(), s.Proof, assignment, s.Policy, lineage); err != nil {
		t.Fatal(err)
	}
	policy := f.serve.archive.policy.ReplicaPolicy
	if err := decoded.VerifyAvailabilityTime(policy, receipt.RetainUntil+1); err == nil {
		t.Fatal("expired scheduled receipt accepted")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err = OpenCoordinator(f.serve.archive.f.authorityPath, f.serve.archive.f.pinsPath, assignment, f.config.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	f.serve.archive.f.coordinator = owner
	second := exchangeManagedCustodyPair(t, f, openManagedCustodyPair(t, f))
	if second.Audit.Record.RenewedReceipt != receipt {
		t.Fatal("restart reexecuted renewal")
	}
	after := testCoordination(t, owner).Authority
	if after.Pending != before.Pending || !reflect.DeepEqual(before.Operations, after.Operations) {
		t.Fatal("exchange implicitly completed original tickets")
	}
}
func TestCustodyScheduleRejectsChangedProofAndAdvancedSource(t *testing.T) {
	f, pair := newManagedCustodyPair(t)
	s, e := managedScheduleFixture(t, f)
	owner := f.serve.archive.f.coordinator
	before := testCoordination(t, owner)
	wrong := s
	wrong.ExpectedID = types.Hash{}
	if _, err := owner.MigrateCustodySchedule(t.Context(), e, wrong, f.serve.config.JournalPath, f.config.CustodyPolicy, f.config.JournalLimits); err == nil {
		t.Fatal("wrong review accepted")
	}
	exchangeManagedCustodyPair(t, f, pair)
	if _, err := owner.MigrateCustodySchedule(t.Context(), e, s, f.serve.config.JournalPath, f.config.CustodyPolicy, f.config.JournalLimits); err == nil {
		t.Fatal("advanced journal accepted as exact migration cursor")
	}
	if !reflect.DeepEqual(before, testCoordination(t, owner)) {
		t.Fatal("failed review changed authority")
	}
	s, e = managedScheduleFixture(t, f)
	migrateManagedSchedule(t, f, s, e)
	// A valid receipt on another prefix or without the original journal is not
	// enough to replace the selected renewed receipt.
	l := scheduledLineage(t, f)
	assignment := f.serve.archive.policy.Assignments[0]
	missing := l
	missing.Entries = nil
	if err := s.Proof.VerifyLineage(t.Context(), assignment, s.Policy, missing, s.Proof.SelectedReceipt); err == nil {
		t.Fatal("missing lineage accepted")
	}
	b, _ := s.Proof.CanonicalBytes()
	p, err := workarchive.DecodeCustodyScheduleProof(b)
	if err != nil {
		t.Fatal(err)
	}
	round, _ := p.CanonicalBytes()
	if !bytes.Equal(round, b) {
		t.Fatal("noncanonical proof")
	}
	for _, n := range []int{0, 1, 8, 81, len(b) - 1} {
		if _, err := workarchive.DecodeCustodyScheduleProof(b[:n]); err == nil {
			t.Fatal("truncated proof accepted")
		}
	}
	if _, err := workarchive.DecodeCustodyScheduleProof(append(bytes.Clone(b), 0)); err == nil {
		t.Fatal("trailing proof bytes accepted")
	}
}

func TestCustodyScheduleFailureBoundariesKeepOriginalObligations(t *testing.T) {
	for _, stage := range []string{"intent-before-publish", "intent-after-publish", "intent-directory-synced", "authority-before-publish", "authority-after-publish", "authority-directory-synced", "confirm-before-publish", "confirm-after-publish", "confirm-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			f, _ := newManagedCustodyPair(t)
			s, e := managedScheduleFixture(t, f)
			owner := f.serve.archive.f.coordinator
			before := testCoordination(t, owner).Authority
			injected := errors.New("injected schedule persistence failure")
			reached := false
			setCoordinatorHooks(owner, storeHooks{at: func(at string) error {
				if at == stage {
					reached = true
					return injected
				}
				return nil
			}})
			_, err := owner.MigrateCustodySchedule(t.Context(), e, s, f.serve.config.JournalPath, f.config.CustodyPolicy, f.config.JournalLimits)
			if !reached || err == nil {
				t.Fatal("did not reach fault", stage, err)
			}
			owner.Close()
			a := f.serve.archive.policy.Assignments[0]
			owner, err = OpenCoordinator(f.serve.archive.f.authorityPath, f.serve.archive.f.pinsPath, a, f.config.AssignmentID)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			f.serve.archive.f.coordinator = owner
			observed := testCoordination(t, owner)
			if observed.Authority.Pending != before.Pending || !reflect.DeepEqual(observed.Authority.Operations, before.Operations) {
				t.Fatal("failure lost obligations")
			}
			if observed.Pending != nil {
				if *observed.Pending != e {
					t.Fatal("unknown attempt replaced")
				}
				if _, err := owner.Resume(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else {
				migrateManagedSchedule(t, f, s, e)
			}
			final := testCoordination(t, owner)
			if final.Pending != nil || final.Authority.ScheduleID != s.ExpectedID || final.Authority.Sequence != before.Sequence+1 || final.Authority.Pending != before.Pending {
				t.Fatal("recovery changed accounting")
			}
			if got := migrateManagedSchedule(t, f, s, e); got.Appended {
				t.Fatal("recovery repeated transition")
			}
		})
	}
}

func TestCustodyScheduleRejectsOldAuthorityAgainstAdvancedPins(t *testing.T) {
	f, _ := newManagedCustodyPair(t)
	s, e := managedScheduleFixture(t, f)
	owner := f.serve.archive.f.coordinator
	backup := filepath.Join(t.TempDir(), "old-authority")
	if err := os.CopyFS(backup, os.DirFS(f.serve.archive.f.authorityPath)); err != nil {
		t.Fatal(err)
	}
	migrateManagedSchedule(t, f, s, e)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	stale, err := OpenCoordinator(backup, f.serve.archive.f.pinsPath, f.serve.archive.policy.Assignments[0], f.config.AssignmentID)
	if err == nil {
		stale.Close()
		t.Fatal("old authority adopted advanced migration pins")
	}
}
