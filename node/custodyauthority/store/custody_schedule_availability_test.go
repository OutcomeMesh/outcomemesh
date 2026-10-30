package store

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func scheduledQuorumFixture(t testing.TB) (*archivePruneFixture, []ScheduledCustodyReplicaSource, workarchive.Checkpoint) {
	t.Helper()
	p := newArchivePruneFixtureWithRenewals(t, []int{1, 2})
	return migratePruneFixtureOwners(t, p)
}

func migratePruneFixtureOwners(t testing.TB, p *archivePruneFixture) (*archivePruneFixture, []ScheduledCustodyReplicaSource, workarchive.Checkpoint) {
	t.Helper()
	next, statement, err := workarchive.PrepareRadixArchiveMigration(p.replicas[0].Directory, p.policy.Checkpoint, p.policy.CheckpointPolicy, p.f.base, p.f.parameters, p.policy.Checkpoint.Statement.Anchor.Height+10, workarchive.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var attest []workarchive.Attestation
	for _, seed := range []byte{51, 52} {
		a, err := workarchive.Attest(testKey(seed), statement)
		if err != nil {
			t.Fatal(err)
		}
		attest = append(attest, a)
	}
	cp, err := workarchive.NewCheckpoint(statement, attest)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := next.CanonicalBytes()
	var sources []ScheduledCustodyReplicaSource
	for i, l := range p.lineages {
		a := p.policy.Assignments[i]
		m, _ := workarchive.DecodeManifest(l.Manifest)
		path := filepath.Join(t.TempDir(), "journal")
		journal, _, err := workarchive.OpenOrCreateCustodyJournal(path, m, l.InitialReceipt, l.Policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, encoded := range l.Entries {
			entry, err := workarchive.DecodeCustodyJournalEntry(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := journal.Append(entry.Record); err != nil {
				t.Fatal(err)
			}
		}
		state, err := journal.State()
		if err != nil {
			t.Fatal(err)
		}
		proof := workarchive.CustodyScheduleProof{AssignmentID: l.AssignmentID, OriginalManifest: l.Manifest, TargetManifest: target, OriginalCheckpoint: p.policy.Checkpoint, TargetCheckpoint: cp, InitialReceipt: l.InitialReceipt, SelectedReceipt: state.CurrentReceipt, JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID}
		id, _ := proof.ID()
		scope := CustodyScheduleContext{Proof: proof, ExpectedID: id, Policy: p.policy.CheckpointPolicy}
		seed := byte(61)
		if testPublic(seed) != a.ReplicaPublicKey {
			seed = 62
		}
		owner := p.operations[i].Coordinator
		pos := testCoordination(t, owner).Confirmed
		cmd, err := (custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, AssignmentID: l.AssignmentID, ScheduleID: id, Kind: custodyauthority.MigrateSchedule, ExpectedSequence: pos.Sequence, ExpectedHead: pos.HeadID}).Sign(testKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(cmd, testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.MigrateCustodySchedule(t.Context(), entry, scope, path, l.Policy, workarchive.DefaultCustodyJournalLimits()); err != nil {
			t.Fatal(err)
		}
		receipt, err := workarchive.CreateScheduledReplicaReceipt(t.Context(), proof, a, scope.Policy, l, state.CurrentReceipt, testKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		rid, _ := receipt.ID()
		sources = append(sources, ScheduledCustodyReplicaSource{AuthorityPath: owner.authority.path, AuthorityPinsPath: owner.journal.path, JournalPath: path, Assignment: a, AssignmentID: l.AssignmentID, Schedule: scope, Receipt: receipt, ReceiptID: rid, CustodyPolicy: l.Policy, JournalLimits: workarchive.DefaultCustodyJournalLimits()})
		owner.Close()
	}
	return p, sources, cp
}

func TestCustodyScheduleQuorumInspectsOriginalOwnersWithoutChangingAccounting(t *testing.T) {
	p, sources, cp := scheduledQuorumFixture(t)
	inspect := func(sources []ScheduledCustodyReplicaSource, now func() uint64) error {
		_, err := InspectScheduledCustodyQuorum(t.Context(), sources, cp, p.policy.CheckpointPolicy, p.policy.ReplicaPolicy, now)
		return err
	}
	now := p.f.request.Boundary.VerifiedAt
	snapshot := func(s ScheduledCustodyReplicaSource) Coordination {
		owner, err := OpenCoordinator(s.AuthorityPath, s.AuthorityPinsPath, s.Assignment, s.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close()
		return testCoordination(t, owner)
	}
	before := []Coordination{snapshot(sources[0]), snapshot(sources[1])}
	if err := inspect(sources, func() uint64 { return now }); err != nil {
		t.Fatal(err)
	}
	for i, s := range sources {
		if !reflect.DeepEqual(before[i], snapshot(s)) {
			t.Fatal("quorum changed pending or spent accounting")
		}
	}
	for _, kind := range []string{"scope", "receipt-id", "old-journal", "shared-root", "unaccepted-schedule", "expired-during-replay", "unconfirmed"} {
		t.Run(kind, func(t *testing.T) {
			changed := append([]ScheduledCustodyReplicaSource(nil), sources...)
			clock := func() uint64 { return now }
			switch kind {
			case "scope":
				changed[0].Schedule.ExpectedID = types.Hash{209}
			case "receipt-id":
				changed[0].ReceiptID = types.Hash{208}
			case "old-journal":
				l := p.lineages[0]
				m, _ := workarchive.DecodeManifest(l.Manifest)
				changed[0].JournalPath = filepath.Join(t.TempDir(), "old")
				if _, _, err := workarchive.OpenOrCreateCustodyJournal(changed[0].JournalPath, m, l.InitialReceipt, l.Policy); err != nil {
					t.Fatal(err)
				}
			case "shared-root":
				changed[1].JournalPath = changed[0].JournalPath
			case "unaccepted-schedule":
				s := &changed[0]
				proof := s.Schedule.Proof
				proof.JournalSequence = 0
				proof.JournalHeadID = types.Hash{}
				proof.SelectedReceipt = proof.InitialReceipt
				id, err := proof.ID()
				if err != nil {
					t.Fatal(err)
				}
				s.Schedule.Proof = proof
				s.Schedule.ExpectedID = id
				seed := byte(61)
				if testPublic(seed) != s.Assignment.ReplicaPublicKey {
					seed = 62
				}
				s.Receipt, err = workarchive.CreateScheduledReplicaReceipt(t.Context(), proof, s.Assignment, s.Schedule.Policy, p.lineages[0], s.Receipt.Original, testKey(seed))
				if err != nil {
					t.Fatal(err)
				}
				s.ReceiptID, _ = s.Receipt.ID()
			case "expired-during-replay":
				calls := 0
				clock = func() uint64 {
					calls++
					if calls == 1 {
						return now
					}
					return sources[0].Receipt.Original.RetainUntil + 1
				}
			case "unconfirmed":
				s := changed[0]
				owner, err := OpenCoordinator(s.AuthorityPath, s.AuthorityPinsPath, s.Assignment, s.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				snap := testCoordination(t, owner).Authority
				cmd, err := (custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, AssignmentID: s.AssignmentID, ScheduleID: s.Schedule.ExpectedID, ExpectedSequence: snap.Sequence, ExpectedHead: snap.HeadID, Kind: custodyauthority.Stop, EvidenceID: testHash(210)}).Sign(testKey(1))
				if err != nil {
					t.Fatal(err)
				}
				entry, err := custodyauthority.SignEntry(cmd, testKey(1))
				if err != nil {
					t.Fatal(err)
				}
				if err := owner.journal.prepare(t.Context(), entry); err != nil {
					t.Fatal(err)
				}
				owner.Close()
			}
			if err := inspect(changed, clock); err == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}
