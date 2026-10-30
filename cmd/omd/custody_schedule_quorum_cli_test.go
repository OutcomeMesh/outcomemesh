package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestCustodyScheduleQuorumCLIOriginalOwnersAndStrictInputs(t *testing.T) {
	f := newPruneEffectCLIFixture(t, false)
	p := f.inventory.Policy
	original, err := loadArchiveManifest(f.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	next := original
	next.Version = workarchive.ManifestVersion2
	next.Binding.RadixActivationHeight = next.Anchor.Height + 10
	oldID, _ := p.Checkpoint.Statement.ID()
	statement, err := next.ArchiveStatement(2, oldID)
	if err != nil {
		t.Fatal(err)
	}
	var attest []workarchive.Attestation
	for _, seed := range []byte{51, 52} {
		v, err := workarchive.Attest(pruneCLIKey(seed), statement)
		if err != nil {
			t.Fatal(err)
		}
		attest = append(attest, v)
	}
	cp, err := workarchive.NewCheckpoint(statement, attest)
	if err != nil {
		t.Fatal(err)
	}
	cpID, _ := statement.ID()
	cpPath := filepath.Join(t.TempDir(), "target.cp")
	raw, _ := cp.CanonicalBytes()
	writePruneCLIFile(t, cpPath, raw)
	target, _ := next.CanonicalBytes()
	originalBytes, _ := original.CanonicalBytes()
	var sources []custodyScheduleQuorumSource
	for i, a := range p.Assignments {
		id, _ := a.ID()
		receipt := f.inventory.Availability.Receipts[i]
		custody := workarchive.CustodyPolicy{TrustedAuditors: a.Auditors, MaximumChallengeLifetime: 60, MaximumProofAge: 100, MaximumRenewalTerm: 20000}
		journalPath := filepath.Join(t.TempDir(), "journal")
		if _, _, err := workarchive.OpenOrCreateCustodyJournal(journalPath, original, receipt, custody); err != nil {
			t.Fatal(err)
		}
		proof := workarchive.CustodyScheduleProof{AssignmentID: id, OriginalManifest: originalBytes, TargetManifest: target, OriginalCheckpoint: p.Checkpoint, TargetCheckpoint: cp, InitialReceipt: receipt, SelectedReceipt: receipt}
		scopeID, _ := proof.ID()
		scope := store.CustodyScheduleContext{Proof: proof, Policy: p.CheckpointPolicy, ExpectedID: scopeID}
		roots := f.config.Authorities[i]
		owner, err := store.OpenCoordinator(roots.AuthorityPath, roots.AuthorityPinsPath, a, id)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := owner.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		seed := byte(61)
		if pruneCLIPublic(seed) != a.ReplicaPublicKey {
			seed = 62
		}
		cmd, err := (custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, AssignmentID: id, ScheduleID: scopeID, ExpectedSequence: snapshot.Confirmed.Sequence, ExpectedHead: snapshot.Confirmed.HeadID, Kind: custodyauthority.MigrateSchedule}).Sign(pruneCLIKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(cmd, pruneCLIKey(1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.MigrateCustodySchedule(t.Context(), entry, scope, journalPath, custody, workarchive.DefaultCustodyJournalLimits()); err != nil {
			t.Fatal(err)
		}
		owner.Close()
		lineage := workarchive.CustodyReceiptLineage{AssignmentID: id, Manifest: originalBytes, InitialReceipt: receipt, Policy: custody}
		wrapped, err := workarchive.CreateScheduledReplicaReceipt(t.Context(), proof, a, p.CheckpointPolicy, lineage, receipt, pruneCLIKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		rid, _ := wrapped.ID()
		root := t.TempDir()
		source := custodyScheduleQuorumSource{Assignment: filepath.Join(root, "assignment"), AssignmentID: id.String(), Authority: roots.AuthorityPath, Pins: roots.AuthorityPinsPath, Journal: journalPath, Proof: filepath.Join(root, "proof"), ScheduleID: scopeID.String(), Receipt: filepath.Join(root, "receipt"), ReceiptID: rid.String()}
		raw, _ := a.CanonicalBytes()
		writePruneCLIFile(t, source.Assignment, raw)
		raw, _ = proof.CanonicalBytes()
		writePruneCLIFile(t, source.Proof, raw)
		raw, _ = wrapped.CanonicalBytes()
		writePruneCLIFile(t, source.Receipt, raw)
		sources = append(sources, source)
	}
	sourcePath := filepath.Join(t.TempDir(), "sources.json")
	raw, _ = json.Marshal(sources)
	writePruneCLIFile(t, sourcePath, raw)
	formatKeys := func(keys [][32]byte) string {
		var out []string
		for _, k := range keys {
			out = append(out, hex.EncodeToString(k[:]))
		}
		return strings.Join(out, ",")
	}
	args := []string{"--sources", sourcePath, "--checkpoint", cpPath, "--checkpoint-id", cpID.String(), "--attestors", formatKeys(p.CheckpointPolicy.TrustedAttestors), "--replicas", formatKeys(p.ReplicaPolicy.TrustedReplicas), "--max-receipt-age-seconds", "1000", "--min-remaining-term-seconds", "100", "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000"}
	now := func() uint64 { return f.inventory.Request.Boundary.VerifiedAt }
	before := f.snapshot(t)
	var out bytes.Buffer
	if err := runCustodyScheduleQuorum(t.Context(), args, &out, now); err != nil {
		t.Fatal(err)
	}
	var report struct {
		BundleID string                                  `json:"bundle_id"`
		Verified int                                     `json:"verified_replicas"`
		Bundle   workarchive.ScheduledAvailabilityBundle `json:"bundle"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Verified != 2 {
		t.Fatal("quorum report", err)
	}
	id, err := report.Bundle.ID()
	if err != nil || report.BundleID != id.String() {
		t.Fatal("unbound report", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("inspection changed original accounting")
	}
	failed := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runCustodyScheduleQuorum(t.Context(), args, failed, now); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost output hidden", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("lost output leaked owner or changed accounting")
	}
	for _, bad := range [][]byte{[]byte(`null`), []byte(`[]`), append(bytes.Clone(raw), []byte(` {}`)...), bytes.Replace(raw, []byte(`"assignment":`), []byte(`"unknown":`), 1), bytes.Replace(raw, []byte(`"assignment_id":`), []byte(`"assignment_id":"bad","assignment_id":`), 1), bytes.Replace(raw, []byte(sources[0].ScheduleID), []byte((types.Hash{99}).String()), 1)} {
		writePruneCLIFile(t, sourcePath, bad)
		if err := runCustodyScheduleQuorum(t.Context(), args, io.Discard, now); err == nil {
			t.Fatal("accepted malformed or substituted sources")
		}
	}
}
