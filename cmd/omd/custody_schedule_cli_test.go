package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestCustodyScheduleCLIPrepareSignApplyAndLiveQUIC(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	s := f.audit.serve
	root := t.TempDir()
	before := f.snapshot(t)
	original := f.config.Audit.Manifest
	statement, err := original.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	oldID, _ := statement.ID()
	if oldID != f.config.Assignment.StatementID {
		t.Fatal("fixture statement mismatch")
	}
	target := original
	target.Version = workarchive.ManifestVersion2
	target.Binding.RadixActivationHeight = target.Anchor.Height + 10
	newStatement, err := target.ArchiveStatement(2, oldID)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(statement workarchive.Statement) workarchive.Checkpoint {
		t.Helper()
		var aa []workarchive.Attestation
		for _, seed := range []byte{51, 52} {
			a, e := workarchive.Attest(pruneCLIKey(seed), statement)
			if e != nil {
				t.Fatal(e)
			}
			aa = append(aa, a)
		}
		cp, e := workarchive.NewCheckpoint(statement, aa)
		if e != nil {
			t.Fatal(e)
		}
		return cp
	}
	cp, newCP := sign(statement), sign(newStatement)
	oldPath, newPath, manifestPath := filepath.Join(root, "original.cp"), filepath.Join(root, "radix.cp"), filepath.Join(root, "radix.manifest")
	b, _ := cp.CanonicalBytes()
	writePruneCLIFile(t, oldPath, b)
	b, _ = newCP.CanonicalBytes()
	writePruneCLIFile(t, newPath, b)
	b, _ = target.CanonicalBytes()
	writePruneCLIFile(t, manifestPath, b)
	proofPath := filepath.Join(root, "schedule.proof")
	commandPath := filepath.Join(root, "migration.command")
	entryPath := filepath.Join(root, "migration.entry")
	authorityKey := filepath.Join(root, "authority.key")
	writePruneCLIFile(t, authorityKey, pruneCLIKey(1).Seed())
	trusted := []string{}
	for _, seed := range []byte{51, 52} {
		key := pruneCLIPublic(seed)
		trusted = append(trusted, hex.EncodeToString(key[:]))
	}
	trusted = []string{"--schedule-attestors", strings.Join(trusted, ",")}
	common := []string{"--assignment", s.assignmentPath, "--assignment-id", f.config.Audit.AssignmentID.String(), "--max-challenge-lifetime-seconds", strconv.FormatUint(f.config.Audit.CustodyPolicy.MaximumChallengeLifetime, 10), "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000"}
	common = append(common, trusted...)
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := runCustodySchedule(t.Context(), append(append([]string{}, common...), args...), &out); err != nil {
			t.Fatal(args, err)
		}
		return out.String()
	}
	prepare := []string{"--mode", "prepare", "--manifest", s.manifestPath, "--checkpoint", oldPath, "--new-manifest", manifestPath, "--new-checkpoint", newPath, "--receipt", s.receiptPath, "--journal", f.config.Serve.JournalPath, "--out", proofPath}
	run(prepare...)
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("prepare changed authority")
	}
	if err := runCustodySchedule(t.Context(), append(append([]string{}, common...), prepare...), &bytes.Buffer{}); err == nil {
		t.Fatal("prepare overwrote immutable proof")
	}
	b, err = os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := workarchive.DecodeCustodyScheduleProof(b)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := proof.ID()
	proofArgs := []string{"--schedule-proof", proofPath, "--schedule-id", id.String()}
	common = append(common, proofArgs...)
	run("--mode", "review")
	run("--mode", "sign", "--expected-sequence", strconv.FormatUint(before.Confirmed.Sequence, 10), "--expected-head", before.Confirmed.HeadID.String(), "--key", s.replicaKey, "--out", commandPath)
	cosignReport := run("--mode", "cosign", "--command", commandPath, "--key", authorityKey, "--out", entryPath)
	b, err = os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.DecodeEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	entryID, _ := entry.ID()
	if !strings.Contains(cosignReport, entryID.String()) {
		t.Fatal("co-signing omitted independently usable entry ID")
	}
	apply := []string{"--mode", "apply", "--authority", f.config.AuthorityPath, "--authority-pins", f.config.AuthorityPinsPath, "--journal", f.config.Serve.JournalPath, "--entry", entryPath, "--entry-id", entryID.String()}
	failedOutput := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runCustodySchedule(t.Context(), append(append([]string{}, common...), apply...), failedOutput); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost apply output not reported", err)
	}
	run(apply...)
	after := f.snapshot(t)
	if after.Authority.ScheduleID != id || after.Authority.Sequence != before.Authority.Sequence+1 || !reflect.DeepEqual(after.Authority.Operations, before.Authority.Operations) {
		t.Fatal("CLI reset original obligations")
	}
	if err := runManagedCustodyPair(t.Context(), f.args(""), nil, &bytes.Buffer{}); err == nil {
		t.Fatal("legacy CLI silently adopted schedule")
	}
	args := append(f.args(""), proofArgs...)
	args = append(args, trusted...)
	opts, err := loadManagedCustodyPairOptions(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := store.OpenManagedCustodyPairRuntime(t.Context(), opts.config)
	if err != nil {
		t.Fatal(err)
	}
	review, err := runtime.Review(t.Context())
	if err != nil {
		runtime.Close()
		t.Fatal(err)
	}
	reviewID, _ := review.ID()
	result, err := runtime.ExchangeQUICReviewed(t.Context(), reviewID, opts.auditorTransport, opts.replicaTransport, libp2ptransport.DefaultConfig())
	if closeErr := runtime.Close(); err != nil || closeErr != nil {
		t.Fatal("migrated QUIC pair", err, closeErr)
	}
	selected := result.Audit.Record.RenewedReceipt
	selectedID, _ := selected.ID()
	wrappedPath := filepath.Join(root, "scheduled.receipt")
	receiptReport := run("--mode", "receipt", "--journal", f.config.Serve.JournalPath, "--selected-receipt-id", selectedID.String(), "--key", s.replicaKey, "--out", wrappedPath)
	b, err = os.ReadFile(wrappedPath)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := workarchive.DecodeScheduledReplicaReceipt(b)
	if err != nil || wrapped.Original != selected || wrapped.ScheduleID != id {
		t.Fatal("receipt wrapper changed original", err)
	}
	var metadata struct {
		ReceiptID   string `json:"original_receipt_id"`
		RetainUntil uint64 `json:"retain_until"`
	}
	if err := json.Unmarshal([]byte(receiptReport), &metadata); err != nil || metadata.ReceiptID != selectedID.String() || metadata.RetainUntil != selected.RetainUntil {
		t.Fatal("receipt report changed selected deadline", err)
	}
	report := run("--mode", "inspect", "--authority", f.config.AuthorityPath, "--authority-pins", f.config.AuthorityPinsPath)
	if !strings.Contains(report, id.String()) {
		t.Fatal("inspection omitted schedule")
	}
	if got := f.snapshot(t); got.Authority.Pending != before.Authority.Pending {
		t.Fatal("migration implicitly released pending work")
	}
}

func TestCustodyScheduleReportCancelsBlockedNativeOutput(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native pipe adoption is macOS/Linux")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := writer.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("x"), 1<<20)); !os.IsTimeout(err) {
		t.Fatal("pipe did not fill", err)
	}
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- writeCustodyScheduleReport(ctx, writer, []byte(`{"mode":"apply"}`)) }()
	select {
	case err := <-done:
		t.Fatal("full output unexpectedly returned", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked output ignored cancellation")
	}
}
