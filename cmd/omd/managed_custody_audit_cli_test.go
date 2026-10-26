package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func startManagedAuditCLI(t testing.TB, f *managedCustodyAuditCLIFixture, args []string, output io.Writer) *managedCustodyCLIControl {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	s := &managedCustodyCLIControl{input: writer, writes: make(chan string, 8), done: make(chan struct{}), cancel: cancel}
	if output == nil {
		output = pruneEffectTestWriter(func(b []byte) (int, error) {
			select {
			case s.writes <- string(b):
				return len(b), nil
			default:
				return 0, errors.New("audit observer not drained")
			}
		})
	}
	if args == nil {
		args = f.args("control")
	}
	go func() { s.err = runManagedCustodyAudit(ctx, args, reader, output); close(s.done) }()
	t.Cleanup(func() { cancel(); _ = writer.Close(); _ = s.wait(t) })
	return s
}

func managedAuditLine(t testing.TB, s *managedCustodyCLIControl, prefix string) map[string]string {
	t.Helper()
	select {
	case line := <-s.writes:
		if !strings.HasPrefix(line, prefix+" ") {
			t.Fatal("unexpected audit output", line)
		}
		return pruneCLIFields(strings.SplitN(line, "\n", 2)[0])
	case <-s.done:
		t.Fatal("audit ended before output", s.err)
	case <-time.After(10 * time.Second):
		t.Fatal("audit output timeout")
	}
	return nil
}

func managedAuditReview(t testing.TB, s *managedCustodyCLIControl) string {
	t.Helper()
	if _, err := io.WriteString(s.input, "review\n"); err != nil {
		t.Fatal(err)
	}
	fields := managedAuditLine(t, s, "work_archive_custody_managed_audit_review")
	if fields["owners_retained"] != "true" || fields["review_id"] == "" {
		t.Fatal(fields)
	}
	return fields["review_id"]
}

func TestManagedCustodyAuditCLIReviewIsReadOnlyAndReleasesBeforeOutput(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	artifacts := prunePrepareTree(t, f.config.Audit.ArtifactsPath)
	journal := prunePrepareTree(t, f.config.Audit.JournalPath)
	var output bytes.Buffer
	write := pruneEffectTestWriter(func(b []byte) (int, error) {
		if !reflect.DeepEqual(before, f.snapshot(t)) {
			t.Error("review retained/advanced original owner")
		}
		return output.Write(b)
	})
	if err := runManagedCustodyAudit(t.Context(), f.args(""), nil, write); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	fields := pruneCLIFields(strings.SplitN(text, "\n", 2)[0])
	if !strings.HasPrefix(text, "work_archive_custody_managed_audit_review ") || fields["owners_retained"] != "false" || fields["execution_authorized"] != "false" || fields["review_id"] == "" || !strings.HasSuffix(text, "work_archive_custody_managed_audit_scope_end\n") {
		t.Fatal(text)
	}
	for _, secret := range []string{f.intent.Nonce.String(), hex.EncodeToString(pruneCLIKey(3).Seed()), hex.EncodeToString(pruneCLIKey(46).Seed()), "AuditorPrivateKey"} {
		if strings.Contains(text, secret) {
			t.Fatal("review exposed nonce or private key")
		}
	}
	if !reflect.DeepEqual(artifacts, prunePrepareTree(t, f.config.Audit.ArtifactsPath)) || !reflect.DeepEqual(journal, prunePrepareTree(t, f.config.Audit.JournalPath)) {
		t.Fatal("review published/repaired evidence")
	}
}

func TestManagedCustodyAuditCLIPrepareRequiresReportedTokenAndCannotReuseIt(t *testing.T) {
	for _, mode := range []string{"unreported", "reported"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedCustodyAuditCLIFixture(t)
			before := f.snapshot(t)
			s := startManagedAuditCLI(t, f, nil, nil)
			managedAuditLine(t, s, "work_archive_custody_managed_audit_ready")
			f.assertBusy(t)
			id := pruneCLIHash(77).String()
			if mode == "reported" {
				id = managedAuditReview(t, s)
			}
			_, _ = io.WriteString(s.input, "prepare "+id+"\n")
			if mode == "reported" {
				prepared := managedAuditLine(t, s, "work_archive_custody_managed_audit_prepared")
				expected, _ := f.serve.challenge.ID()
				if prepared["challenge_id"] != expected.String() || prepared["completion_submitted"] != "false" {
					t.Fatal(prepared)
				}
				f.assertBusy(t)
				_, _ = io.WriteString(s.input, "prepare "+id+"\n")
			}
			if err := s.wait(t); err == nil {
				t.Fatal("unreported/reused token accepted")
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("prepare completed authority")
			}
			_, err := os.Stat(filepath.Join(f.config.Audit.ArtifactsPath, "cycle-00000000000000000001", "challenge.omcc"))
			if (err == nil) != (mode == "reported") {
				t.Fatal("unreported action published challenge", err)
			}
		})
	}
}

func TestManagedCustodyAuditCLIControlsAndBrokenOutput(t *testing.T) {
	for _, mode := range []string{"close", "eof", "cancel", "malformed", "partial", "oversized", "recover-absent"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedCustodyAuditCLIFixture(t)
			before := f.snapshot(t)
			s := startManagedAuditCLI(t, f, nil, nil)
			managedAuditLine(t, s, "work_archive_custody_managed_audit_ready")
			switch mode {
			case "close":
				_, _ = io.WriteString(s.input, "close\n")
			case "eof":
				_ = s.input.Close()
			case "cancel":
				s.cancel()
			case "malformed":
				_, _ = io.WriteString(s.input, "complete\n")
			case "partial":
				_, _ = io.WriteString(s.input, "close")
				_ = s.input.Close()
			case "oversized":
				_, _ = io.WriteString(s.input, strings.Repeat("x", maximumPruneControlLine+1)+"\n")
			case "recover-absent":
				id := managedAuditReview(t, s)
				_, _ = io.WriteString(s.input, "recover "+id+"\n")
			}
			err := s.wait(t)
			wantErr := mode == "malformed" || mode == "partial" || mode == "oversized" || mode == "recover-absent" || mode == "cancel"
			if (err != nil) != wantErr {
				t.Fatal(mode, err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("supervision advanced authority")
			}
		})
	}
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	injected := errors.New("lost audit readiness")
	s := startManagedAuditCLI(t, f, nil, pruneEffectTestWriter(func([]byte) (int, error) { return 0, injected }))
	if err := s.wait(t); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("broken readiness changed authority")
	}
}

func TestManagedCustodyAuditCLIQUICAndExplicitRecovery(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	server, err := libp2ptransport.New(ctx, pruneCLIKey(45), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	objects, err := workarchive.OpenExistingObjectStore(f.serve.config.ObjectPath, f.serve.config.ObjectPolicy)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := workarchive.NewJournalCustodyReplicaSession(f.serve.journal, objects, f.serve.config.Session.ReplicaPrivateKey, f.serve.config.Session.SessionConfig)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	if err := server.SetArchiveCustodyHandler([]types.Hash{f.config.AuditorPeerID}, func(ctx context.Context, _ types.Hash, stream network.Stream) {
		_, err := replica.Serve(ctx, stream)
		served <- err
	}); err != nil {
		t.Fatal(err)
	}
	args := append(f.args("control"), "--peer", server.Addresses()[0], "--transport-key", f.transportKey)
	s := startManagedAuditCLI(t, f, args, nil)
	managedAuditLine(t, s, "work_archive_custody_managed_audit_ready")
	id := managedAuditReview(t, s)
	_, _ = io.WriteString(s.input, "prepare "+id+"\n")
	managedAuditLine(t, s, "work_archive_custody_managed_audit_prepared")
	id = managedAuditReview(t, s)
	_, _ = io.WriteString(s.input, "audit "+id+"\n")
	result := managedAuditLine(t, s, "work_archive_custody_managed_audit_result")
	if result["sequence"] != "1" || result["action"] != "audit" || result["recovered"] != "false" || result["completion_submitted"] != "false" {
		t.Fatal(result)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("raw remote replica did not drain")
	}
	id = managedAuditReview(t, s)
	_, _ = io.WriteString(s.input, "recover "+id+"\n")
	recovered := managedAuditLine(t, s, "work_archive_custody_managed_audit_result")
	if recovered["recovered"] != "true" || recovered["proof_id"] != result["proof_id"] || recovered["receipt_id"] != result["receipt_id"] {
		t.Fatal("recovery changed exact result", recovered, result)
	}
	_, _ = io.WriteString(s.input, "close\n")
	if err := s.wait(t); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("audit/recovery completed authority")
	}
}

func TestManagedCustodyAuditCLIRejectsScopeBeforeSeeds(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	base := f.args("")
	// Missing seed proves these failures do not get as far as secret loading.
	if err := os.Remove(f.auditorKey); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"mode": replacePruneEffectConfigArg(base, "--mode", "audit"), "ticket": replacePruneEffectConfigArg(base, "--ticket-id", pruneCLIHash(122).String()), "intent": replacePruneEffectConfigArg(base, "--intent-id", pruneCLIHash(122).String()),
		"upper": replacePruneEffectConfigArg(base, "--assignment-id", strings.ToUpper(f.config.Audit.AssignmentID.String())), "peer-role": replacePruneEffectConfigArg(base, "--auditor-peer-id", f.intent.ReplicaPeerID.String()),
		"policy": replacePruneEffectConfigArg(base, "--max-proof-age-seconds", "101"), "missing-root": replacePruneEffectConfigArg(base, "--artifacts", filepath.Join(t.TempDir(), "missing")), "duplicate": append(append([]string(nil), base...), "--intent-id", f.config.Audit.IntentID.String()),
		"route-no-key": append(append([]string(nil), base...), "--peer", "/ip4/127.0.0.1/udp/1/quic-v1"), "bad-listen": append(append([]string(nil), base...), "--listen", "/dns4/test/udp/1/quic-v1"), "invalid-utf8": replacePruneEffectConfigArg(base, "--journal", string([]byte{0xff})),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadManagedCustodyAuditOptions(t.Context(), args)
			if err == nil || strings.Contains(err.Error(), "read explicit seed") {
				t.Fatal("invalid scope accepted or seed read first", err)
			}
		})
	}
}
