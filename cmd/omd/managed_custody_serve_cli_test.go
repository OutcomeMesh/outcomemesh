package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagedCustodyServeCLIReviewClosesBeforeOutput(t *testing.T) {
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	journalBefore, err := f.journal.State()
	if err != nil {
		t.Fatal(err)
	}
	tree := pruneLineageTree(t, f.root)
	var output bytes.Buffer
	writer := pruneEffectTestWriter(func(encoded []byte) (int, error) {
		if !reflect.DeepEqual(before, f.snapshot(t)) {
			t.Error("review retained its owner or changed authority behind output")
		}
		return output.Write(encoded)
	})
	if err := runManagedCustodyServe(t.Context(), f.args(""), nil, writer); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	fields := pruneCLIFields(strings.SplitN(text, "\n", 2)[0])
	ticketID, _ := f.config.Session.Admission.ID()
	if !strings.HasPrefix(text, "work_archive_custody_managed_serve_review ") || fields["owners_retained"] != "false" ||
		fields["listener_started"] != "false" || fields["automatic_completion"] != "false" ||
		fields["ticket_id"] != ticketID.String() || fields["challenge_id"] != f.config.Session.ChallengeID.String() ||
		fields["assignment_id"] != f.config.Session.AssignmentID.String() || !strings.HasSuffix(text, "work_archive_custody_managed_serve_scope_end\n") {
		t.Fatal("review changed its scope or claimed an active service", text)
	}
	for _, value := range []string{f.config.AuthorityPath, f.config.AuthorityPinsPath, f.config.Session.JournalPath, f.config.ObjectPath,
		f.config.Assignment.ManifestID.String(), f.config.Assignment.InitialReceiptID.String(), f.config.Assignment.CustodyPolicyID.String()} {
		if !strings.Contains(text, value) {
			t.Fatal("review omitted a configured root/content pin", value)
		}
	}
	if state, err := f.journal.State(); err != nil || state != journalBefore {
		t.Fatal("review changed the journal", state, err)
	}
	assertPruneLineageTree(t, f.root, tree)
}

type managedCustodyCLIControl struct {
	input  *io.PipeWriter
	writes chan string
	done   chan struct{}
	cancel context.CancelFunc
	err    error // read only after done
}

func startManagedCustodyCLI(t testing.TB, f *managedCustodyServeCLIFixture, output io.Writer) *managedCustodyCLIControl {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	s := &managedCustodyCLIControl{input: writer, writes: make(chan string, 2), done: make(chan struct{}), cancel: cancel}
	if output == nil {
		output = pruneEffectTestWriter(func(encoded []byte) (int, error) {
			select {
			case s.writes <- string(encoded):
				return len(encoded), nil
			default:
				return 0, errors.New("test readiness observer did not drain")
			}
		})
	}
	go func() {
		s.err = runManagedCustodyServe(ctx, f.args("serve"), reader, output)
		close(s.done)
	}()
	t.Cleanup(func() { cancel(); _ = writer.Close(); _ = s.wait(t) })
	return s
}

func (s *managedCustodyCLIControl) wait(t testing.TB) error {
	t.Helper()
	select {
	case <-s.done:
		return s.err
	case <-time.After(10 * time.Second):
		t.Fatal("managed custody CLI did not drain and release its owner")
	}
	return nil
}

func (s *managedCustodyCLIControl) ready(t testing.TB) map[string]string {
	t.Helper()
	select {
	case line := <-s.writes:
		fields := pruneCLIFields(line)
		if !strings.HasPrefix(line, "work_archive_custody_managed_serve_ready ") || fields["owners_retained"] != "true" ||
			fields["automatic_completion"] != "false" || fields["listen"] == "" {
			t.Fatal("invalid managed custody readiness", line)
		}
		return fields
	case <-s.done:
		t.Fatal("managed custody CLI ended before readiness", s.err)
	case <-time.After(10 * time.Second):
		t.Fatal("managed custody CLI readiness timed out")
	}
	return nil
}

func TestManagedCustodyServeCLISupervisionRetainsAndReleasesOriginalOwner(t *testing.T) {
	for _, mode := range []string{"close", "eof", "cancel", "malformed", "partial", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedCustodyServeCLIFixture(t)
			before := f.snapshot(t)
			s := startManagedCustodyCLI(t, f, nil)
			s.ready(t)
			f.assertBusy(t)
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
			}
			err := s.wait(t)
			if (err != nil) != (mode == "malformed" || mode == "partial" || mode == "oversized") {
				t.Fatal("unexpected supervision result", mode, err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("server startup/shutdown admitted or completed an operation")
			}
			if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
				t.Fatal("server startup/shutdown signed or journaled a response", state, err)
			}
		})
	}
}

func TestManagedCustodyServeCLIReadinessFailureClosesOwners(t *testing.T) {
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	injected := errors.New("readiness receiver lost")
	s := startManagedCustodyCLI(t, f, pruneEffectTestWriter(func([]byte) (int, error) { return 0, injected }))
	if err := s.wait(t); !errors.Is(err, injected) {
		t.Fatal("readiness failure was lost", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("lost readiness changed the original authority")
	}
}

type managedCustodyCLIBlockedOutput struct {
	entered chan struct{}
	closed  chan struct{}
	write   sync.Once
	close   sync.Once
}

func (w *managedCustodyCLIBlockedOutput) Write([]byte) (int, error) {
	w.write.Do(func() { close(w.entered) })
	<-w.closed
	return 0, io.ErrClosedPipe
}
func (w *managedCustodyCLIBlockedOutput) Close() error {
	w.close.Do(func() { close(w.closed) })
	return nil
}

func TestManagedCustodyServeCLICancellationInterruptsBlockedReadiness(t *testing.T) {
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	output := &managedCustodyCLIBlockedOutput{entered: make(chan struct{}), closed: make(chan struct{})}
	s := startManagedCustodyCLI(t, f, output)
	select {
	case <-output.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("readiness write was not reached")
	}
	f.assertBusy(t)
	s.cancel()
	if err := s.wait(t); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("blocked readiness loss was not retained", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("cancellation released an altered original authority")
	}
}

func TestManagedCustodyServeCLIPublicValidationBeforeSeedReads(t *testing.T) {
	f := newManagedCustodyServeCLIFixture(t)
	if err := os.Remove(f.serverKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.replicaKey); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"mode":             pruneCLISet(f.args(""), "mode", "control"),
		"duplicate":        append(f.args(""), "--assignment-id", f.config.Session.AssignmentID.String()),
		"positionals":      append(f.args(""), "ignored"),
		"unknown":          append(f.args(""), "--unknown", "x"),
		"zero-ticket":      pruneCLISet(f.args(""), "ticket-id", strings.Repeat("0", 64)),
		"different-ticket": pruneCLISet(f.args(""), "ticket-id", pruneCLIHash(122).String()),
		"challenge":        pruneCLISet(f.args(""), "challenge-id", pruneCLIHash(123).String()),
		"assignment":       pruneCLISet(f.args(""), "assignment-id", pruneCLIHash(124).String()),
		"role-peer":        pruneCLISet(f.args(""), "auditor-peer-id", pruneCLIPeer(3).String()),
		"same-peer":        pruneCLISet(f.args(""), "auditor-peer-id", f.config.ServerPeerID.String()),
		"policy-pin":       pruneCLISet(f.args(""), "max-proof-age-seconds", "99"),
		"policy-bound":     pruneCLISet(f.args(""), "max-proof-age-seconds", "0"),
		"timeout-low":      pruneCLISet(f.args(""), "timeout", "99ms"),
		"timeout-high":     pruneCLISet(f.args(""), "timeout", "11m"),
		"object-budget":    pruneCLISet(f.args(""), "max-objects", "0"),
		"journal-budget":   pruneCLISet(f.args(""), "journal-max-paths", "0"),
		"listen-malformed": pruneCLISet(f.args(""), "listen", "invalid"),
		"listen-tcp":       pruneCLISet(f.args(""), "listen", "/ip4/127.0.0.1/tcp/0"),
		"listen-dns":       pruneCLISet(f.args(""), "listen", "/dns4/localhost/udp/0/quic-v1"),
		"overlap":          pruneCLISet(f.args(""), "objects", f.config.AuthorityPath),
		"invalid-utf8":     pruneCLISet(f.args(""), "objects", string([]byte{0xff})),
		"nul-path":         pruneCLISet(f.args(""), "objects", "bad\x00path"),
		"missing-root":     pruneCLISet(f.args(""), "journal", filepath.Join(f.root, "missing-root")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadManagedCustodyServeOptions(t.Context(), args); err == nil || strings.Contains(err.Error(), "read explicit seed file") {
				t.Fatal("invalid public scope reached secret inputs", err)
			}
		})
	}
	if _, err := loadManagedCustodyServeOptions(nil, f.args("")); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadManagedCustodyServeOptions(ctx, f.args("")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestManagedCustodyServeCLIRejectsWrongKeysAndNativeNonPipes(t *testing.T) {
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	wrong := filepath.Join(f.root, "wrong.key")
	writePruneCLIFile(t, wrong, pruneCLIKey(47).Seed())
	for _, flag := range []string{"key", "replica-key"} {
		if _, err := loadManagedCustodyServeOptions(t.Context(), pruneCLISet(f.args(""), flag, wrong)); err == nil {
			t.Fatal("wrong role seed accepted", flag)
		}
	}
	regular, err := os.Open(f.assignmentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if err := runManagedCustodyServe(t.Context(), f.args("serve"), regular, io.Discard); err == nil {
		t.Fatal("native regular input adopted for supervised service")
	}
	output, err := os.Create(filepath.Join(f.root, "regular.out"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	input, writer := io.Pipe()
	defer writer.Close()
	if err := runManagedCustodyServe(t.Context(), f.args("serve"), input, output); err == nil {
		t.Fatal("native regular output adopted for supervised service")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("failed configuration changed its authority")
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("failed configuration signed a response", state, err)
	}
}
