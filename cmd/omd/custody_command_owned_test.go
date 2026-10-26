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
	"testing"
	"time"

	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func custodyCommandExistingApplyArgs(f *managedCustodyAuditCLIFixture) []string {
	id, _ := f.config.Audit.Admission.ID()
	args := append([]string{custodyCommandApplyCommand}, custodyCommandCLICommonArgs(f)...)
	return append(args, "--purpose", "audit", "--entry", f.admissionPath, "--entry-id", id.String(), "--authority", f.config.AuthorityPath, "--authority-pins", f.config.AuthorityPinsPath, "--journal", f.config.Audit.JournalPath)
}

func startCustodyCommandControl(t testing.TB, args []string, output io.Writer) *managedCustodyCLIControl {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	s := &managedCustodyCLIControl{input: writer, writes: make(chan string, 4), done: make(chan struct{}), cancel: cancel}
	if output == nil {
		output = pruneEffectTestWriter(func(b []byte) (int, error) {
			select {
			case s.writes <- string(b):
				return len(b), nil
			default:
				return 0, errors.New("custody observer not drained")
			}
		})
	}
	go func() {
		s.err = runCustodyCommand(ctx, append(append([]string{}, args...), "--mode", "control"), reader, output)
		close(s.done)
	}()
	t.Cleanup(func() { cancel(); _ = writer.Close(); _ = s.wait(t) })
	return s
}

func custodyCommandControlLine(t testing.TB, s *managedCustodyCLIControl, prefix string) map[string]string {
	t.Helper()
	select {
	case line := <-s.writes:
		if !strings.HasPrefix(line, prefix+" ") {
			t.Fatal("unexpected custody output", line)
		}
		return pruneCLIFields(strings.SplitN(line, "\n", 2)[0])
	case <-s.done:
		t.Fatal("custody control ended before output", s.err)
	case <-time.After(10 * time.Second):
		t.Fatal("custody output timeout")
	}
	return nil
}

func custodyCommandControlReview(t testing.TB, s *managedCustodyCLIControl) string {
	t.Helper()
	if _, err := io.WriteString(s.input, "review\n"); err != nil {
		t.Fatal(err)
	}
	fields := custodyCommandControlLine(t, s, "work_archive_custody_command_review")
	if fields["owners_retained"] != "true" || fields["review_id"] == "" {
		t.Fatal(fields)
	}
	return fields["review_id"]
}

func TestCustodyCommandOwnedReviewClosesBeforeOutputAndApplyIsExplicit(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	args := custodyCommandExistingApplyArgs(f)
	var report bytes.Buffer
	w := pruneEffectTestWriter(func(b []byte) (int, error) {
		if !reflect.DeepEqual(before, f.snapshot(t)) {
			t.Error("review retained or changed authority")
		}
		return report.Write(b)
	})
	if err := runCustodyCommand(t.Context(), args, nil, w); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.String(), "owners_retained=false") || !strings.HasSuffix(report.String(), "work_archive_custody_command_scope_end\n") {
		t.Fatal(report.String())
	}
	s := startCustodyCommandControl(t, args, nil)
	custodyCommandControlLine(t, s, "work_archive_custody_command_ready")
	f.assertBusy(t)
	id := custodyCommandControlReview(t, s)
	if _, err := io.WriteString(s.input, "apply "+id+"\n"); err != nil {
		t.Fatal(err)
	}
	fields := custodyCommandControlLine(t, s, "work_archive_custody_command_result")
	if fields["action"] != "apply" || fields["execution_started"] != "false" {
		t.Fatal(fields)
	}
	// An exact historical retry cannot turn this token into a second action.
	_, _ = io.WriteString(s.input, "apply "+id+"\n")
	if err := s.wait(t); err == nil {
		t.Fatal("reused reported token accepted")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("historical exact entry re-appended")
	}
}

func TestCustodyCommandOwnedControlRejectsUnreportedAndPartialInput(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	args := custodyCommandExistingApplyArgs(f)
	for _, mode := range []string{"unreported", "partial", "eof", "close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			s := startCustodyCommandControl(t, args, nil)
			custodyCommandControlLine(t, s, "work_archive_custody_command_ready")
			switch mode {
			case "unreported":
				_, _ = io.WriteString(s.input, "apply "+pruneCLIHash(99).String()+"\n")
			case "partial":
				_, _ = io.WriteString(s.input, "close")
				_ = s.input.Close()
			case "eof":
				_ = s.input.Close()
			case "close":
				_, _ = io.WriteString(s.input, "close\n")
			case "cancel":
				s.cancel()
			}
			err := s.wait(t)
			if (mode == "eof" || mode == "close") != (err == nil) {
				t.Fatal(mode, err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("control failure changed authority")
			}
		})
	}
}

func TestCustodyCommandTerminalCaptureIsReviewedAndPinnedToSelectedHead(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	r, err := authoritystore.OpenManagedCustodyPairRuntime(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	review, err := r.Review(t.Context())
	if err != nil {
		_ = r.Close()
		t.Fatal(err)
	}
	id, err := review.ID()
	if err != nil {
		_ = r.Close()
		t.Fatal(err)
	}
	_, err = r.ExchangeQUICReviewed(t.Context(), id, pruneCLIKey(46), pruneCLIKey(45), libp2ptransport.DefaultConfig())
	if closeErr := r.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	before := f.snapshot(t)
	for _, purpose := range []string{"audit", "serve"} {
		t.Run(purpose, func(t *testing.T) {
			admission, path, journal := f.config.Audit.Admission, f.audit.admissionPath, f.config.Audit.JournalPath
			if purpose == "serve" {
				admission, path, journal = f.config.Serve.Admission, f.audit.serve.admissionPath, f.config.Serve.JournalPath
			}
			admissionID, _ := admission.ID()
			args := append([]string{custodyTerminalCommand}, custodyCommandCLICommonArgs(f.audit)...)
			args = append(args, "--purpose", purpose, "--admission", path, "--admission-id", admissionID.String(), "--authority", f.config.AuthorityPath, "--authority-pins", f.config.AuthorityPinsPath, "--journal", journal)
			var report bytes.Buffer
			if err := runCustodyCommand(t.Context(), args, nil, &report); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "terminal.omct")
			if err := runCustodyCommand(t.Context(), append(append([]string{}, args...), "--out", out), nil, io.Discard); err == nil {
				t.Fatal("default review accepted output")
			}
			s := startCustodyCommandControl(t, append(args, "--out", out), nil)
			custodyCommandControlLine(t, s, "work_archive_custody_command_ready")
			f.assertBusy(t)
			reviewID := custodyCommandControlReview(t, s)
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("review published terminal", err)
			}
			_, _ = io.WriteString(s.input, "capture "+reviewID+"\n")
			fields := custodyCommandControlLine(t, s, "work_archive_custody_command_result")
			if fields["completion_submitted"] != "false" || fields["terminal_id"] == "" {
				t.Fatal(fields)
			}
			_, _ = io.WriteString(s.input, "close\n")
			if err := s.wait(t); err != nil {
				t.Fatal(err)
			}
			tid, err := managedCustodyExternalID("terminal-id", fields["terminal_id"])
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := authoritystore.LoadCustodyTerminalFile(out, tid)
			if err != nil {
				t.Fatal(err)
			}
			if terminal.Admission != admission || terminal.Entry.Sequence != 1 {
				t.Fatal("captured a different admission/head")
			}
		})
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("capture completed authority")
	}
}
