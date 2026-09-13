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

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func (f *pruneCLIFixture) maintenanceArgs() []string {
	args := []string{pruneMaintenanceCommand}
	serve := f.serveArgs()
	for i := 1; i+1 < len(serve); i += 2 {
		if serve[i] != "--key" && serve[i] != "--timeout" {
			args = append(args, serve[i:i+2]...)
		}
	}
	return args
}

func admitPruneMaintenanceFixture(t testing.TB, f *pruneCLIFixture) {
	t.Helper()
	address, stop := startPruneCLI(t, f)
	runPruneCLIDelivery(t, f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address))
	stop()
}

func runPruneMaintenanceFields(t testing.TB, args []string) map[string]string {
	t.Helper()
	var output bytes.Buffer
	if err := runPruneOffline(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(output.String())
	if fields["historical_only"] != "true" || fields["execution_authorized"] != "false" {
		t.Fatal("maintenance overclaimed authority", output.String())
	}
	return fields
}

func checkPruneCancellationOutput(t testing.TB, f *pruneCLIFixture, fields map[string]string) []byte {
	t.Helper()
	encoded, err := hex.DecodeString(fields["canonical_hex"])
	if err != nil {
		t.Fatal(err)
	}
	cancellation, err := authoritystore.DecodePruneCancellation(encoded)
	if err != nil {
		t.Fatal(err)
	}
	id, err := cancellation.ID()
	ticket, _ := f.admission.ID()
	if err != nil || id.String() != fields["terminal_id"] || cancellation.AssignmentID != f.config.AssignmentID ||
		cancellation.RequestID != f.config.RequestID || cancellation.TicketID != ticket || fields["completion_submitted"] != "false" || fields["automatic_retry"] != "false" {
		t.Fatal("invalid historical cancellation", fields)
	}
	return encoded
}

func TestPruneMaintenanceCLIOfflineReviewCancelAndRetry(t *testing.T) {
	f := newPruneCLIFixture(t)
	before, authority := f.snapshot(t)
	prepared := runPruneMaintenanceFields(t, f.maintenanceArgs())
	if prepared["network_stopped"] != "true" || prepared["automatic_resume"] != "false" {
		t.Fatal("invalid offline review", prepared)
	}
	after, observed := f.snapshot(t)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(authority, observed) {
		t.Fatal("review changed history")
	}
	args := append(f.maintenanceArgs(), "--mode", "cancel", "--expected-review-id", prepared["review_id"])
	if err := runPruneOffline(t.Context(), args, io.Discard); !errors.Is(err, authoritystore.ErrPruneStage) {
		t.Fatal("prepared executor was cancelled", err)
	}
	admitPruneMaintenanceFixture(t, f)
	review := runPruneMaintenanceFields(t, f.maintenanceArgs())
	if review["review_id"] == prepared["review_id"] {
		t.Fatal("admission did not change review")
	}
	if err := runPruneOffline(t.Context(), args, io.Discard); !errors.Is(err, authoritystore.ErrPruneMaintenanceReview) {
		t.Fatal("stale prepared review accepted", err)
	}
	args = pruneCLISet(args, "expected-review-id", review["review_id"])
	cancelled := runPruneMaintenanceFields(t, args)
	checkPruneCancellationOutput(t, f, cancelled)
	after, observed = f.snapshot(t)
	if after.Stage != authoritystore.PruneCancelled || observed.Authority.Sequence != 1 || observed.Authority.Pending != 1 {
		t.Fatal("cancel completed the ticket or failed to confirm")
	}
	if err := runPruneOffline(t.Context(), args, io.Discard); !errors.Is(err, authoritystore.ErrPruneMaintenanceReview) {
		t.Fatal("old review was automatically refreshed", err)
	}
	review = runPruneMaintenanceFields(t, f.maintenanceArgs())
	retried := runPruneMaintenanceFields(t, pruneCLISet(args, "expected-review-id", review["review_id"]))
	if !bytes.Equal(checkPruneCancellationOutput(t, f, retried), checkPruneCancellationOutput(t, f, cancelled)) {
		t.Fatal("historical retry replaced cancellation")
	}
}

func TestPruneMaintenanceCLIRejectsFlagsAndPins(t *testing.T) {
	f := newPruneCLIFixture(t)
	args := f.maintenanceArgs()
	before, authority := f.snapshot(t)
	var cases [][]string
	for i := 1; i+1 < len(args); i += 2 {
		cases = append(cases, append(append([]string(nil), args[:i]...), args[i+2:]...))
	}
	for _, extra := range [][]string{{"--assignment-id", f.config.AssignmentID.String()}, {"--mode", "cancel"},
		{"--mode", "execute"}, {"--expected-review-id", ""}, {"--resume", "true"}, {"--force", "true"},
		{"--key", f.serverKey}, {"--listen", "unused"}, {"--maintenance-control", "stdin"}, {"trailing"}} {
		cases = append(cases, append(append([]string(nil), args...), extra...))
	}
	for _, change := range []struct{ name, value string }{{"assignment-id", pruneCLIHash(99).String()},
		{"request-id", pruneCLIHash(99).String()}, {"server-peer-id", f.config.ClientPeerID.String()},
		{"client-peer-id", pruneCLIPeer(1).String()}, {"authority", f.config.ExecutorPinsPath},
		{"executor", filepath.Join(f.root, "missing-executor")}, {"authority-pins", filepath.Join(f.root, "missing-pins")}} {
		cases = append(cases, pruneCLISet(args, change.name, change.value))
	}
	for _, args := range cases {
		var output bytes.Buffer
		if err := runPruneOffline(t.Context(), args, &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid maintenance request accepted", args, err)
		}
	}
	after, observed := f.snapshot(t)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(authority, observed) {
		t.Fatal("rejected command changed history")
	}
	for _, name := range []string{"missing-executor", "missing-pins"} {
		if _, err := os.Lstat(filepath.Join(f.root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing root was initialized")
		}
	}
	if err := run([]string{pruneMaintenanceCommand}); err == nil || strings.Contains(err.Error(), "unknown command") {
		t.Fatal("maintenance command not wired", err)
	}
}

type pruneShortWriter struct{}

func (pruneShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestPruneMaintenanceCLIOutputFailureRetainsCancellation(t *testing.T) {
	for _, kind := range []string{"failed", "short"} {
		t.Run(kind, func(t *testing.T) {
			f := newPruneCLIFixture(t)
			admitPruneMaintenanceFixture(t, f)
			fault := errors.New("stdout unavailable")
			var output io.Writer = pruneFailWriter{fault}
			if kind == "short" {
				output, fault = pruneShortWriter{}, io.ErrShortWrite
			}
			if err := runPruneOffline(t.Context(), f.maintenanceArgs(), output); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			review := runPruneMaintenanceFields(t, f.maintenanceArgs())
			args := append(f.maintenanceArgs(), "--mode", "cancel", "--expected-review-id", review["review_id"])
			if err := runPruneOffline(t.Context(), args, output); !errors.Is(err, fault) || !errors.Is(err, errPruneMaintenanceUnobserved) {
				t.Fatal("lost output hid historical ambiguity", err)
			}
			state, authority := f.snapshot(t)
			if state.Stage != authoritystore.PruneCancelled || state.Protection.Pending != nil || authority.Authority.Pending != 1 {
				t.Fatal("stdout failure erased evidence or completed ticket")
			}
			review = runPruneMaintenanceFields(t, f.maintenanceArgs())
			checkPruneCancellationOutput(t, f, runPruneMaintenanceFields(t, pruneCLISet(args, "expected-review-id", review["review_id"])))
		})
	}
}

type pruneControlTestSession struct {
	input  *io.PipeWriter
	lines  chan string
	done   chan struct{}
	cancel context.CancelFunc
	err    error // read only after done
}

func startPruneControlTest(t testing.TB, f *pruneCLIFixture) (*pruneControlTestSession, string) {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	s := &pruneControlTestSession{input: writer, lines: make(chan string, 16), done: make(chan struct{}), cancel: cancel}
	go func() {
		s.err = runPruneCommandIO(ctx, append(f.serveArgs(), "--maintenance-control", "stdin"), reader, pruneCLIReady{s.lines})
		close(s.done)
	}()
	t.Cleanup(func() { cancel(); _ = writer.Close(); s.wait(t) })
	ready := s.next(t)
	if ready["maintenance_control"] != "stdin" || ready["listen"] == "" {
		t.Fatal("control mode not explicit", ready)
	}
	return s, ready["listen"]
}

func (s *pruneControlTestSession) next(t testing.TB) map[string]string {
	t.Helper()
	select {
	case line := <-s.lines:
		return pruneCLIFields(line)
	case <-s.done:
		t.Fatal("control ended before output", s.err)
	case <-time.After(10 * time.Second):
		t.Fatal("control output timeout")
	}
	return nil
}

func (s *pruneControlTestSession) send(t testing.TB, line string) {
	t.Helper()
	if _, err := io.WriteString(s.input, line); err != nil {
		t.Fatal(err)
	}
}

func (s *pruneControlTestSession) wait(t testing.TB) error {
	t.Helper()
	select {
	case <-s.done:
		return s.err
	case <-time.After(10 * time.Second):
		t.Fatal("control lifetime did not drain")
	}
	return nil
}

func TestPruneMaintenanceCLIContinuousOwnershipAndControl(t *testing.T) {
	f := newPruneCLIFixture(t)
	s, address := startPruneControlTest(t, f)
	runPruneCLIDelivery(t, f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address))
	f.assertBusy(t)
	s.send(t, "review\n")
	review := s.next(t)
	f.assertBusy(t)
	// An empty receipt journal prevents a cached ACK from hiding an open socket.
	newOutbox := filepath.Join(f.root, "fresh-admission-observation")
	box, err := authoritystore.CreateAdmissionOutbox(newOutbox, f.assignment, authoritystore.AdmissionIntent{
		ClientPeerID: f.config.ClientPeerID, ServerPeerID: f.config.ServerPeerID, Entry: f.admission}, f.admissionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := box.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runPruneCommand(t.Context(), pruneCLISet(f.deliveryArgs(pruneAdmissionCommand, newOutbox, f.admissionID, address), "timeout", "100ms"), io.Discard); !errors.Is(err, admissionwire.ErrUnconfirmed) {
		t.Fatal("parked command transport remained reachable", err)
	}
	if err := runPruneOffline(t.Context(), f.maintenanceArgs(), io.Discard); !errors.Is(err, authoritystore.ErrBusy) {
		t.Fatal("offline command shared live maintenance owners", err)
	}
	s.send(t, "review\n")
	if !reflect.DeepEqual(review, s.next(t)) {
		t.Fatal("review advanced retained state")
	}
	s.send(t, "cancel-before-start "+review["review_id"]+"\n")
	checkPruneCancellationOutput(t, f, s.next(t))
	f.assertBusy(t)
	s.send(t, "review\n")
	terminal := s.next(t)
	if terminal["review_id"] == review["review_id"] {
		t.Fatal("cancel did not invalidate review")
	}
	s.send(t, "cancel-before-start "+review["review_id"]+"\n")
	if err := s.wait(t); !errors.Is(err, authoritystore.ErrPruneMaintenanceReview) {
		t.Fatal("stale review did not terminate control", err)
	}
	state, authority := f.snapshot(t)
	if state.Stage != authoritystore.PruneCancelled || authority.Authority.Pending != 1 {
		t.Fatal("maintenance completed or repeated work")
	}
}

func TestPruneMaintenanceCLIControlLifetime(t *testing.T) {
	for _, point := range []string{"serving", "parked", "cancelled"} {
		for _, exit := range []string{"eof", "context", "close", "truncated", "oversized", "invalid"} {
			t.Run(point+"/"+exit, func(t *testing.T) {
				f := newPruneCLIFixture(t)
				s, address := startPruneControlTest(t, f)
				if point != "serving" {
					runPruneCLIDelivery(t, f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address))
					s.send(t, "review\n")
					review := s.next(t)
					if point == "cancelled" {
						s.send(t, "cancel-before-start "+review["review_id"]+"\n")
						checkPruneCancellationOutput(t, f, s.next(t))
					}
				}
				f.assertBusy(t)
				switch exit {
				case "eof":
					_ = s.input.Close()
				case "context":
					s.cancel() // writer remains open: supervisor must interrupt Read
				case "close":
					s.send(t, "close\n")
				case "truncated":
					s.send(t, "review")
					_ = s.input.Close()
				case "oversized":
					s.send(t, strings.Repeat("x", maximumPruneControlLine))
				case "invalid":
					s.send(t, "execute\n")
				}
				err := s.wait(t)
				invalid := exit == "truncated" || exit == "oversized" || exit == "invalid"
				if (err != nil) != invalid {
					t.Fatal("incorrect session exit", err)
				}
				state, authority := f.snapshot(t)
				want := authoritystore.PrunePrepared
				if point == "parked" {
					want = authoritystore.PruneAdmitted
				}
				if point == "cancelled" {
					want = authoritystore.PruneCancelled
				}
				if state.Stage != want || authority.Authority.Sequence > 1 {
					t.Fatal("session exit advanced work")
				}
			})
		}
	}
}

func TestPruneMaintenanceCLIControlInputValidation(t *testing.T) {
	f := newPruneCLIFixture(t)
	args := append(f.serveArgs(), "--maintenance-control", "stdin")
	if err := runPruneCommand(t.Context(), args, io.Discard); err == nil {
		t.Fatal("missing control input accepted")
	}
	file, err := os.Open(f.assignmentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := runPruneCommandIO(t.Context(), args, file, io.Discard); err == nil {
		t.Fatal("regular file accepted as live control pipe")
	}
	for _, command := range []string{"cancel-before-start " + pruneCLIHash(99).String() + "\n", "review\r\n", "review \n", "\n"} {
		s, _ := startPruneControlTest(t, f)
		s.send(t, command)
		if err := s.wait(t); err == nil {
			t.Fatal("unreviewed or noncanonical control accepted", command)
		}
	}
	for _, value := range []string{"", "socket", "true"} {
		if err := runPruneCommand(t.Context(), pruneCLISet(args, "maintenance-control", value), io.Discard); err == nil {
			t.Fatal("invalid control mode accepted")
		}
	}
	state, authority := f.snapshot(t)
	if state.Stage != authoritystore.PrunePrepared || authority.Authority.Sequence != 0 {
		t.Fatal("invalid control changed state")
	}
}

func TestPruneMaintenanceCLIPendingConfirmationIsNotResumed(t *testing.T) {
	f := newPruneCLIFixture(t)
	admitPruneMaintenanceFixture(t, f)
	review := runPruneMaintenanceFields(t, f.maintenanceArgs())
	// Preserve the disposable fixture's original confirmation outside the pin
	// root. This represents a retained intent/record without its confirmation;
	// the CLI must not manufacture the missing step merely to produce a review.
	path := filepath.Join(f.config.ExecutorPinsPath, "confirmed", "01.omcpp")
	saved := filepath.Join(f.root, "preserved-admission-confirmation")
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	before := prunePrepareTree(t, f.root)
	for range 2 {
		for _, args := range [][]string{f.maintenanceArgs(), append(f.maintenanceArgs(), "--mode", "cancel", "--expected-review-id", review["review_id"])} {
			var output bytes.Buffer
			if err := runPruneOffline(t.Context(), args, &output); !errors.Is(err, authoritystore.ErrPrunePinPending) || output.Len() != 0 {
				t.Fatal("CLI promoted unconfirmed executor", err)
			}
		}
	}
	if !reflect.DeepEqual(before, prunePrepareTree(t, f.root)) {
		t.Fatal("maintenance rewrote pending evidence")
	}
	state, _ := f.snapshot(t)
	if state.Stage != authoritystore.PruneAdmitted || state.Protection.Pending == nil {
		t.Fatal("missing retained uncertainty")
	}
}

func TestPruneMaintenanceCLIStorageShutdownInterruptsInput(t *testing.T) {
	f := newPruneCLIFixture(t)
	s, address := startPruneControlTest(t, f)
	saved := filepath.Join(f.root, "preserved-executor")
	if err := os.Rename(f.config.ExecutorPath, saved); err != nil {
		t.Fatal(err)
	}
	defer func() {
		s.cancel()
		s.wait(t)
		if err := os.Rename(saved, f.config.ExecutorPath); err != nil {
			t.Error(err)
		}
	}()
	if err := runPruneCommand(t.Context(), f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address), io.Discard); !errors.Is(err, admissionwire.ErrUnconfirmed) {
		t.Fatal("missing storage acknowledged command", err)
	}
	// Parent context and stdin writer stay live. Service failure must stop the
	// input supervisor itself, join it and return the retained storage error.
	if err := s.wait(t); !errors.Is(err, authoritystore.ErrUncertain) {
		t.Fatal("storage shutdown was hidden", err)
	}
}

type pruneCloseFailureInput struct {
	*io.PipeReader
	fault error
}

func (input pruneCloseFailureInput) Close() error {
	return errors.Join(input.PipeReader.Close(), input.fault)
}

func TestPruneMaintenanceCLIInputCleanupAndReadinessFailure(t *testing.T) {
	f := newPruneCLIFixture(t)
	for _, kind := range []string{"close-error", "startup", "output", "short-output"} {
		t.Run(kind, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer writer.Close()
			fault := errors.New("input close failed")
			var input io.ReadCloser = reader
			var output io.Writer = io.Discard
			args := append(f.serveArgs(), "--maintenance-control", "stdin")
			switch kind {
			case "close-error":
				input = pruneCloseFailureInput{reader, fault}
				_ = writer.Close() // EOF stops the service; Close error still matters
			case "startup":
				args = pruneCLISet(args, "listen", "not-a-listener")
			case "output":
				output = pruneFailWriter{fault}
			case "short-output":
				output, fault = pruneShortWriter{}, io.ErrShortWrite
			}
			err := runPruneCommandIO(t.Context(), args, input, output)
			if err == nil || (kind != "startup" && !errors.Is(err, fault)) {
				t.Fatal("cleanup failure lost", err)
			}
			if _, err := writer.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("CLI leaked owned input", err)
			}
			state, authority := f.snapshot(t)
			if state.Stage != authoritystore.PrunePrepared || authority.Authority.Sequence != 0 {
				t.Fatal("cleanup advanced work")
			}
		})
	}
}
