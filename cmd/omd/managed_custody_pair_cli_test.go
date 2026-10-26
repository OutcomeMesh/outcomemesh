package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
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

func TestManagedCustodyPairCLIReviewClosesBeforeOutput(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	before, heads := f.snapshot(t), f.heads(t)
	var output bytes.Buffer
	writer := pruneEffectTestWriter(func(b []byte) (int, error) {
		if !reflect.DeepEqual(before, f.snapshot(t)) {
			t.Error("review retained or changed original authority")
		}
		return output.Write(b)
	})
	if err := runManagedCustodyPair(t.Context(), f.args(""), nil, writer); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	fields := pruneCLIFields(strings.SplitN(text, "\n", 2)[0])
	if !strings.HasPrefix(text, "work_archive_custody_managed_pair_review ") || fields["review_id"] == "" || fields["runtime_review_id"] == "" || fields["owners_retained"] != "false" || fields["exchange_authorized"] != "false" || !strings.HasSuffix(text, "work_archive_custody_managed_pair_scope_end\n") {
		t.Fatal("review scope incomplete", text)
	}
	for _, required := range []string{f.config.AuthorityPath, f.config.AuthorityPinsPath, f.config.Audit.IntentPath, f.config.Audit.ArtifactsPath, f.config.Audit.JournalPath, f.config.Serve.JournalPath, f.config.ObjectPath, f.config.Audit.IntentID.String(), f.config.Serve.ChallengeID.String(), f.config.Assignment.ManifestID.String()} {
		if !strings.Contains(text, required) {
			t.Fatal("missing readable scope", required)
		}
	}
	for _, key := range [][]byte{f.config.Audit.AuditorPrivateKey, f.config.Serve.ReplicaPrivateKey, pruneCLIKey(45).Seed(), pruneCLIKey(46).Seed()} {
		if bytes.Contains(output.Bytes(), key) || strings.Contains(text, hex.EncodeToString(key)) || strings.Contains(text, base64.StdEncoding.EncodeToString(key)) {
			t.Fatal("private seed leaked in review")
		}
	}
	if !reflect.DeepEqual(heads, f.heads(t)) {
		t.Fatal("review changed either journal")
	}
}

func TestManagedCustodyPairCLIReviewNeverPreparesMissingChallenge(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	cycle := filepath.Join(f.config.Audit.ArtifactsPath, "cycle-00000000000000000001")
	if err := os.Remove(filepath.Join(cycle, "challenge.omcc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cycle); err != nil {
		t.Fatal(err)
	}
	before := pruneLineageTree(t, f.config.Audit.ArtifactsPath)
	var output bytes.Buffer
	if err := runManagedCustodyPair(t.Context(), f.args(""), nil, &output); err != nil {
		t.Fatal(err)
	}
	assertPruneLineageTree(t, f.config.Audit.ArtifactsPath, before)
	if _, err := os.Lstat(cycle); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("review signed/published missing challenge", err)
	}
}

type managedCustodyPairPartialOutput struct {
	headers chan string
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (w *managedCustodyPairPartialOutput) Write(b []byte) (int, error) {
	if strings.HasPrefix(string(b), "scope:\n") {
		w.once.Do(func() { close(w.entered) })
		<-w.closed
		return 0, io.ErrClosedPipe
	}
	w.headers <- string(b)
	return len(b), nil
}
func (w *managedCustodyPairPartialOutput) Close() error {
	select {
	case <-w.closed:
	default:
		close(w.closed)
	}
	return nil
}

func TestManagedCustodyPairCLIIncompleteReviewCannotEnableQueuedExchange(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	before, heads := f.snapshot(t), f.heads(t)
	output := &managedCustodyPairPartialOutput{headers: make(chan string, 4), entered: make(chan struct{}), closed: make(chan struct{})}
	s := startManagedCustodyPairCLI(t, f, output)
	select {
	case <-output.headers:
	case <-time.After(10 * time.Second):
		t.Fatal("pair readiness not reported")
	}
	s.send(t, "review")
	var header string
	select {
	case header = <-output.headers:
	case <-time.After(10 * time.Second):
		t.Fatal("review header not reported")
	}
	id := pruneCLIFields(header)["review_id"]
	if id == "" {
		t.Fatal("review header omitted token")
	}
	select {
	case <-output.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("scope did not block")
	}
	// The digest alone is already visible, but its required readable scope has
	// not reached the observer. Even a correctly queued digest cannot execute.
	s.send(t, "exchange "+id)
	if !reflect.DeepEqual(heads, f.heads(t)) {
		t.Fatal("queued exchange ran before complete scope output")
	}
	s.cancel()
	if err := s.wait(t); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("partial review failure lost", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) || !reflect.DeepEqual(heads, f.heads(t)) {
		t.Fatal("incomplete review performed an exchange")
	}
}

type managedCustodyPairCLIControl struct {
	input  *io.PipeWriter
	writes chan string
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func startManagedCustodyPairCLI(t testing.TB, f *managedCustodyPairCLIFixture, output io.Writer) *managedCustodyPairCLIControl {
	t.Helper()
	r, w := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	s := &managedCustodyPairCLIControl{input: w, writes: make(chan string, 8), done: make(chan struct{}), cancel: cancel}
	if output == nil {
		output = pruneEffectTestWriter(func(b []byte) (int, error) {
			select {
			case s.writes <- string(b):
				return len(b), nil
			default:
				return 0, errors.New("pair observer did not drain bounded output")
			}
		})
	}
	go func() { s.err = runManagedCustodyPair(ctx, f.args("control"), r, output); close(s.done) }()
	t.Cleanup(func() { cancel(); _ = w.Close(); _ = s.wait(t) })
	return s
}

func (s *managedCustodyPairCLIControl) wait(t testing.TB) error {
	t.Helper()
	select {
	case <-s.done:
		return s.err
	case <-time.After(12 * time.Second):
		t.Fatal("pair CLI did not drain")
	}
	return nil
}
func (s *managedCustodyPairCLIControl) next(t testing.TB) string {
	t.Helper()
	select {
	case b := <-s.writes:
		return b
	case <-s.done:
		select {
		case b := <-s.writes:
			return b
		default:
			t.Fatal("pair CLI stopped before output", s.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pair CLI output timeout")
	}
	return ""
}
func (s *managedCustodyPairCLIControl) ready(t testing.TB) {
	t.Helper()
	line := s.next(t)
	if !strings.HasPrefix(line, "work_archive_custody_managed_pair_ready ") || pruneCLIFields(line)["owners_retained"] != "true" {
		t.Fatal("invalid pair readiness", line)
	}
}
func (s *managedCustodyPairCLIControl) send(t testing.TB, text string) {
	t.Helper()
	if _, err := io.WriteString(s.input, text+"\n"); err != nil {
		t.Fatal(err)
	}
}
func (s *managedCustodyPairCLIControl) review(t testing.TB) string {
	t.Helper()
	s.send(t, "review")
	header := s.next(t)
	if !strings.HasPrefix(header, "work_archive_custody_managed_pair_review ") {
		t.Fatal("missing pair review", header)
	}
	scope := s.next(t)
	if !strings.HasSuffix(scope, "work_archive_custody_managed_pair_scope_end\n") {
		t.Fatal("scope did not complete")
	}
	return pruneCLIFields(header)["review_id"]
}

func TestManagedCustodyPairCLIExchangeRequiresReportedReviewAndPreservesAuthority(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	before := f.snapshot(t)
	var first string
	for _, phase := range []string{"fresh", "reopened"} {
		s := startManagedCustodyPairCLI(t, f, nil)
		s.ready(t)
		f.assertBusy(t)
		id := s.review(t)
		s.send(t, "exchange "+id)
		line := s.next(t)
		fields := pruneCLIFields(line)
		if !strings.HasPrefix(line, "work_archive_custody_managed_pair_exchanged ") || fields["expected_review_id"] != id || fields["audit_sequence"] != "1" || fields["replica_sequence"] != "1" || fields["automatic_completion"] != "false" {
			t.Fatal("wrong exchange report", line)
		}
		if phase == "fresh" {
			first = fields["renewal_id"]
		} else if fields["renewal_id"] != first || fields["recovered"] != "true" {
			t.Fatal("reopen refreshed the response", line)
		}
		s.send(t, "close")
		if err := s.wait(t); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, f.snapshot(t)) {
			t.Fatal("exchange or close completed authority")
		}
		heads := f.heads(t)
		if heads.Audit.Sequence != 1 || heads.Replica.Sequence != 1 || heads.Audit.CurrentReceipt != heads.Replica.CurrentReceipt {
			t.Fatal("journals disagree")
		}
	}
}

func TestManagedCustodyPairCLIRejectsUnreportedAndConsumedTokens(t *testing.T) {
	for _, mode := range []string{"unreported", "wrong", "consumed"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedCustodyPairCLIFixture(t)
			before := f.snapshot(t)
			s := startManagedCustodyPairCLI(t, f, nil)
			s.ready(t)
			id := pruneCLIHash(119).String()
			if mode != "unreported" {
				id = s.review(t)
			}
			if mode == "wrong" {
				id = pruneCLIHash(120).String()
			}
			if mode == "consumed" {
				s.send(t, "exchange "+id)
				_ = s.next(t)
			}
			s.send(t, "exchange "+id)
			if err := s.wait(t); err == nil {
				t.Fatal("invalid review token accepted")
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("token failure changed authority")
			}
			heads := f.heads(t)
			expected := uint64(0)
			if mode == "consumed" {
				expected = 1
			}
			if heads.Audit.Sequence != expected || heads.Replica.Sequence != expected {
				t.Fatal("invalid token performed an extra exchange")
			}
		})
	}
}

func TestManagedCustodyPairCLISupervisionAndReadinessFailures(t *testing.T) {
	for _, mode := range []string{"close", "eof", "cancel", "malformed", "partial", "oversized", "broken-readiness", "blocked-readiness"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedCustodyPairCLIFixture(t)
			before, heads := f.snapshot(t), f.heads(t)
			var output io.Writer
			injected := errors.New("lost pair readiness")
			var blocked *managedCustodyCLIBlockedOutput
			if mode == "broken-readiness" {
				output = pruneEffectTestWriter(func([]byte) (int, error) { return 0, injected })
			}
			if mode == "blocked-readiness" {
				blocked = &managedCustodyCLIBlockedOutput{entered: make(chan struct{}), closed: make(chan struct{})}
				output = blocked
			}
			s := startManagedCustodyPairCLI(t, f, output)
			if blocked != nil {
				select {
				case <-blocked.entered:
				case <-time.After(10 * time.Second):
					t.Fatal("readiness not reached")
				}
				f.assertBusy(t)
				s.cancel()
			} else if mode != "broken-readiness" {
				s.ready(t)
				f.assertBusy(t)
				switch mode {
				case "close":
					s.send(t, "close")
				case "eof":
					_ = s.input.Close()
				case "cancel":
					s.cancel()
				case "malformed":
					s.send(t, "complete")
				case "partial":
					_, _ = io.WriteString(s.input, "exchange")
					_ = s.input.Close()
				case "oversized":
					_, _ = io.WriteString(s.input, strings.Repeat("x", maximumPruneControlLine+1)+"\n")
				}
			}
			err := s.wait(t)
			if mode == "broken-readiness" && !errors.Is(err, injected) {
				t.Fatal("readiness failure lost", err)
			}
			if mode == "blocked-readiness" && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("blocked output not interrupted", err)
			}
			if (mode == "malformed" || mode == "partial" || mode == "oversized") && err == nil {
				t.Fatal("invalid control accepted")
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) || !reflect.DeepEqual(heads, f.heads(t)) {
				t.Fatal("supervision failure changed durable evidence")
			}
		})
	}
}

func TestManagedCustodyPairCLIPublicValidationBeforeSeeds(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	for _, path := range []string{f.audit.auditorKey, f.audit.serve.replicaKey, f.audit.transportKey, f.audit.serve.serverKey} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	for name, args := range map[string][]string{
		"mode": pruneCLISet(f.args(""), "mode", "serve"), "duplicate": append(f.args(""), "--intent-id", f.config.Audit.IntentID.String()), "positionals": append(f.args(""), "extra"),
		"intent": pruneCLISet(f.args(""), "intent-id", pruneCLIHash(115).String()), "audit-ticket": pruneCLISet(f.args(""), "audit-ticket-id", pruneCLIHash(115).String()),
		"serve-ticket": pruneCLISet(f.args(""), "serve-ticket-id", pruneCLIHash(115).String()), "challenge": pruneCLISet(f.args(""), "challenge-id", pruneCLIHash(115).String()),
		"role-peer": pruneCLISet(f.args(""), "auditor-peer-id", pruneCLIPeer(3).String()), "same-peer": pruneCLISet(f.args(""), "auditor-peer-id", f.config.ReplicaPeerID.String()),
		"overlap": pruneCLISet(f.args(""), "audit-journal", f.config.Serve.JournalPath), "missing-root": pruneCLISet(f.args(""), "objects", filepath.Join(f.audit.serve.root, "absent")),
		"policy": pruneCLISet(f.args(""), "max-proof-age-seconds", "99"), "budget": pruneCLISet(f.args(""), "max-objects", "0"), "timeout": pruneCLISet(f.args(""), "timeout", "99ms"),
		"listen": pruneCLISet(f.args(""), "listen", "/ip4/127.0.0.1/tcp/0"), "utf8": pruneCLISet(f.args(""), "objects", string([]byte{0xff})),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadManagedCustodyPairOptions(t.Context(), args); err == nil || strings.Contains(err.Error(), "read explicit seed file") {
				t.Fatal("invalid public scope reached private seeds", err)
			}
		})
	}
}

func TestManagedCustodyPairCLIRejectsWrongRoleKeysAndNativeNonPipes(t *testing.T) {
	f := newManagedCustodyPairCLIFixture(t)
	before := f.snapshot(t)
	wrong := filepath.Join(f.audit.serve.root, "pair-wrong.seed")
	writePruneCLIFile(t, wrong, pruneCLIKey(49).Seed())
	for _, name := range []string{"auditor-key", "replica-key", "auditor-transport-key", "replica-transport-key"} {
		if _, err := loadManagedCustodyPairOptions(t.Context(), pruneCLISet(f.args(""), name, wrong)); err == nil {
			t.Fatal("wrong role key accepted", name)
		}
	}
	regular, err := os.Open(f.audit.serve.assignmentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if err := runManagedCustodyPair(t.Context(), f.args("control"), regular, io.Discard); err == nil {
		t.Fatal("adopted regular file as control input")
	}
	output, err := os.Create(filepath.Join(f.audit.serve.root, "pair-regular-output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	r, w := io.Pipe()
	defer w.Close()
	if err := runManagedCustodyPair(t.Context(), f.args("control"), r, output); err == nil {
		t.Fatal("adopted regular file as control output")
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("invalid keys or pipe placement changed authority")
	}
}
