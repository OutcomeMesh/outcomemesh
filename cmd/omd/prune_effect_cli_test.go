package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type pruneEffectTestWriter func([]byte) (int, error)

func (write pruneEffectTestWriter) Write(encoded []byte) (int, error) { return write(encoded) }

type pruneEffectTestSession struct {
	input   *io.PipeWriter
	fixture *pruneEffectCLIFixture
	writes  chan string
	done    chan struct{}
	cancel  context.CancelFunc
	err     error // only read after done
}

func startPruneEffectTest(t testing.TB, f *pruneEffectCLIFixture, output io.Writer) *pruneEffectTestSession {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	s := &pruneEffectTestSession{input: writer, fixture: f, writes: make(chan string, 32), done: make(chan struct{}), cancel: cancel}
	if output == nil {
		output = pruneEffectTestWriter(func(encoded []byte) (int, error) {
			select {
			case s.writes <- string(encoded):
				return len(encoded), nil
			default:
				return 0, errors.New("test observer did not drain bounded output")
			}
		})
	}
	go func() {
		s.err = runPruneArchiveEffect(ctx, f.args("control"), reader, output)
		close(s.done)
	}()
	t.Cleanup(func() { cancel(); _ = writer.Close(); _ = s.wait(t) })
	return s
}

func (s *pruneEffectTestSession) next(t testing.TB) string {
	t.Helper()
	select {
	case output := <-s.writes:
		return output
	case <-s.done:
		select {
		case output := <-s.writes:
			return output
		default:
		}
		t.Fatal("effect session ended before expected output", s.err)
	case <-time.After(10 * time.Second):
		t.Fatal("effect output timed out")
	}
	return ""
}

func (s *pruneEffectTestSession) send(t testing.TB, command string) {
	t.Helper()
	if _, err := io.WriteString(s.input, command); err != nil {
		t.Fatal("effect input write failed", err)
	}
}

func (s *pruneEffectTestSession) wait(t testing.TB) error {
	t.Helper()
	select {
	case <-s.done:
		return s.err
	case <-time.After(10 * time.Second):
		t.Fatal("effect session did not release its owners")
	}
	return nil
}

func (s *pruneEffectTestSession) ready(t testing.TB) map[string]string {
	t.Helper()
	line := s.next(t)
	fields := pruneCLIFields(line)
	if !strings.HasPrefix(line, "work_prune_archive_effect_ready ") || fields["mode"] != "control" || fields["owners_retained"] != "true" || fields["effect_execution"] != "false" {
		t.Fatal("invalid control readiness", fields)
	}
	return fields
}

func (s *pruneEffectTestSession) review(t testing.TB) map[string]string {
	t.Helper()
	s.send(t, "review\n")
	header := pruneCLIFields(s.next(t))
	if header["review_id"] == "" || header["owners_retained"] != "true" || header["execution_authorized"] != "false" {
		t.Fatal("invalid effect review header", header)
	}
	scope := s.next(t)
	if !strings.HasPrefix(scope, "scope:\n") || !strings.HasSuffix(scope, "\nwork_prune_archive_effect_scope_end\n") {
		t.Fatal("scope was not completely reported", scope)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(scope, "scope:\n"), "\nwork_prune_archive_effect_scope_end\n")), &decoded); err != nil || len(decoded) == 0 {
		t.Fatal("scope is not readable JSON", err)
	}
	assertPruneEffectScope(t, s.fixture, scope)
	return header
}

func assertPruneEffectScope(t testing.TB, f *pruneEffectCLIFixture, scope string) {
	t.Helper()
	if !strings.HasPrefix(scope, "scope:\n") {
		_, scope, _ = strings.Cut(scope, "\n") // one-shot output includes its header
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(scope, "scope:\n"), "\nwork_prune_archive_effect_scope_end\n")
	var decoded struct {
		Base struct {
			ID               string   `json:"id"`
			Height           uint64   `json:"height"`
			Timestamp        uint64   `json:"timestamp"`
			CumulativeWork   string   `json:"cumulative_work"`
			StateRoot        string   `json:"state_root"`
			RecentTimestamps []uint64 `json:"recent_timestamps"`
		} `json:"base"`
		Parameters struct {
			DifficultyAnchorTarget string `json:"difficulty_anchor_target"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatal("scope JSON cannot be reviewed", err)
	}
	b, p := f.config.Base, f.config.Parameters
	root := b.State.Root()
	if decoded.Base.ID != b.Tip.ID.String() || decoded.Base.Height != b.Tip.Height || decoded.Base.Timestamp != b.Tip.Timestamp ||
		decoded.Base.StateRoot != root.String() || decoded.Base.CumulativeWork != hex.EncodeToString(b.Tip.CumulativeWork) ||
		!reflect.DeepEqual(decoded.Base.RecentTimestamps, b.RecentTimestamps) {
		t.Fatal("scope does not display the actual activation base", decoded.Base)
	}
	if decoded.Parameters.DifficultyAnchorTarget != p.DifficultyAnchorTarget.String() || len(decoded.Parameters.DifficultyAnchorTarget) != 64 {
		t.Fatal("scope target is not the exact canonical 32-byte hex value", decoded.Parameters)
	}
}

func TestPruneArchiveEffectCLIReviewClosesBeforeOutput(t *testing.T) {
	for _, lineage := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "lineage"}[lineage], func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, lineage)
			before := f.snapshot(t)
			sourceBefore := pruneLineageTree(t, f.data)
			var output bytes.Buffer
			write := pruneEffectTestWriter(func(encoded []byte) (int, error) {
				if state := f.snapshot(t); !reflect.DeepEqual(before, state) {
					t.Error("review retained owners or advanced state behind output")
				}
				return output.Write(encoded)
			})
			if err := runPruneArchiveEffect(t.Context(), f.args(""), nil, write); err != nil {
				t.Fatal(err)
			}
			fields := pruneCLIFields(strings.SplitN(output.String(), "\n", 2)[0])
			if fields["review_id"] == "" || fields["owners_retained"] != "false" || fields["effect_execution"] != "false" ||
				fields["inventory_id"] != f.config.InventoryID.String() || !strings.HasSuffix(output.String(), "work_prune_archive_effect_scope_end\n") {
				t.Fatal("default review output changed scope or claimed an effect", output.String())
			}
			assertPruneEffectScope(t, f, output.String())
			if state := f.snapshot(t); !reflect.DeepEqual(before, state) {
				t.Fatal("default review changed retained state")
			}
			if _, err := os.Stat(f.config.AvailabilityPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("review published availability evidence", err)
			}
			assertPruneLineageTree(t, f.data, sourceBefore)
		})
	}
}

func TestPruneArchiveEffectCLIControlRunsBothModesAndExportsCanonicalResult(t *testing.T) {
	for _, lineage := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "lineage"}[lineage], func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, lineage)
			s := startPruneEffectTest(t, f, nil)
			s.ready(t)
			f.assertBusy(t)
			review := s.review(t)
			f.assertBusy(t)
			if again := s.review(t); !reflect.DeepEqual(review, again) {
				t.Fatal("read-only review advanced state")
			}
			s.send(t, "execute "+review["review_id"]+"\n")
			result := pruneCLIFields(s.next(t))
			if result["applied"] != "true" || result["completion_submitted"] != "false" || result["automatic_retry"] != "false" || result["owners_retained"] != "true" {
				t.Fatal("execution response lost confirmed semantics", result)
			}
			encoded, err := hex.DecodeString(result["canonical_hex"])
			if err != nil {
				t.Fatal(err)
			}
			effect, err := workchain.DecodeCanonicalPruneEffect(encoded)
			if err != nil || effect.Report.RemovedNodes == 0 {
				t.Fatal("response does not contain the actual canonical effect", err)
			}
			terminalID, err := effect.ID()
			if err != nil || terminalID.String() != result["terminal_id"] {
				t.Fatal("response terminal pin does not match canonical bytes", err)
			}
			ticket, _ := f.admissions[0].ID()
			if kind, _, err := validatePruneSigningTerminal(f.inventory.Request, f.inventory.Policy.RequestID, ticket, terminalID, encoded); err != nil || kind != "succeeded" {
				t.Fatal("export is incompatible with existing Complete signing", err)
			}
			f.assertBusy(t)
			s.send(t, "close\n")
			if err := s.wait(t); err != nil {
				t.Fatal(err)
			}
			state := f.snapshot(t)
			if state.Executor.Stage != authoritystore.PruneSucceeded || state.Executor.ArchiveInventoryID != f.config.InventoryID ||
				state.Executor.Protection.Pending != nil || !state.EffectFound || !reflect.DeepEqual(state.Effect, effect) {
				t.Fatal("CLI response differs from confirmed journal/database result")
			}
			for _, authority := range state.Authorities {
				if authority.Authority.Sequence != 1 || authority.Authority.Pending != 1 || authority.Pending != nil {
					t.Fatal("effect automatically completed an original authority")
				}
			}
		})
	}
}

func TestPruneArchiveEffectCLIRejectsUnreviewedAndMalformedCommands(t *testing.T) {
	f := newPruneEffectCLIFixture(t, false)
	before := f.snapshot(t)
	for _, name := range []string{"early-execute", "different-id", "uppercase-id", "missing-id", "leading-space", "trailing-space", "tab", "crlf", "extra-argument", "truncated", "oversized"} {
		t.Run(name, func(t *testing.T) {
			s := startPruneEffectTest(t, f, nil)
			s.ready(t)
			id := pruneCLIHash(99).String()
			if name != "early-execute" {
				id = s.review(t)["review_id"]
			}
			command := "execute " + id + "\n"
			switch name {
			case "different-id":
				command = "execute " + pruneCLIHash(99).String() + "\n"
			case "uppercase-id":
				command = "execute " + strings.ToUpper(id) + "\n"
			case "missing-id":
				command = "execute\n"
			case "leading-space":
				command = " " + command
			case "trailing-space":
				command = strings.TrimSuffix(command, "\n") + " \n"
			case "tab":
				command = "execute\t" + id + "\n"
			case "crlf":
				command = "execute " + id + "\r\n"
			case "extra-argument":
				command = "execute " + id + " ignored\n"
			case "truncated":
				command = strings.TrimSuffix(command, "\n")
			case "oversized":
				command = strings.Repeat("x", maximumPruneControlLine) + "\n"
			}
			_, _ = io.WriteString(s.input, command)
			if name == "truncated" {
				_ = s.input.Close()
			}
			if err := s.wait(t); err == nil {
				t.Fatal("invalid command ended as success", name)
			}
			if state := f.snapshot(t); !reflect.DeepEqual(before, state) {
				t.Fatal("rejected control input advanced work", name)
			}
		})
	}
	// An externally obtained one-shot review ID is insufficient in a new session.
	var output bytes.Buffer
	if err := runPruneArchiveEffect(t.Context(), f.args("review"), nil, &output); err != nil {
		t.Fatal(err)
	}
	id := pruneCLIFields(strings.SplitN(output.String(), "\n", 2)[0])["review_id"]
	s := startPruneEffectTest(t, f, nil)
	s.ready(t)
	s.send(t, "execute "+id+"\n")
	if err := s.wait(t); err == nil || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("new session accepted another session's review", err)
	}
}

func TestPruneArchiveEffectCLIControlLifetime(t *testing.T) {
	for _, phase := range []string{"ready", "reviewed", "executed"} {
		for _, exit := range []string{"close", "eof", "context"} {
			t.Run(phase+"/"+exit, func(t *testing.T) {
				f := newPruneEffectCLIFixture(t, false)
				before := f.snapshot(t)
				s := startPruneEffectTest(t, f, nil)
				s.ready(t)
				if phase != "ready" {
					review := s.review(t)
					if phase == "executed" {
						s.send(t, "execute "+review["review_id"]+"\n")
						if result := pruneCLIFields(s.next(t)); result["applied"] != "true" {
							t.Fatal("effect was not applied", result)
						}
					}
				}
				f.assertBusy(t)
				switch exit {
				case "close":
					s.send(t, "close\n")
				case "eof":
					_ = s.input.Close()
				case "context":
					s.cancel() // input remains open; the supervisor must interrupt Read
				}
				err := s.wait(t)
				if exit == "close" && err != nil {
					t.Fatal("explicit close failed", err)
				}
				state := f.snapshot(t)
				if phase != "executed" {
					if !reflect.DeepEqual(before, state) {
						t.Fatal("lifetime termination advanced an unexecuted operation")
					}
				} else if state.Executor.Stage != authoritystore.PruneSucceeded || !state.EffectFound || state.Executor.Protection.Pending != nil {
					t.Fatal("lifetime termination erased the confirmed effect")
				}
				for _, authority := range state.Authorities {
					if authority.Authority.Pending != 1 || authority.Authority.Sequence != 1 {
						t.Fatal("lifetime termination completed an original ticket")
					}
				}
			})
		}
	}
}

func TestPruneArchiveEffectCLIShortOutputPreservesOutcome(t *testing.T) {
	for _, failAt := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, false)
			before := f.snapshot(t)
			events := make(chan string, 8)
			writes := 0
			writer := pruneEffectTestWriter(func(encoded []byte) (int, error) {
				writes++
				if writes == failAt {
					return len(encoded) - 1, nil
				}
				events <- string(encoded)
				return len(encoded), nil
			})
			s := startPruneEffectTest(t, f, writer)
			s.writes = events
			if failAt != 1 {
				s.ready(t)
				s.send(t, "review\n")
				if failAt == 4 {
					header := pruneCLIFields(s.next(t))
					_ = s.next(t)
					s.send(t, "execute "+header["review_id"]+"\n")
				}
			}
			if err := s.wait(t); !errors.Is(err, io.ErrShortWrite) || (failAt == 4 && !errors.Is(err, errPruneEffectUnobserved)) {
				t.Fatal("short output lost its error/outcome ambiguity", err)
			}
			state := f.snapshot(t)
			if failAt != 4 {
				if !reflect.DeepEqual(before, state) {
					t.Fatal("failed readiness/review/scope output allowed execution")
				}
			} else if state.Executor.Stage != authoritystore.PruneSucceeded || !state.EffectFound || state.Executor.Protection.Pending != nil {
				t.Fatal("failed terminal output erased the committed outcome")
			}
			for _, authority := range state.Authorities {
				if authority.Authority.Pending != 1 {
					t.Fatal("output failure completed a ticket")
				}
			}
		})
	}
}

func TestPruneArchiveEffectControlEOFBypassesQueuedCommand(t *testing.T) {
	for _, input := range []string{"review\n", "review\nexecute", "review\nreview\n"} {
		ctx, cancel := context.WithCancel(t.Context())
		lines, terminal := make(chan string, 1), make(chan error, 1)
		done := make(chan struct{})
		go func() { readPruneEffectControl(ctx, strings.NewReader(input), lines, terminal, cancel); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("full command queue prevented EOF/error cancellation")
		}
		if ctx.Err() != context.Canceled || len(lines) != 1 || len(terminal) != 1 {
			t.Fatal("producer failed to retain one command and signal terminal state")
		}
		err := <-terminal
		if (input == "review\n") != (err == io.EOF) {
			t.Fatal("partial or pipelined input became clean EOF", err)
		}
		cancel()
	}
}

func TestPruneArchiveEffectCLIRejectsRetainedInputLossAfterReview(t *testing.T) {
	for _, kind := range []string{"inventory", "lineage"} {
		t.Run(kind, func(t *testing.T) {
			f := newPruneEffectCLIFixture(t, kind == "lineage")
			before := f.snapshot(t)
			s := startPruneEffectTest(t, f, nil)
			s.ready(t)
			review := s.review(t)
			path := f.config.InventoryPath
			if kind == "lineage" {
				path = f.config.LineagePath
			}
			if err := os.Rename(path, path+".offline"); err != nil {
				t.Fatal(err)
			}
			s.send(t, "execute "+review["review_id"]+"\n")
			if err := s.wait(t); err == nil {
				t.Fatal("retained input loss allowed an effect")
			}
			if state := f.snapshot(t); !reflect.DeepEqual(before, state) {
				t.Fatal("lost retained input advanced executor, authority or chain")
			}
			if _, err := os.Stat(f.config.AvailabilityPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("input rejection published availability", err)
			}
		})
	}
}

func TestPruneArchiveEffectCLIRejectsChangedRootsBeforeOpen(t *testing.T) {
	f := newPruneEffectCLIFixture(t, false)
	before := f.snapshot(t)
	sourceBefore := pruneLineageTree(t, f.data)
	writePruneCLIFile(t, f.rootsPath, []byte(`{"authorities":[],"replicas":[]}`))
	var output bytes.Buffer
	if err := runPruneArchiveEffect(t.Context(), f.args("review"), nil, &output); err == nil || output.Len() != 0 {
		t.Fatal("changed incomplete roots were accepted", err, output.String())
	}
	if state := f.snapshot(t); !reflect.DeepEqual(before, state) {
		t.Fatal("roots rejection advanced retained state")
	}
	assertPruneLineageTree(t, f.data, sourceBefore)
}
