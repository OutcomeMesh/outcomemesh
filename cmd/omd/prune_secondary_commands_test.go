package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

type pruneSecondaryCLIFixture struct {
	root, assignmentPath, serverKey, clientKey string
	config                                     authoritystore.PruneSecondaryCommandServiceConfig
	inventory                                  authoritystore.ArchivePruneInventory
	primary, target                            custodyauthority.Assignment
	admission                                  custodyauthority.Entry
	admissionPath                              string
	admissionID                                types.Hash
}

// The frozen signed package supplies the real checkpoint/replica trust surface.
// Only its disposable executor binding changes; no WorkChain is opened here.
func newPruneSecondaryCLIFixture(t testing.TB) *pruneSecondaryCLIFixture {
	t.Helper()
	encoded, err := os.ReadFile("../../node/custodyauthority/store/testdata/prune_lineage_evidence_v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct{ Inventory []byte }
	if err := json.Unmarshal(encoded, &golden); err != nil {
		t.Fatal(err)
	}
	inventory, err := authoritystore.DecodeArchivePruneInventory(golden.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	f := &pruneSecondaryCLIFixture{root: t.TempDir(), inventory: inventory}
	c := &f.config
	c.Mode = authoritystore.PruneSecondaryBoth
	c.ExecutorPath, c.ExecutorPinsPath = filepath.Join(f.root, "executor"), filepath.Join(f.root, "executor-pins")
	c.AuthorityPath, c.AuthorityPinsPath = filepath.Join(f.root, "secondary"), filepath.Join(f.root, "secondary-pins")
	c.PrimaryAuthorityPath, c.PrimaryAuthorityPinsPath = filepath.Join(f.root, "primary"), filepath.Join(f.root, "primary-pins")
	c.Session = authoritystore.PreparedArchiveSecondaryCommandConfig{ServerPeerID: pruneCLIPeer(45), ClientPeerID: pruneCLIPeer(46), Timeout: 2 * time.Second}
	var primaryAdmission custodyauthority.Entry
	for i, assignment := range inventory.Policy.Assignments {
		id, err := assignment.ID()
		if err != nil {
			t.Fatal(err)
		}
		if id == inventory.Request.AssignmentID {
			f.primary, primaryAdmission = assignment, inventory.Admissions[i]
		} else {
			if !c.Session.AssignmentID.IsZero() {
				t.Fatal("fixture must select exactly one secondary")
			}
			f.target, f.admission, c.Session.AssignmentID = assignment, inventory.Admissions[i], id
		}
	}
	primary, err := authoritystore.CreateCoordinatedAuthority(c.PrimaryAuthorityPath, c.PrimaryAuthorityPinsPath, f.primary, inventory.Request.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	secondary, err := authoritystore.CreateCoordinatedAuthority(c.AuthorityPath, c.AuthorityPinsPath, f.target, c.Session.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondary.Close(); err != nil {
		t.Fatal(err)
	}
	executor, err := authoritystore.CreatePinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, f.primary, inventory.Request, inventory.Policy.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close()
	if _, err := executor.Admit(t.Context(), primary, primaryAdmission); err != nil {
		t.Fatal(err)
	}
	state, err := executor.Snapshot()
	if err != nil || state.Protection == nil {
		t.Fatal("missing independent executor binding", err)
	}
	f.inventory.Policy.ExecutorBindingID = state.Protection.BindingID
	c.Session.InventoryID, err = f.inventory.ID()
	if err != nil {
		t.Fatal(err)
	}
	c.Session.PolicyID, err = f.inventory.PolicyID()
	if err != nil {
		t.Fatal(err)
	}
	inventoryParent := filepath.Join(f.root, "inventory")
	if err := os.Mkdir(inventoryParent, 0o700); err != nil {
		t.Fatal(err)
	}
	c.Session.InventoryPath = filepath.Join(inventoryParent, "prepared.ompi")
	if err := authoritystore.SaveArchivePruneInventoryFile(c.Session.InventoryPath, f.inventory, c.Session.InventoryID, c.Session.PolicyID); err != nil {
		t.Fatal(err)
	}
	f.assignmentPath, f.serverKey, f.clientKey = filepath.Join(f.root, "secondary.omcaa"), filepath.Join(f.root, "server.key"), filepath.Join(f.root, "client.key")
	assignmentBytes, _ := f.target.CanonicalBytes()
	writePruneCLIFile(t, f.assignmentPath, assignmentBytes)
	writePruneCLIFile(t, f.serverKey, pruneCLIKey(45).Seed())
	writePruneCLIFile(t, f.clientKey, pruneCLIKey(46).Seed())
	intent := authoritystore.AdmissionIntent{ClientPeerID: c.Session.ClientPeerID, ServerPeerID: c.Session.ServerPeerID, Entry: f.admission}
	f.admissionID, err = intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	f.admissionPath = filepath.Join(f.root, "admission-outbox")
	outbox, err := authoritystore.CreateAdmissionOutbox(f.admissionPath, f.target, intent, f.admissionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *pruneSecondaryCLIFixture) serveArgs(mode string) []string {
	c, s := f.config, f.config.Session
	args := []string{pruneSecondaryServeCommand, "--mode", mode, "--inventory", s.InventoryPath, "--inventory-id", s.InventoryID.String(),
		"--policy-id", s.PolicyID.String(), "--assignment-id", s.AssignmentID.String(), "--key", f.serverKey,
		"--authority", c.AuthorityPath, "--authority-pins", c.AuthorityPinsPath, "--executor", c.ExecutorPath, "--executor-pins", c.ExecutorPinsPath,
		"--server-peer-id", s.ServerPeerID.String(), "--client-peer-id", s.ClientPeerID.String(), "--timeout", "2s"}
	if mode != "complete" {
		args = append(args, "--primary-authority", c.PrimaryAuthorityPath, "--primary-authority-pins", c.PrimaryAuthorityPinsPath)
	}
	return args
}

func (f *pruneSecondaryCLIFixture) deliveryArgs(name, path string, id types.Hash, address string) []string {
	return []string{name, "--assignment", f.assignmentPath, "--assignment-id", f.config.Session.AssignmentID.String(), "--key", f.clientKey,
		"--outbox", path, "--intent-id", id.String(), "--peer", address, "--timeout", "2s"}
}

func (f *pruneSecondaryCLIFixture) executor(t testing.TB) *authoritystore.PruneExecutor {
	t.Helper()
	e, err := authoritystore.OpenPinnedPruneExecutor(f.config.ExecutorPath, f.config.ExecutorPinsPath, f.primary, f.inventory.Policy.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func (f *pruneSecondaryCLIFixture) coordinator(t testing.TB, primary bool) *authoritystore.Coordinator {
	t.Helper()
	path, pins, assignment, id := f.config.AuthorityPath, f.config.AuthorityPinsPath, f.target, f.config.Session.AssignmentID
	if primary {
		path, pins, assignment, id = f.config.PrimaryAuthorityPath, f.config.PrimaryAuthorityPinsPath, f.primary, f.inventory.Request.AssignmentID
	}
	c, err := authoritystore.OpenCoordinator(path, pins, assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type pruneSecondaryCLIState struct {
	executor           authoritystore.PruneExecution
	primary, secondary authoritystore.Coordination
}

func (f *pruneSecondaryCLIFixture) snapshot(t testing.TB) pruneSecondaryCLIState {
	t.Helper()
	e, p, s := f.executor(t), f.coordinator(t, true), f.coordinator(t, false)
	defer e.Close()
	defer p.Close()
	defer s.Close()
	execution, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	primary, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return pruneSecondaryCLIState{execution, primary, secondary}
}

func (f *pruneSecondaryCLIFixture) prepareCompletion(t testing.TB) (string, types.Hash) {
	t.Helper()
	e, p, s := f.executor(t), f.coordinator(t, true), f.coordinator(t, false)
	defer e.Close()
	defer p.Close()
	defer s.Close()
	cancelled, err := e.CancelBeforeStart(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := cancelled.ID()
	state, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := f.admission.ID()
	entry := signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: f.config.Session.AssignmentID, Kind: custodyauthority.Complete,
		ExpectedSequence: state.Authority.Sequence, ExpectedHead: state.Authority.HeadID, TicketID: ticket, EvidenceID: evidence})
	intent := authoritystore.CompletionIntent{ClientPeerID: f.config.Session.ClientPeerID, ServerPeerID: f.config.Session.ServerPeerID, Entry: entry}
	id, err := intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "completion-outbox")
	outbox, err := authoritystore.CreateCompletionOutbox(path, f.target, intent, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Close(); err != nil {
		t.Fatal(err)
	}
	return path, id
}

func startPruneSecondaryCLI(t testing.TB, args []string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan string, 1), make(chan struct{})
	var result error
	go func() { result = runPruneCommand(ctx, args, pruneCLIReady{ready}); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
				if result != nil {
					t.Error(result)
				}
			case <-time.After(5 * time.Second):
				t.Error("secondary command service did not drain")
			}
		})
	}
	t.Cleanup(stop)
	select {
	case line := <-ready:
		fields := pruneCLIFields(line)
		if !strings.HasPrefix(line, "serving_work_prune_secondary_commands ") || fields["command_only"] != "true" || fields["execution_enabled"] != "false" || fields["automatic_resume"] != "false" || fields["listen"] == "" {
			stop()
			t.Fatal("invalid secondary command readiness", line)
		}
		return line, stop
	case <-done:
		t.Fatal("secondary command service failed before readiness", result)
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("secondary command readiness timeout")
	}
	return "", stop
}

func TestPruneSecondaryCLIRequiresExplicitScope(t *testing.T) {
	f := newPruneSecondaryCLIFixture(t)
	args := f.serveArgs("both")
	for i := 1; i < len(args); i += 2 {
		if args[i] == "--timeout" {
			continue
		}
		t.Run("missing-"+args[i], func(t *testing.T) {
			missing := append(append([]string(nil), args[:i]...), args[i+2:]...)
			var output bytes.Buffer
			if err := runPruneCommand(t.Context(), missing, &output); err == nil || output.Len() != 0 {
				t.Fatal("missing scope accepted", err)
			}
		})
	}
	for _, extra := range [][]string{{"--mode", "admit"}, {"--timeout=1s"}, {"--assignment", f.assignmentPath}, {"--request-id", f.inventory.Policy.RequestID.String()},
		{"--init"}, {"--execute"}, {"--resume"}, {"--sign"}, {"--maintenance-control", "stdin"}, {"trailing"}} {
		if err := runPruneCommand(t.Context(), append(append([]string(nil), args...), extra...), io.Discard); err == nil {
			t.Fatal("ambiguous or expanded service accepted", extra)
		}
	}
	for _, mode := range []string{"", "all", "ADMIT", "none"} {
		if err := runPruneCommand(t.Context(), pruneCLISet(args, "mode", mode), io.Discard); err == nil {
			t.Fatal("implicit/unknown mode accepted", mode)
		}
	}
	for _, flag := range []string{"primary-authority", "primary-authority-pins"} {
		for _, value := range []string{"", f.config.PrimaryAuthorityPath} {
			if err := runPruneCommand(t.Context(), pruneCLISet(f.serveArgs("complete"), flag, value), io.Discard); err == nil {
				t.Fatal("completion accepted supplied primary flag", flag, value)
			}
		}
	}
	if err := runPruneCommand(nil, args, io.Discard); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := runPruneCommand(t.Context(), args, nil); err == nil {
		t.Fatal("nil output accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runPruneCommand(ctx, args, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := run([]string{pruneSecondaryServeCommand}); err == nil || strings.Contains(err.Error(), "unknown command") {
		t.Fatal("secondary command is not wired", err)
	}
}

func TestPruneSecondaryCLIValidatesBeforeReadingKey(t *testing.T) {
	f := newPruneSecondaryCLIFixture(t)
	before := f.snapshot(t)
	args := pruneCLISet(f.serveArgs("both"), "key", filepath.Join(f.root, "missing.key"))
	for _, change := range []struct{ flag, value string }{
		{"inventory-id", pruneCLIHash(99).String()}, {"policy-id", pruneCLIHash(99).String()},
		{"assignment-id", f.inventory.Request.AssignmentID.String()}, {"server-peer-id", pruneCLIPeer(1).String()},
		{"client-peer-id", pruneCLIPeer(51).String()}, {"authority", f.config.ExecutorPath},
		{"authority-pins", filepath.Join(f.config.ExecutorPath, "nested")}, {"executor-pins", filepath.Dir(f.config.Session.InventoryPath)},
		{"executor", filepath.Join(f.root, "missing-executor")}, {"authority-pins", filepath.Join(f.root, "missing-pins")},
	} {
		var output bytes.Buffer
		err := runPruneCommand(t.Context(), pruneCLISet(args, change.flag, change.value), &output)
		if err == nil || strings.Contains(err.Error(), "read explicit seed file") || output.Len() != 0 {
			t.Fatal("invalid scope reached key or listener", change, err)
		}
		if after := f.snapshot(t); !reflect.DeepEqual(before, after) {
			t.Fatal("failed scope open advanced an owner", change)
		}
	}
	for _, change := range []struct{ flag, value string }{{"key", filepath.Join(f.root, "missing.key")}, {"key", f.clientKey}, {"listen", "invalid-listen"}} {
		var output bytes.Buffer
		if err := runPruneCommand(t.Context(), pruneCLISet(f.serveArgs("both"), change.flag, change.value), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid startup reported ready", change, err)
		}
		if after := f.snapshot(t); !reflect.DeepEqual(before, after) {
			t.Fatal("key/listener failure retained or advanced owners")
		}
	}
	for _, name := range []string{"missing-executor", "missing-pins", "missing.key"} {
		if _, err := os.Lstat(filepath.Join(f.root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("service created missing artifact", name, err)
		}
	}
	failed := errors.New("readiness unavailable")
	if err := runPruneCommand(t.Context(), f.serveArgs("both"), pruneFailWriter{failed}); !errors.Is(err, failed) {
		t.Fatal("lost readiness error", err)
	}
	if after := f.snapshot(t); !reflect.DeepEqual(before, after) {
		t.Fatal("readiness failure advanced owners")
	}
}

func TestPruneSecondaryCLILifetimeAndOfflineHandoff(t *testing.T) {
	f := newPruneSecondaryCLIFixture(t)
	before := f.snapshot(t)
	for _, mode := range []string{"admit", "complete", "both"} {
		var heldPrimary *authoritystore.Coordinator
		if mode == "complete" {
			heldPrimary = f.coordinator(t, true)
		}
		line, stop := startPruneSecondaryCLI(t, f.serveArgs(mode))
		fields := pruneCLIFields(line)
		if fields["mode"] != mode || fields["peer_id"] != f.config.Session.ServerPeerID.String() ||
			fields["assignment_id"] != f.config.Session.AssignmentID.String() || fields["inventory_id"] != f.config.Session.InventoryID.String() || fields["policy_id"] != f.config.Session.PolicyID.String() {
			t.Fatal("readiness lost independent scope", line)
		}
		var output bytes.Buffer
		if err := runPruneCommand(t.Context(), f.serveArgs(mode), &output); !errors.Is(err, authoritystore.ErrBusy) || output.Len() != 0 {
			t.Fatal("second service shared protected owners", err)
		}
		stop()
		if heldPrimary != nil {
			if err := heldPrimary.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if after := f.snapshot(t); !reflect.DeepEqual(before, after) {
			t.Fatal("start/stop automatically advanced a command")
		}
	}
	line, stop := startPruneSecondaryCLI(t, f.serveArgs("admit"))
	admission := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, pruneCLIFields(line)["listen"])
	admitted := runPruneCLIDelivery(t, admission)
	stop()
	state := f.snapshot(t)
	if state.executor.Stage != authoritystore.PruneAdmitted || state.secondary.Authority.Sequence != 1 || state.secondary.Authority.Pending != 1 {
		t.Fatal("secondary admission executed or duplicated work")
	}
	path, id := f.prepareCompletion(t)
	primary := f.coordinator(t, true) // completion does not acquire the primary
	line, stop = startPruneSecondaryCLI(t, f.serveArgs("complete"))
	completion := f.deliveryArgs(pruneCompletionCommand, path, id, pruneCLIFields(line)["listen"])
	completed := runPruneCLIDelivery(t, completion)
	stop()
	if err := primary.Close(); err != nil {
		t.Fatal(err)
	}
	state = f.snapshot(t)
	if state.executor.Stage != authoritystore.PruneCancelled || state.secondary.Authority.Sequence != 2 || state.secondary.Authority.Pending != 0 {
		t.Fatal("secondary completion did not drain exactly once")
	}
	for _, item := range []struct {
		args   []string
		output string
	}{{admission, admitted}, {completion, completed}} {
		if got := runPruneCLIDelivery(t, pruneCLISet(item.args, "peer", "offline")); got != item.output {
			t.Fatal("generic delivery lost retained secondary receipt")
		}
	}
}
