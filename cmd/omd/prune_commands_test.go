package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
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
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
)

type pruneCLIFixture struct {
	root, assignmentPath, serverKey, clientKey string
	assignment                                 custodyauthority.Assignment
	config                                     authoritystore.PruneCommandServiceConfig
	admission                                  custodyauthority.Entry
	admissionPath                              string
	admissionID                                types.Hash
}

func pruneCLIHash(seed byte) types.Hash { return types.DomainHash("test/prune-cli", []byte{seed}) }
func pruneCLIKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func pruneCLIPublic(seed byte) [32]byte {
	return [32]byte(pruneCLIKey(seed).Public().(ed25519.PublicKey))
}
func pruneCLIPeer(seed byte) types.Hash {
	id, _ := transport.PeerIDFromPublicKey(pruneCLIKey(seed).Public().(ed25519.PublicKey))
	return id
}

func writePruneCLIFile(t testing.TB, path string, encoded []byte) {
	t.Helper()
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newPruneCLIFixture(t testing.TB) *pruneCLIFixture {
	t.Helper()
	f := &pruneCLIFixture{root: t.TempDir()}
	a := custodyauthority.Assignment{NetworkID: 77, GenesisID: pruneCLIHash(1), ActivationHeight: 10,
		BaseID: pruneCLIHash(2), ManifestID: pruneCLIHash(3), StatementID: pruneCLIHash(4), InitialReceiptID: pruneCLIHash(5),
		CustodyPolicyID: pruneCLIHash(6), IncarnationID: pruneCLIHash(7), AuthorityPublicKey: pruneCLIPublic(1), ReplicaPublicKey: pruneCLIPublic(2),
		Auditors: [][32]byte{pruneCLIPublic(3)}, Consumers: []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.AllPurposes}},
		MaximumOperations: 4, MaximumPending: 2}
	f.assignment = a
	assignmentID, err := a.ID()
	if err != nil {
		t.Fatal(err)
	}
	f.assignmentPath, f.serverKey, f.clientKey = filepath.Join(f.root, "assignment.omcaa"), filepath.Join(f.root, "server.key"), filepath.Join(f.root, "client.key")
	encoded, _ := a.CanonicalBytes()
	writePruneCLIFile(t, f.assignmentPath, encoded)
	writePruneCLIFile(t, f.serverKey, pruneCLIKey(45).Seed())
	writePruneCLIFile(t, f.clientKey, pruneCLIKey(46).Seed())
	// The command-only fixture deliberately has no WorkChain database. This is a
	// retained syntactically valid request, not evidence authorizing real pruning.
	request := authoritystore.PruneRequest{AssignmentID: assignmentID, ConsumerPublicKey: pruneCLIPublic(4), StorageID: pruneCLIHash(90),
		Boundary: workchain.CanonicalFloor{Pruned: true, BaseID: a.BaseID,
			Anchor:        storage.Tip{ID: pruneCLIHash(10), Height: a.ActivationHeight, Timestamp: 100, Target: pruneCLIHash(11), StateRoot: pruneCLIHash(12), CumulativeWork: []byte{1}},
			AncestryNodes: 2, AncestryRoot: pruneCLIHash(13), StatementID: a.StatementID, ManifestID: a.ManifestID,
			AvailabilityID: pruneCLIHash(14), VerifiedAt: 100, RetainUntil: 1000}}
	requestID, err := request.ID()
	if err != nil {
		t.Fatal(err)
	}
	f.config = authoritystore.PruneCommandServiceConfig{Assignment: a, AssignmentID: assignmentID, RequestID: requestID,
		AuthorityPath: filepath.Join(f.root, "authority"), AuthorityPinsPath: filepath.Join(f.root, "authority-pins"),
		ExecutorPath: filepath.Join(f.root, "executor"), ExecutorPinsPath: filepath.Join(f.root, "executor-pins"),
		ServerPeerID: pruneCLIPeer(45), ClientPeerID: pruneCLIPeer(46), Timeout: 2 * time.Second}
	authority, err := authoritystore.Create(f.config.AuthorityPath, a, assignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	coordinator, err := authoritystore.CreateCoordinator(f.config.AuthorityPath, f.config.AuthorityPinsPath, a, assignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	executor, err := authoritystore.CreatePinnedPruneExecutor(f.config.ExecutorPath, f.config.ExecutorPinsPath, a, request, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	f.admission = signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: assignmentID, ExpectedHead: assignmentID,
		Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: requestID})
	intent := authoritystore.AdmissionIntent{ClientPeerID: f.config.ClientPeerID, ServerPeerID: f.config.ServerPeerID, Entry: f.admission}
	f.admissionID, err = intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	f.admissionPath = filepath.Join(f.root, "admission-outbox")
	outbox, err := authoritystore.CreateAdmissionOutbox(f.admissionPath, a, intent, f.admissionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

func signPruneCLIEntry(t testing.TB, command custodyauthority.Command) custodyauthority.Entry {
	t.Helper()
	actor := byte(4)
	if command.Kind == custodyauthority.Stop || command.Kind == custodyauthority.Retire {
		actor = 1
	}
	command, err := command.Sign(pruneCLIKey(actor))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(command, pruneCLIKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func (f *pruneCLIFixture) serveArgs() []string {
	c := f.config
	return []string{pruneServeCommand, "--assignment", f.assignmentPath, "--assignment-id", c.AssignmentID.String(), "--key", f.serverKey,
		"--authority", c.AuthorityPath, "--authority-pins", c.AuthorityPinsPath, "--executor", c.ExecutorPath, "--executor-pins", c.ExecutorPinsPath,
		"--request-id", c.RequestID.String(), "--server-peer-id", c.ServerPeerID.String(), "--client-peer-id", c.ClientPeerID.String(), "--timeout", "2s"}
}

func (f *pruneCLIFixture) deliveryArgs(name, path string, id types.Hash, address string) []string {
	return []string{name, "--assignment", f.assignmentPath, "--assignment-id", f.config.AssignmentID.String(), "--key", f.clientKey,
		"--outbox", path, "--intent-id", id.String(), "--peer", address, "--timeout", "2s"}
}

func pruneCLISet(arguments []string, name, value string) []string {
	copy := append([]string(nil), arguments...)
	for i := 1; i+1 < len(copy); i += 2 {
		if copy[i] == "--"+name {
			copy[i+1] = value
			return copy
		}
	}
	return append(copy, "--"+name, value)
}

func (f *pruneCLIFixture) owners(t testing.TB) (*authoritystore.PruneExecutor, *authoritystore.Coordinator) {
	t.Helper()
	c := f.config
	e, err := authoritystore.OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, f.assignment, c.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := authoritystore.OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, f.assignment, c.AssignmentID)
	if err != nil {
		_ = e.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close(); _ = coordinator.Close() })
	return e, coordinator
}

func (f *pruneCLIFixture) snapshot(t testing.TB) (authoritystore.PruneExecution, authoritystore.Coordination) {
	t.Helper()
	e, c := f.owners(t)
	defer e.Close()
	defer c.Close()
	s, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	cs, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return s, cs
}

func (f *pruneCLIFixture) assertBusy(t testing.TB) {
	t.Helper()
	c := f.config
	if e, err := authoritystore.OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, f.assignment, c.RequestID); !errors.Is(err, authoritystore.ErrBusy) {
		if e != nil {
			_ = e.Close()
		}
		t.Fatal("executor ownership escaped service", err)
	}
	if owner, err := authoritystore.OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, f.assignment, c.AssignmentID); !errors.Is(err, authoritystore.ErrBusy) {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("coordinator ownership escaped service", err)
	}
}

func (f *pruneCLIFixture) prepareCompletion(t testing.TB) (string, types.Hash) {
	t.Helper()
	e, c := f.owners(t)
	defer e.Close()
	defer c.Close()
	cancelled, err := e.CancelBeforeStart(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := cancelled.ID()
	ticket, _ := f.admission.ID()
	snapshot, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	entry := signPruneCLIEntry(t, custodyauthority.Command{AssignmentID: f.config.AssignmentID, ExpectedSequence: snapshot.Authority.Sequence,
		ExpectedHead: snapshot.Authority.HeadID, Kind: custodyauthority.Complete, TicketID: ticket, EvidenceID: evidence})
	intent := authoritystore.CompletionIntent{ClientPeerID: f.config.ClientPeerID, ServerPeerID: f.config.ServerPeerID, Entry: entry}
	id, err := intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "completion-outbox")
	outbox, err := authoritystore.CreateCompletionOutbox(path, f.assignment, intent, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Close(); err != nil {
		t.Fatal(err)
	}
	return path, id
}

type pruneCLIReady struct{ line chan string }

func (w pruneCLIReady) Write(p []byte) (int, error) { w.line <- string(p); return len(p), nil }

func startPruneCLI(t testing.TB, f *pruneCLIFixture) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan string, 1), make(chan struct{})
	var result error
	go func() { result = runPruneCommand(ctx, f.serveArgs(), pruneCLIReady{ready}); close(done) }()
	stop := func() {
		cancel()
		select {
		case <-done:
			if result != nil {
				t.Error(result)
			}
		case <-time.After(5 * time.Second):
			t.Error("CLI service did not drain")
		}
	}
	var once sync.Once
	stopOnce := func() { once.Do(stop) }
	t.Cleanup(stopOnce)
	select {
	case line := <-ready:
		fields := pruneCLIFields(line)
		if fields["peer_id"] != f.config.ServerPeerID.String() || fields["execution_enabled"] != "false" || fields["command_only"] != "true" {
			t.Fatal("invalid service readiness", line)
		}
		return fields["listen"], stopOnce
	case <-done:
		t.Fatal("service failed before readiness", result)
	case <-time.After(5 * time.Second):
		t.Fatal("service readiness timeout")
	}
	return "", stopOnce
}

func pruneCLIFields(output string) map[string]string {
	fields := make(map[string]string)
	for _, field := range strings.Fields(output) {
		if key, value, ok := strings.Cut(field, "="); ok {
			fields[key] = value
		}
	}
	return fields
}

func runPruneCLIDelivery(t testing.TB, args []string) string {
	t.Helper()
	var output bytes.Buffer
	if err := runPruneCommand(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(output.String())
	if fields["delivery_confirmed"] != "true" || fields["historical_only"] != "true" || fields["execution_authorized"] != "false" || fields["automatic_retry"] != "false" {
		t.Fatal("delivery output overclaims authority", output.String())
	}
	return output.String()
}

func TestPruneCLIExplicitDeliveryAndOfflineReceipts(t *testing.T) {
	f := newPruneCLIFixture(t)
	address, stop := startPruneCLI(t, f)
	f.assertBusy(t)
	args := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)
	admitted := runPruneCLIDelivery(t, args)
	if again := runPruneCLIDelivery(t, args); again != admitted {
		t.Fatal("cached admission changed exchange")
	}
	stop()
	s, c := f.snapshot(t)
	if s.Stage != authoritystore.PruneAdmitted || c.Authority.Sequence != 1 || c.Authority.Pending != 1 {
		t.Fatal("delivery executed or repeated work")
	}
	path, id := f.prepareCompletion(t) // explicit offline guarded handoff, not a CLI execution capability
	address, stop = startPruneCLI(t, f)
	completion := f.deliveryArgs(pruneCompletionCommand, path, id, address)
	completed := runPruneCLIDelivery(t, completion)
	stop()
	s, c = f.snapshot(t)
	if s.Stage != authoritystore.PruneCancelled || c.Authority.Sequence != 2 || c.Authority.Pending != 0 {
		t.Fatal("completion repeated or did not drain")
	}
	for _, item := range []struct {
		args   []string
		output string
	}{{args, admitted}, {completion, completed}} {
		if got := runPruneCLIDelivery(t, pruneCLISet(item.args, "peer", "offline")); got != item.output {
			t.Fatal("offline receipt changed")
		}
		var output bytes.Buffer
		if err := runPruneCommand(t.Context(), pruneCLISet(item.args, "key", f.serverKey), &output); !errors.Is(err, authoritystore.ErrPruneRuntime) || output.Len() != 0 {
			t.Fatal("cached receipt bypassed identity", err)
		}
	}
}

func TestPruneCLIRejectsFlagsAndMissingPins(t *testing.T) {
	f := newPruneCLIFixture(t)
	for _, name := range []string{pruneServeCommand, pruneAdmissionCommand, pruneCompletionCommand} {
		args := f.serveArgs()
		if name != pruneServeCommand {
			args = f.deliveryArgs(name, f.admissionPath, f.admissionID, "unused")
		}
		for i := 1; i+1 < len(args); i += 2 {
			if args[i] == "--timeout" {
				continue
			}
			t.Run(name+"/missing-"+args[i], func(t *testing.T) {
				missing := append(append([]string(nil), args[:i]...), args[i+2:]...)
				var output bytes.Buffer
				if err := runPruneCommand(t.Context(), missing, &output); err == nil || output.Len() != 0 {
					t.Fatal("missing required flag accepted", err)
				}
			})
		}
		for _, extra := range [][]string{{"--assignment-id", f.config.AssignmentID.String()}, {"--timeout=1s"}, {"--init"}, {"--execute"}, {"--resume"}, {"--sign"}, {"trailing"}} {
			var output bytes.Buffer
			bad := append(append([]string(nil), args...), extra...)
			if err := runPruneCommand(t.Context(), bad, &output); err == nil || output.Len() != 0 {
				t.Fatal("ambiguous or expansive flags accepted", err)
			}
		}
		for _, name := range []string{"assignment-id", "timeout"} {
			for _, value := range []string{"", "0", "0s", strings.Repeat("0", 64)} {
				if err := runPruneCommand(t.Context(), pruneCLISet(args, name, value), io.Discard); err == nil {
					t.Fatal("invalid bound/pin accepted")
				}
			}
		}
	}
	if err := runPruneCommand(nil, f.serveArgs(), io.Discard); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := runPruneCommand(t.Context(), f.serveArgs(), nil); err == nil {
		t.Fatal("nil output accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runPruneCommand(ctx, f.serveArgs(), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, name := range []string{pruneServeCommand, pruneAdmissionCommand, pruneCompletionCommand} {
		if err := run([]string{name}); err == nil || strings.Contains(err.Error(), "unknown command") {
			t.Fatal("command is not wired", err)
		}
	}
	s, c := f.snapshot(t)
	if s.Stage != authoritystore.PrunePrepared || c.Authority.Sequence != 0 {
		t.Fatal("invalid CLI advanced state")
	}
}

func TestPruneCLIStartupFailureReleasesRoots(t *testing.T) {
	f := newPruneCLIFixture(t)
	before, coord := f.snapshot(t)
	for _, change := range []struct{ flag, value string }{
		{"assignment-id", pruneCLIHash(99).String()}, {"request-id", pruneCLIHash(99).String()},
		{"server-peer-id", f.config.ClientPeerID.String()}, {"client-peer-id", pruneCLIPeer(1).String()},
		{"key", f.clientKey}, {"listen", "not-a-listener"}, {"authority", f.config.ExecutorPinsPath},
		{"executor", filepath.Join(f.root, "missing-executor")}, {"authority-pins", filepath.Join(f.root, "missing-pins")},
	} {
		var output bytes.Buffer
		if err := runPruneCommand(t.Context(), pruneCLISet(f.serveArgs(), change.flag, change.value), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid startup reported ready", change, err)
		}
		s, c := f.snapshot(t)
		if !reflect.DeepEqual(before, s) || !reflect.DeepEqual(coord, c) {
			t.Fatal("failed startup changed journals")
		}
	}
	for _, name := range []string{"missing-executor", "missing-pins"} {
		if _, err := os.Lstat(filepath.Join(f.root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing root was created")
		}
	}
}

func TestPruneCLIBoundedArtifactsAndOutboxFailures(t *testing.T) {
	f := newPruneCLIFixture(t)
	args := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, "unused")
	for _, source := range []string{"assignment", "key"} {
		valid := f.assignmentPath
		bound := custodyauthority.MaximumAssignmentBytes
		if source == "key" {
			valid, bound = f.clientKey, ed25519.SeedSize
		}
		for _, kind := range []string{"empty", "short", "oversized", "trailing", "symlink", "directory", "missing"} {
			t.Run(source+"/"+kind, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "input")
				switch kind {
				case "empty":
					writePruneCLIFile(t, path, nil)
				case "short":
					writePruneCLIFile(t, path, []byte{1})
				case "oversized":
					writePruneCLIFile(t, path, make([]byte, bound+1))
				case "trailing":
					encoded, err := os.ReadFile(valid)
					if err != nil {
						t.Fatal(err)
					}
					writePruneCLIFile(t, path, append(encoded, 1))
				case "symlink":
					if err := os.Symlink(valid, path); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				var output bytes.Buffer
				if err := runPruneCommand(t.Context(), pruneCLISet(args, source, path), &output); err == nil || output.Len() != 0 {
					t.Fatal("invalid input accepted", err)
				}
			})
		}
	}
	for _, change := range []struct{ flag, value string }{{"key", f.serverKey}, {"intent-id", pruneCLIHash(99).String()}, {"outbox", filepath.Join(f.root, "missing-outbox")}, {"peer", "not-a-route"}} {
		var output bytes.Buffer
		if err := runPruneCommand(t.Context(), pruneCLISet(args, change.flag, change.value), &output); err == nil || output.Len() != 0 {
			t.Fatal("failed delivery reported success", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(f.root, "missing-outbox")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("client initialized missing journal")
	}
	wrong := append([]string(nil), args...)
	wrong[0] = pruneCompletionCommand
	if err := runPruneCommand(t.Context(), wrong, io.Discard); err == nil {
		t.Fatal("cross-kind outbox accepted")
	}
	outbox, err := authoritystore.OpenAdmissionOutbox(f.admissionPath, f.assignment, f.admissionID)
	if err != nil {
		t.Fatal("failed CLI leaked outbox owner", err)
	}
	defer outbox.Close()
	s, err := outbox.Snapshot()
	if err != nil || s.Acknowledgement != nil {
		t.Fatal("failed CLI retained success", err)
	}
}

type pruneFailWriter struct{ err error }

func (w pruneFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestPruneCLIStorageFailureIsReturnedAfterDrain(t *testing.T) {
	f := newPruneCLIFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready, done := make(chan string, 1), make(chan struct{})
	var result error
	go func() { result = runPruneCommand(ctx, f.serveArgs(), pruneCLIReady{ready}); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("failed service did not drain")
		}
	})
	var address string
	select {
	case line := <-ready:
		address = pruneCLIFields(line)["listen"]
	case <-done:
		t.Fatal("service failed before fault", result)
	case <-time.After(5 * time.Second):
		t.Fatal("service readiness timeout")
	}
	// Make only this disposable executor root unavailable. Keep its bytes intact
	// and restore them after the old process owner has finished draining.
	saved := filepath.Join(f.root, "unavailable-executor")
	if err := os.Rename(f.config.ExecutorPath, saved); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		<-done
		if err := os.Rename(saved, f.config.ExecutorPath); err != nil {
			t.Error(err)
		}
	}()
	var output bytes.Buffer
	args := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)
	if err := runPruneCommand(t.Context(), args, &output); !errors.Is(err, admissionwire.ErrUnconfirmed) || output.Len() != 0 {
		t.Fatal("storage failure acknowledged command", err)
	}
	select {
	case <-done:
		if !errors.Is(result, authoritystore.ErrUncertain) {
			t.Fatal("service hid its retained storage/shutdown error", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("storage failure did not stop CLI")
	}
}

func TestPruneCLIOutputFailureKeepsDurableReceipt(t *testing.T) {
	f := newPruneCLIFixture(t)
	fault := errors.New("output unavailable")
	if err := runPruneCommand(t.Context(), f.serveArgs(), pruneFailWriter{fault}); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if s, c := f.snapshot(t); s.Stage != authoritystore.PrunePrepared || c.Authority.Sequence != 0 {
		t.Fatal("readiness failure changed state")
	}
	address, stop := startPruneCLI(t, f)
	args := f.deliveryArgs(pruneAdmissionCommand, f.admissionPath, f.admissionID, address)
	if err := runPruneCommand(t.Context(), args, pruneFailWriter{fault}); !errors.Is(err, fault) || !errors.Is(err, admissionwire.ErrUnconfirmed) {
		t.Fatal(err)
	}
	stop()
	outbox, err := authoritystore.OpenAdmissionOutbox(f.admissionPath, f.assignment, f.admissionID)
	if err != nil {
		t.Fatal(err)
	}
	s, err := outbox.Snapshot()
	_ = outbox.Close()
	if err != nil || s.Acknowledgement == nil {
		t.Fatal("stdout failure erased receipt", err)
	}
	fields := pruneCLIFields(runPruneCLIDelivery(t, pruneCLISet(args, "peer", "offline")))
	if fields["nonce"] != s.Acknowledgement.Nonce.String() {
		t.Fatal("printing retry sent a new exchange")
	}
	path, id := f.prepareCompletion(t)
	address, stop = startPruneCLI(t, f)
	args = f.deliveryArgs(pruneCompletionCommand, path, id, address)
	if err := runPruneCommand(t.Context(), args, pruneFailWriter{fault}); !errors.Is(err, fault) || !errors.Is(err, completionwire.ErrUnconfirmed) {
		t.Fatal(err)
	}
	stop()
	completion, err := authoritystore.OpenCompletionOutbox(path, f.assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := completion.Snapshot()
	_ = completion.Close()
	if err != nil || cs.Acknowledgement == nil {
		t.Fatal("stdout failure erased completion", err)
	}
	fields = pruneCLIFields(runPruneCLIDelivery(t, pruneCLISet(args, "peer", "offline")))
	if fields["nonce"] != cs.Acknowledgement.Nonce.String() {
		t.Fatal("completion print retry changed nonce")
	}
}

func TestPruneCLIFlagHelpAndEquals(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	var help bytes.Buffer
	flags.SetOutput(&help)
	flags.String("assignment-id", "", "external pin")
	flags.Duration("timeout", time.Second, "timeout")
	if err := parsePruneFlags(flags, []string{"-h"}); !errors.Is(err, flag.ErrHelp) || strings.Contains(help.String(), "panic") {
		t.Fatal(err, help.String())
	}
	flags = flag.NewFlagSet("test", flag.ContinueOnError)
	value := flags.String("pin", "", "pin")
	if err := parsePruneFlags(flags, []string{"--pin=first"}); err != nil || *value != "first" {
		t.Fatal(err)
	}
}
