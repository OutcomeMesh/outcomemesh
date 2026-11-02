//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	"github.com/outcomemesh/outcomemesh/node/pruneservice/serviceclient"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const pruneProcessOwnerUID = 60000
const pruneProcessParticipantUID = 65534
const pruneProcessEnv = "OUTCOMEMESH_PRUNE_UID_"

// These are disposable process coordinates and public signed artifacts, not a
// protocol or an owner configuration. No private key is sent to the participant.
type pruneProcessManifest struct {
	Root, Socket        string
	Descriptor, Request []byte
	PrivatePaths        []string
	Position            wire.Position
	Held                bool
}

type pruneUIDProcess struct {
	done chan struct{}
	err  error
	log  string
}

// This test proves participant/service UID separation with the real Owner and
// Unix server. The fixture's guard and witnesses share the service account;
// it does not claim independent operators or protection against root rollback.
func TestProcessPruneServiceUIDIsolation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root to start fresh service and participant UIDs")
	}
	for _, mode := range []string{"completed", "held"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			base, err := os.MkdirTemp("/tmp", "ompsi-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(base) })
			if err = os.Chmod(base, 0755); err != nil {
				t.Fatal(err)
			}
			ownerDir, participantDir := filepath.Join(base, "owner-work"), filepath.Join(base, "participant-work")
			public, control := filepath.Join(base, "public"), filepath.Join(base, "control")
			// Only new empty containers are assigned here. Every original key,
			// journal and store is subsequently created by UID 60000 itself.
			for _, d := range []struct {
				path string
				uid  int
				mode fs.FileMode
			}{{ownerDir, pruneProcessOwnerUID, 0700}, {participantDir, pruneProcessParticipantUID, 0700}, {public, pruneProcessOwnerUID, 0755}, {control, 0, 0755}} {
				if err = os.Mkdir(d.path, d.mode); err != nil {
					t.Fatal(err)
				}
				if err = os.Chown(d.path, d.uid, d.uid); err != nil {
					t.Fatal(err)
				}
				if err = os.Chmod(d.path, d.mode); err != nil {
					t.Fatal(err)
				}
			}
			binary := filepath.Join(base, "omd.test")
			pruneCopyTestBinary(t, binary)
			owner := pruneStartUID(t, ctx, binary, ownerDir, public, control, mode, "owner", pruneProcessOwnerUID, 85*time.Second)
			pruneWaitProcessFile(t, ctx, owner, filepath.Join(public, "ready-live"))
			manifest := pruneReadProcessManifest(t, public)
			d, q := pruneDecodeProcessManifest(t, manifest)
			if d.OwnerUID != pruneProcessOwnerUID || d.ParticipantUID != pruneProcessParticipantUID {
				t.Fatal("fixture lost UID pins")
			}
			// Root has a valid signed request but the wrong peer UID. The real
			// server must refuse it before asking the consumer to sign anything.
			wrongCtx, stopWrong := context.WithTimeout(ctx, 3*time.Second)
			wrongCalls := 0
			_, err = serviceclient.Call(wrongCtx, manifest.Socket, d, q, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
				wrongCalls++
				return custodyfence.Command{}, errors.New("wrong UID reached approval")
			})
			stopWrong()
			if err == nil || wrongCalls != 0 {
				t.Fatal("wrong kernel UID accepted", err, wrongCalls)
			}
			participant := pruneStartUID(t, ctx, binary, participantDir, public, control, mode, "participant", pruneProcessParticipantUID, 20*time.Second)
			pruneWaitUIDProcess(t, ctx, participant)
			pruneWriteProcessJSON(t, filepath.Join(control, "stop-live"), true, 0644)
			pruneWaitProcessFile(t, ctx, owner, filepath.Join(public, "offline-ready"))
			manifest = pruneReadProcessManifest(t, public)
			if manifest.Held != (mode == "held") || manifest.Position.Sequence != map[string]uint32{"completed": 2, "held": 1}[mode] {
				t.Fatal("wrong retained position", manifest.Position)
			}
			// A distinct owner process now opens only the original service root.
			// The first process keeps fixture parents alive, with network stopped
			// and all original runtime paths renamed out of service.
			replayOwner := pruneStartUID(t, ctx, binary, ownerDir, public, control, mode, "replay-owner", pruneProcessOwnerUID, 25*time.Second)
			pruneWaitProcessFile(t, ctx, replayOwner, filepath.Join(public, "ready-replay"))
			replayParticipant := pruneStartUID(t, ctx, binary, participantDir, public, control, mode, "replay-participant", pruneProcessParticipantUID, 20*time.Second)
			pruneWaitUIDProcess(t, ctx, replayParticipant)
			pruneWriteProcessJSON(t, filepath.Join(control, "stop-replay"), true, 0644)
			pruneWaitUIDProcess(t, ctx, replayOwner)
			pruneWriteProcessJSON(t, filepath.Join(control, "finish-owner"), true, 0644)
			pruneWaitUIDProcess(t, ctx, owner)
		})
	}
}

func pruneCopyTestBinary(t testing.TB, path string) {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	err = errors.Join(copyErr, out.Sync(), out.Close())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func pruneStartUID(t *testing.T, parent context.Context, binary, work, public, control, mode, role string, uid uint32, limit time.Duration) *pruneUIDProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, limit)
	t.Cleanup(cancel)
	log := filepath.Join(filepath.Dir(public), role+".log")
	output, err := os.OpenFile(log, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestProcessPruneServiceUIDHelper$", "-test.v", "-test.timeout=85s")
	cmd.Dir = work
	cmd.Stdout = output
	cmd.Stderr = output
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, pruneProcessEnv) && !strings.HasPrefix(entry, "TMPDIR=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "TMPDIR="+work, pruneProcessEnv+"ROLE="+role, pruneProcessEnv+"MODE="+mode, pruneProcessEnv+"PUBLIC="+public, pruneProcessEnv+"CONTROL="+control)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	if err = cmd.Start(); err != nil {
		output.Close()
		t.Fatal(err)
	}
	p := &pruneUIDProcess{done: make(chan struct{}), log: log}
	go func() { p.err = errors.Join(cmd.Wait(), output.Close()); close(p.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			t.Errorf("child did not stop: %s", role)
		}
	})
	return p
}

func pruneWaitUIDProcess(t testing.TB, ctx context.Context, p *pruneUIDProcess) {
	t.Helper()
	select {
	case <-p.done:
		if p.err != nil {
			raw, _ := os.ReadFile(p.log)
			t.Fatalf("UID child failed: %v\n%s", p.err, raw)
		}
	case <-ctx.Done():
		t.Fatal("UID child deadline", ctx.Err())
	}
}
func pruneWaitProcessFile(t testing.TB, ctx context.Context, p *pruneUIDProcess, path string) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("waiting for process stage", path, ctx.Err())
		case <-p.done:
			raw, _ := os.ReadFile(p.log)
			t.Fatalf("child ended before %s: %v\n%s", path, p.err, raw)
		case <-ticker.C:
		}
	}
}
func pruneWaitMarker(ctx context.Context, path string) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func pruneWriteProcessJSON(t testing.TB, path string, value any, mode fs.FileMode) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "stage-")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		t.Fatal(err)
	}
	_, writeErr := f.Write(raw)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(name, path); err != nil {
		t.Fatal(err)
	}
}
func pruneReadProcessManifest(t testing.TB, public string) pruneProcessManifest {
	t.Helper()
	var m pruneProcessManifest
	raw, err := os.ReadFile(filepath.Join(public, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func pruneDecodeProcessManifest(t testing.TB, m pruneProcessManifest) (wire.Descriptor, wire.Request) {
	t.Helper()
	d, err := wire.DecodeDescriptor(m.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.DecodeRequest(m.Request)
	if err != nil || q.Authorize(d) != nil {
		t.Fatal("invalid process request", err)
	}
	return d, q
}

func TestProcessPruneServiceUIDHelper(t *testing.T) {
	role := os.Getenv(pruneProcessEnv + "ROLE")
	if role == "" {
		t.Skip("UID process helper")
	}
	public, control, mode := os.Getenv(pruneProcessEnv+"PUBLIC"), os.Getenv(pruneProcessEnv+"CONTROL"), os.Getenv(pruneProcessEnv+"MODE")
	if !filepath.IsAbs(public) || !filepath.IsAbs(control) || (mode != "held" && mode != "completed") {
		t.Fatal("invalid process coordinates")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Second)
	defer cancel()
	switch role {
	case "owner":
		pruneUIDOwner(t, ctx, public, control, mode)
	case "replay-owner":
		pruneUIDReplayOwner(t, ctx, public, control, mode)
	case "participant", "replay-participant":
		pruneUIDParticipant(t, ctx, public, mode, role == "replay-participant")
	default:
		t.Fatal("unknown UID helper role")
	}
}

func pruneUIDOwner(t *testing.T, ctx context.Context, public, control, mode string) {
	if os.Geteuid() != pruneProcessOwnerUID {
		t.Fatal("bootstrap did not run under service UID")
	}
	f := preparePruneServiceOwnerCLI(t)
	// Bootstrap signs the public request with a deterministic fixture key. Remove
	// its seed artifact before the isolated owner starts accepting connections.
	if err := os.Remove(f.consumerPath); err != nil {
		t.Fatal(err)
	}
	before := pruneUIDObligations(t, f)
	m := pruneProcessManifest{Root: f.root, Socket: filepath.Join(public, "live.sock"), Held: mode == "held"}
	m.Descriptor, _ = f.descriptor.CanonicalBytes()
	m.Request, _ = f.request.CanonicalBytes()
	m.PrivatePaths = []string{filepath.Join(f.root, "key"), filepath.Join(f.root, "transport-key"), filepath.Join(f.root, "config"), f.config.Runtime.ExecutorPath, f.config.Runtime.ExecutorPinsPath, f.config.Runtime.ChainPath, f.config.Runtime.ChainPinsPath, f.config.Runtime.InventoryPath}
	pruneWriteProcessJSON(t, filepath.Join(public, "manifest.json"), m, 0644)
	owner := f.open(t, wire.Position{}, nil)
	stop := pruneUIDServe(t, ctx, owner, m.Socket, filepath.Join(public, "ready-live"))
	if err := pruneWaitMarker(ctx, filepath.Join(control, "stop-live")); err != nil {
		t.Fatal(err)
	}
	stop()
	snapshot, err := owner.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Intent == nil || *snapshot.Intent != f.request {
		t.Fatal("exact signed intent not retained")
	}
	m.Position = snapshot.Position
	if mode == "completed" {
		if snapshot.Response == nil || snapshot.Position.Sequence != 2 || snapshot.Response.Result == nil || snapshot.Response.Effect.Report.RemovedNodes == 0 {
			t.Fatal("real deletion did not complete")
		}
		if err = snapshot.Response.Verify(f.descriptor, f.request); err != nil {
			t.Fatal(err)
		}
		pruneUIDCheckStorageEffect(t, f, snapshot.Response)
	} else {
		if snapshot.Response != nil || snapshot.Position.Sequence != 1 {
			t.Fatal("disconnect lost held intent")
		}
		if _, err = owner.Recover(ctx, f.request); err == nil {
			t.Fatal("missing outcome became success")
		}
		pruneUIDCheckStorageEffect(t, f, nil)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if after := pruneUIDObligations(t, f); !reflect.DeepEqual(before, after) {
		t.Fatal("Prune changed original pending or spent accounting")
	}
	f.assertObligations(t)
	f.stopNetwork()
	if _, err = os.Stat(f.consumerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("consumer seed reappeared in owner fixture", err)
	}
	for _, path := range append(pruneServiceRuntimeRoots(f.config.Runtime), f.config.Runtime.InventoryPath) {
		if err = os.Rename(path, path+".offline"); err != nil {
			t.Fatal("source offline", err)
		}
	}
	m.Socket = filepath.Join(public, "replay.sock")
	pruneWriteProcessJSON(t, filepath.Join(public, "manifest.json"), m, 0644)
	pruneWriteProcessJSON(t, filepath.Join(public, "offline-ready"), m.Position, 0644)
	if err = pruneWaitMarker(ctx, filepath.Join(control, "finish-owner")); err != nil {
		t.Fatal(err)
	}
}

func pruneUIDServe(t *testing.T, ctx context.Context, owner *service.Owner, socket, ready string) func() {
	t.Helper()
	run, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	listening := make(chan error, 1)
	go func() {
		done <- service.Serve(run, owner, socket, func(id types.Hash) error {
			raw, err := json.Marshal(id)
			if err == nil {
				err = os.WriteFile(ready, raw, 0644)
			}
			listening <- err
			return err
		})
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("Serve", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not drain")
		}
	}
	t.Cleanup(stop)
	select {
	case err := <-listening:
		if err != nil {
			t.Fatal("publish listening stage", err)
		}
	case err := <-done:
		stopped = true
		cancel()
		t.Fatal("Serve ended before listening", err)
	case <-ctx.Done():
		t.Fatal("Serve listening deadline", ctx.Err())
	}
	return stop
}

func pruneUIDObligations(t testing.TB, f *pruneServiceOwnerCLIFixture) []store.Coordination {
	t.Helper()
	var snapshots []store.Coordination
	for _, replica := range f.inventory.Replicas {
		aid, _ := replica.Assignment.ID()
		for _, root := range f.config.Runtime.Authorities {
			if root.AssignmentID != aid {
				continue
			}
			owner, err := store.OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, replica.Assignment, aid)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := owner.Snapshot()
			closeErr := owner.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			snapshots = append(snapshots, snapshot)
		}
	}
	if len(snapshots) != len(f.inventory.Replicas) {
		t.Fatal("missing original authority")
	}
	return snapshots
}

func pruneUIDCheckStorageEffect(t testing.TB, f *pruneServiceOwnerCLIFixture, response *wire.Response) {
	t.Helper()
	c := f.config.Runtime
	chain, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(c.ChainPath, c.ChainPinsPath, c.Base, c.Parameters, c.StoragePolicy, f.inventory.Request.StorageID, c.StorageMigrationID)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	var ticket types.Hash
	for _, r := range f.inventory.Replicas {
		aid, _ := r.Assignment.ID()
		if aid == f.inventory.Request.AssignmentID {
			ticket, _ = r.Admission.ID()
		}
	}
	if ticket.IsZero() {
		t.Fatal("missing original primary ticket")
	}
	effect, found, err := chain.CanonicalPruneEffect(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if response == nil {
		if found {
			t.Fatal("disconnect performed a storage effect")
		}
		return
	}
	if !found {
		t.Fatal("response lacks retained storage effect")
	}
	actual, _ := effect.ID()
	want, _ := response.Effect.ID()
	if actual != want {
		t.Fatal("response changed actual effect")
	}
	floor, err := chain.CanonicalFloor()
	if err != nil || !floor.Pruned || floor.PruneTicketID != ticket {
		t.Fatal("actual canonical floor not pruned", err)
	}
}

func pruneUIDReplayOwner(t *testing.T, ctx context.Context, public, control, mode string) {
	if os.Geteuid() != pruneProcessOwnerUID {
		t.Fatal("replay owner UID")
	}
	m := pruneReadProcessManifest(t, public)
	d, q := pruneDecodeProcessManifest(t, m)
	did, _ := d.ID()
	// Unqualified stale initial cursors never reopen an already retained attempt.
	if bad, err := service.Open(ctx, m.Root, did, wire.Position{}, nil); err == nil {
		bad.Close()
		t.Fatal("stale cursor reopened owner")
	}
	owner, err := service.Open(ctx, m.Root, did, m.Position, &q)
	if err != nil {
		t.Fatal("cold owner", err)
	}
	defer owner.Close()
	stop := pruneUIDServe(t, ctx, owner, m.Socket, filepath.Join(public, "ready-replay"))
	if err = pruneWaitMarker(ctx, filepath.Join(control, "stop-replay")); err != nil {
		t.Fatal(err)
	}
	stop()
	snapshot, err := owner.Snapshot()
	if err != nil || snapshot.Position != m.Position {
		t.Fatal("replay moved retained cursor", err)
	}
	if mode == "held" {
		if snapshot.Response != nil {
			t.Fatal("held retry manufactured result")
		}
		if _, err = owner.Execute(ctx, q, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
			t.Error("held retry requested another signature")
			return custodyfence.Command{}, io.ErrUnexpectedEOF
		}); !errors.Is(err, service.ErrHeld) {
			t.Fatal("held retry was not refused", err)
		}
	}
}

func pruneUIDParticipant(t *testing.T, ctx context.Context, public, mode string, replay bool) {
	if os.Geteuid() != pruneProcessParticipantUID {
		t.Fatal("participant UID")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatal("participant inherited supplementary groups", groups, err)
	}
	m := pruneReadProcessManifest(t, public)
	d, q := pruneDecodeProcessManifest(t, m)
	if !replay {
		if len(m.PrivatePaths) < 8 {
			t.Fatal("missing private isolation probes")
		}
		for _, path := range m.PrivatePaths {
			file, err := os.Open(path)
			if err == nil {
				file.Close()
				t.Fatal("participant opened original private placement", path)
			}
			if !errors.Is(err, fs.ErrPermission) {
				t.Fatal("private placement was not denied by kernel", path, err)
			}
		}
	}
	calls := 0
	disconnected := errors.New("participant disconnected before approval")
	callContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	response, err := serviceclient.Call(callContext, m.Socket, d, q, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		calls++
		if replay {
			return custodyfence.Command{}, errors.New("cold replay asked for a new signature")
		}
		if mode == "held" {
			return custodyfence.Command{}, disconnected
		}
		_, draft, e := ch.Candidate.Draft()
		if e != nil {
			return draft, e
		}
		return draft.Sign(pruneCLIKey(4))
	})
	if mode == "held" {
		if replay {
			if err == nil || calls != 0 {
				t.Fatal("held retry executed", err, calls)
			}
		} else if !errors.Is(err, disconnected) || calls != 1 {
			t.Fatal("disconnect did not stop approval", err, calls)
		}
		return
	}
	if err != nil {
		t.Fatal("participant exchange", err)
	}
	wantCalls := 1
	if replay {
		wantCalls = 0
	}
	if calls != wantCalls {
		t.Fatal("unexpected approval count", calls)
	}
	if err = response.Verify(d, q); err != nil {
		t.Fatal(err)
	}
	raw, err := response.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	path := "original-response"
	if replay {
		before, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, raw) {
			t.Fatal("cold replay changed exact signed response", err)
		}
	} else if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
