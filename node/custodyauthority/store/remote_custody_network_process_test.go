//go:build integration

package store

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// This private fixture contains only B's public scope, original local paths and
// B-specific keys. It has no A authority/pin path, A control key or A signer.
// SessionConfig.Now is reconstructed explicitly rather than JSON-marshalling a
// function. The fixture file is never printed by the child or controller.
type remoteNetworkProcessConfig struct {
	Scope                                                     RemoteCustodyScope
	WorkerPath, JournalPath, ObjectPath                       string
	ObjectPolicy                                              workarchive.ObjectStorePolicy
	JournalLimits                                             workarchive.CustodyJournalLimits
	ReplicaPrivateKey, ControlPrivateKey, TransportPrivateKey ed25519.PrivateKey
	Timeout                                                   time.Duration
	Now                                                       uint64
	PauseBeforeResponse                                       bool
	PauseStage                                                string
	Listen                                                    []string
	Marker                                                    string
}

type remoteNetworkProcess struct {
	command                      *exec.Cmd
	input                        io.WriteCloser
	output                       io.ReadCloser
	lines                        chan string
	done, readerDone, stopReader chan struct{}
	stderr                       bytes.Buffer
	err                          error // read only after done
}

func startRemoteNetworkProcess(t testing.TB, f *remoteExecutionFixture, pause bool) (*remoteNetworkProcess, string, string) {
	t.Helper()
	c := f.serveConfig()
	marker := filepath.Join(t.TempDir(), "response-committed")
	fixture := remoteNetworkProcessConfig{Scope: c.Scope, WorkerPath: c.WorkerPath, JournalPath: c.JournalPath, ObjectPath: c.ObjectPath,
		ObjectPolicy: c.ObjectPolicy, JournalLimits: c.JournalLimits, ReplicaPrivateKey: c.ReplicaPrivateKey, ControlPrivateKey: c.ControlPrivateKey,
		TransportPrivateKey: testKey(15), Timeout: 5 * time.Second, Now: f.base.serve.now, PauseBeforeResponse: pause, Marker: marker}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "b-process.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRemoteCustodyNetworkProcessHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OMESH_REMOTE_NETWORK_PROCESS_CONFIG="+path)
	p := &remoteNetworkProcess{command: command, lines: make(chan string, 64), done: make(chan struct{}), readerDone: make(chan struct{}), stopReader: make(chan struct{})}
	p.input, err = command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.output, err = command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = &p.stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.readerDone)
		defer close(p.lines)
		reader := bufio.NewReader(p.output)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			select {
			case p.lines <- line:
			case <-p.stopReader:
				return
			}
		}
	}()
	go func() { p.err = command.Wait(); close(p.done) }()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = p.command.Process.Kill()
			<-p.done
		}
		_ = p.input.Close()
		close(p.stopReader)
		_ = p.output.Close()
		<-p.readerDone
	})
	select {
	case line := <-p.lines:
		address, ok := strings.CutPrefix(line, "remote_custody_process_ready address=")
		if !ok || strings.TrimSpace(address) == "" {
			t.Fatal("unexpected B readiness", line)
		}
		return p, strings.TrimSpace(address), marker
	case <-p.done:
		t.Fatal("B process exited before readiness", p.err, p.stderr.String())
	case <-time.After(15 * time.Second):
		t.Fatal("B process readiness timed out")
	}
	return nil, "", ""
}

func (p *remoteNetworkProcess) kill(t testing.TB) {
	t.Helper()
	if err := p.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
		if p.err == nil {
			t.Fatal("B was not terminated by process kill")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("killed B process was not reaped")
	}
}

func (p *remoteNetworkProcess) close(t testing.TB) {
	t.Helper()
	if _, err := io.WriteString(p.input, "close\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatal("B close failed", p.err, p.stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("B did not drain before close")
	}
}

func waitRemoteNetworkMarker(t testing.TB, p *remoteNetworkProcess, marker string) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		select {
		case <-p.done:
			t.Fatal("B exited before its committed response gate", p.err, p.stderr.String())
		case <-deadline.C:
			t.Fatal("B did not reach committed first-response gate")
		case <-ticker.C:
		}
	}
}

func remoteNetworkAssertWorker(t testing.TB, f *remoteExecutionFixture, stage remoteworker.Stage) {
	t.Helper()
	worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	state, err := worker.Snapshot(t.Context())
	closeErr := worker.Close()
	if err != nil || closeErr != nil || state.Stage != stage || state.Pending != 0 {
		t.Fatal("unexpected retained B stage", state, err, closeErr)
	}
}

func TestRemoteCustodyNetworkProcessRecovery(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := map[bool]string{false: "started_without_result", true: "committed_before_response"}[committed]
		t.Run(name, func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := f.auditConfig(t)
			config.Audit.SessionConfig.RequestTimeout = 5 * time.Second
			a, err := OpenRemoteCustodyAuditRuntime(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			if _, err := a.PrepareChallenge(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Begin(t.Context()); err != nil {
				t.Fatal(err)
			}
			p, address, marker := startRemoteNetworkProcess(t, f, committed)
			lockPaths := []string{filepath.Join(f.workerPath, "worker.lock"), filepath.Join(f.serveConfig().JournalPath, "journal.lock")}
			identities := make(map[string]os.FileInfo)
			for _, path := range lockPaths {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				identities[path] = info
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			if committed {
				executed := make(chan error, 1)
				go func() {
					_, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address)
					executed <- err
				}()
				waitRemoteNetworkMarker(t, p, marker)
				if worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker); !errors.Is(err, remoteworker.ErrBusy) {
					if worker != nil {
						_ = worker.Close()
					}
					t.Fatal("B released original worker before response", err)
				}
				p.kill(t)
				if err := <-executed; err == nil {
					t.Fatal("B process death acknowledged an undelivered response")
				}
			} else {
				injected := errors.New("stop after authenticated Start and before data")
				a.hooks.at = func(stage string) error {
					if stage == "remote-audit-start-confirmed" {
						return injected
					}
					return nil
				}
				if _, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); !errors.Is(err, injected) {
					t.Fatal("did not stop before data", err)
				}
				a.hooks = storeHooks{}
				p.kill(t)
			}
			for path, before := range identities {
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("process death replaced an original lock inode", path, err)
				}
			}
			remoteNetworkAssertWorker(t, f, remoteworker.Started)
			aState, err := f.base.journal.State()
			if err != nil || aState.Sequence != 0 {
				t.Fatal("A accepted undelivered evidence", aState, err)
			}
			bState, err := f.base.serve.journal.State()
			if err != nil || bState.Sequence != map[bool]uint64{false: 0, true: 1}[committed] {
				t.Fatal("kill boundary changed B source history", bState, err)
			}
			var oldEntry workarchive.CustodyJournalEntry
			var oldBytes []byte
			if committed {
				var exists bool
				oldEntry, exists, err = f.base.serve.journal.Head()
				if err != nil || !exists {
					t.Fatal(exists, err)
				}
				oldBytes, err = oldEntry.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
			}
			before := testCoordination(t, a.life.owner)
			if before.Pending != nil || before.Authority.Remote == nil || before.Authority.Pending != 2 || before.Confirmed.HeadID != f.scope.Worker.BeginID {
				t.Fatal("failed exchange cleared original A hold", before)
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			a, err = OpenRemoteCustodyAuditRuntime(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, a.life.owner)) {
				t.Fatal("A reopen changed durable remote obligation")
			}
			p, address, _ = startRemoteNetworkProcess(t, f, false)
			if !committed {
				if _, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err == nil {
					t.Fatal("restarted Started B minted a fresh proof")
				}
				if current, err := f.base.serve.journal.State(); err != nil || current.Sequence != 0 {
					t.Fatal("reopened Started created B result", current, err)
				}
				reply, err := a.SealQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address)
				if err != nil || reply.Seal.Disposition != remoteworker.NoResult || !reply.Seal.ResultID.IsZero() {
					t.Fatal("unknown crashed start fabricated success", reply, err)
				}
				if _, err := a.CaptureTerminal(ctx, reply); err == nil {
					t.Fatal("unknown crashed result manufactured A terminal")
				}
			} else {
				result, err := a.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address)
				if err != nil || result.JournalSequence != 1 {
					t.Fatal("exact cached recovery failed", result, err)
				}
				newEntry, exists, err := f.base.serve.journal.Head()
				if err != nil || !exists {
					t.Fatal(exists, err)
				}
				newBytes, err := newEntry.CanonicalBytes()
				if err != nil || !bytes.Equal(oldBytes, newBytes) || newEntry.Record.Proof.RespondedAt != oldEntry.Record.Proof.RespondedAt {
					t.Fatal("restart refreshed B response", err)
				}
				aEntry, exists, err := f.base.journal.Head()
				if err != nil || !exists {
					t.Fatal(exists, err)
				}
				accepted, err := aEntry.CanonicalBytes()
				if err != nil || !bytes.Equal(oldBytes, accepted) {
					t.Fatal("A accepted a different body than original committed B entry", err)
				}
				reply, err := a.SealQUIC(ctx, testKey(16), libp2ptransport.DefaultConfig(), address)
				oldID, _ := oldEntry.ID()
				if err != nil || reply.Seal.Disposition != remoteworker.RetainedResult || reply.Seal.ResultID != oldID {
					t.Fatal("drain changed retained result", reply, err)
				}
				terminal, err := a.CaptureTerminal(ctx, reply)
				if err != nil {
					t.Fatal(err)
				}
				if err := terminal.Validate(f.scope); err != nil {
					t.Fatal(err)
				}
				terminalBody, err := terminal.Entry.CanonicalBytes()
				if err != nil || !bytes.Equal(oldBytes, terminalBody) {
					t.Fatal("terminal replaced historical response", err)
				}
			}
			current := testCoordination(t, a.life.owner)
			if current.Pending != nil || current.Authority.Remote != nil || current.Authority.Pending != 2 {
				t.Fatal("explicit drain implicitly completed ordinary tickets", current)
			}
			p.close(t)
			remoteNetworkAssertWorker(t, f, remoteworker.Sealed)
		})
	}
}

func TestRemoteCustodyNetworkProcessHelper(t *testing.T) {
	path := os.Getenv("OMESH_REMOTE_NETWORK_PROCESS_CONFIG")
	if path == "" {
		t.Skip("private B process helper")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture remoteNetworkProcessConfig
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	session := workarchive.DefaultCustodySessionConfig()
	session.RequestTimeout = fixture.Timeout
	if fixture.Now != 0 {
		session.Now = func() uint64 { return fixture.Now }
	}
	service, err := OpenRemoteCustodyServeService(t.Context(), RemoteCustodyServeServiceConfig{Scope: fixture.Scope, WorkerPath: fixture.WorkerPath,
		JournalPath: fixture.JournalPath, ObjectPath: fixture.ObjectPath, ObjectPolicy: fixture.ObjectPolicy, JournalLimits: fixture.JournalLimits,
		ReplicaPrivateKey: fixture.ReplicaPrivateKey, ControlPrivateKey: fixture.ControlPrivateKey, SessionConfig: session})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if fixture.PauseBeforeResponse || fixture.PauseStage != "" {
		stage := fixture.PauseStage
		if stage == "" {
			stage = "remote-data-before-response-write"
		}
		if stage != "remote-data-admitted" && stage != "remote-data-before-response-write" && stage != "remote-control-drained-before-response-write" {
			t.Fatal("unsupported private pause stage")
		}
		service.hooks.at = func(stage string) error {
			if stage == fixture.PauseStage || fixture.PauseStage == "" && stage == "remote-data-before-response-write" {
				if err := os.WriteFile(fixture.Marker, []byte("committed\n"), 0o600); err != nil {
					return err
				}
				select {}
			}
			return nil
		}
	}
	transportConfig := libp2ptransport.DefaultConfig()
	if len(fixture.Listen) != 0 {
		transportConfig.Listen = fixture.Listen
	}
	if err := service.Start(t.Context(), fixture.TransportPrivateKey, transportConfig); err != nil {
		t.Fatal(err)
	}
	addresses := service.Addresses()
	if len(addresses) == 0 {
		t.Fatal("B has no direct address")
	}
	fmt.Printf("remote_custody_process_ready address=%s\n", addresses[0])
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line == "") {
		t.Fatal("B helper requires close followed by LF", err)
	}
	if err == nil && line != "close\n" {
		t.Fatal("B helper accepts only explicit close")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}
