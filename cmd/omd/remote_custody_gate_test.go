//go:build integration && (darwin || linux)

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// This helper is deliberately reachable only through an explicitly selected
// integration test and private fixture argv. It is not a production command or
// an authority delegation mechanism. The same original B owner is retained.
func TestRemoteCustodyGatedServeHelper(t *testing.T) {
	path := os.Getenv("OMESH_REMOTE_GATE_ARGS")
	if path == "" {
		t.Skip("standalone remote acceptance helper")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || len(b) > 128<<10 {
		t.Fatal("remote gate requires a bounded fixture argv array")
	}
	var arguments []string
	if err := json.Unmarshal(b, &arguments); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	options, err := loadManagedCustodyServeOptions(ctx, arguments)
	if err != nil {
		t.Fatal(err)
	}
	if err := runRemoteCustodyGatedServe(ctx, options, os.Stdin, os.Stdout); err != nil {
		t.Fatal(err)
	}
}

type remoteCustodyResponseGate struct {
	mu       sync.Mutex
	once     sync.Once
	waiting  bool
	released bool
	release  chan struct{}
	timeout  time.Duration
	output   io.Writer
	cancel   context.CancelFunc
	failure  error
}

// Inherited descriptors 0/1 are not necessarily registered with Go's poller.
// Private nonblocking reads/writes make signal cancellation interruptible
// without adopting or changing the production control protocol.
type remoteCustodyGatePipe struct {
	file *os.File
	fd   int
	ctx  context.Context
}

func newRemoteCustodyGatePipe(ctx context.Context, value any) (*remoteCustodyGatePipe, error) {
	file, ok := value.(*os.File)
	if !ok {
		return nil, errors.New("remote gate requires standalone inherited pipes")
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return nil, errors.Join(errors.New("remote gate requires dedicated pipes"), err)
	}
	fd := int(file.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	return &remoteCustodyGatePipe{file: file, fd: fd, ctx: ctx}, nil
}

func (pipe *remoteCustodyGatePipe) wait() error {
	select {
	case <-pipe.ctx.Done():
		return pipe.ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return nil
	}
}

func (pipe *remoteCustodyGatePipe) Read(b []byte) (int, error) {
	for {
		if err := pipe.ctx.Err(); err != nil {
			return 0, err
		}
		n, err := syscall.Read(pipe.fd, b)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			if err := pipe.wait(); err != nil {
				return 0, err
			}
			continue
		}
		if n == 0 && err == nil {
			return 0, io.EOF
		}
		return n, err
	}
}

func (pipe *remoteCustodyGatePipe) Write(b []byte) (int, error) {
	for {
		if err := pipe.ctx.Err(); err != nil {
			return 0, err
		}
		n, err := syscall.Write(pipe.fd, b)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			if err := pipe.wait(); err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func (pipe *remoteCustodyGatePipe) Close() error { return pipe.file.Close() }

func (gate *remoteCustodyResponseGate) fail(err error) {
	// Interrupt a blocked marker write before waiting for its state mutex.
	gate.cancel()
	gate.mu.Lock()
	gate.failure = errors.Join(gate.failure, err)
	gate.mu.Unlock()
}

func (gate *remoteCustodyResponseGate) beforeWrite(ctx context.Context) error {
	selected := false
	gate.once.Do(func() { selected = true })
	if !selected {
		return ctx.Err()
	}
	// A blocked output or controller cannot retain the owner indefinitely.
	timerDone := make(chan struct{})
	timer := time.AfterFunc(gate.timeout, func() {
		defer close(timerDone)
		gate.fail(errors.New("remote response gate release deadline exceeded"))
	})
	defer func() {
		if !timer.Stop() {
			<-timerDone
		}
	}()
	gate.mu.Lock()
	err := writePruneOutputLine(gate.output, "remote_custody_gate phase=before_first_response journal_committed=true\n")
	if err == nil {
		gate.waiting = true
	}
	gate.mu.Unlock()
	if err != nil {
		gate.fail(err)
		return err
	}
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-gate.release:
		err = ctx.Err()
	}
	gate.mu.Lock()
	gate.waiting = false
	gate.mu.Unlock()
	return err
}

func (gate *remoteCustodyResponseGate) releaseFirst() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !gate.waiting || gate.released {
		return errors.New("release requires the reported first-response gate")
	}
	gate.released = true
	close(gate.release)
	return nil
}

func (gate *remoteCustodyResponseGate) result() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.failure
}

// Embedding network.Stream preserves CloseWrite and the full finite-stream
// contract. Lower Serve calls Write only after durable journal publication.
type remoteCustodyGatedStream struct {
	network.Stream
	ctx       context.Context
	gate      *remoteCustodyResponseGate
	closeOnce sync.Once
	closeErr  error
}

func (stream *remoteCustodyGatedStream) Write(b []byte) (int, error) {
	if err := stream.gate.beforeWrite(stream.ctx); err != nil {
		return 0, err
	}
	return stream.Stream.Write(b)
}

func (stream *remoteCustodyGatedStream) Close() error {
	stream.closeOnce.Do(func() { stream.closeErr = stream.Stream.Close() })
	return stream.closeErr
}

func runRemoteCustodyGatedServe(parent context.Context, options managedCustodyServeOptions, input io.ReadCloser, output io.WriteCloser) (returnErr error) {
	if parent == nil || input == nil || output == nil || options.mode != "serve" ||
		options.config.Session.SessionConfig.RequestTimeout <= 0 || options.config.Session.SessionConfig.RequestTimeout > 30*time.Second {
		return errors.New("remote gate requires serve mode, owned pipes and a timeout no greater than 30s")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ownedInput, err := newRemoteCustodyGatePipe(ctx, input)
	if err != nil {
		return err
	}
	ownedOutput, err := newRemoteCustodyGatePipe(ctx, output)
	if err != nil {
		return err
	}
	input, output = ownedInput, ownedOutput
	c := options.config
	owner, err := authoritystore.OpenCoordinator(c.AuthorityPath, c.AuthorityPinsPath, c.Assignment, c.Session.AssignmentID)
	if err != nil {
		return err
	}
	// Cleanup order is fixed: stop callback admission, cancel/close the host,
	// drain accepted handlers and control I/O, then release the original owner.
	var host *libp2ptransport.Host
	var admission sync.Mutex
	var accepted sync.WaitGroup
	accepting := false
	var controlDone chan struct{}
	var handlerFailure sync.Mutex
	var cleanupErr error
	var gate *remoteCustodyResponseGate
	defer func() {
		admission.Lock()
		accepting = false
		admission.Unlock()
		cancel()
		if host != nil {
			returnErr = errors.Join(returnErr, host.Close())
		}
		accepted.Wait()
		if controlDone != nil {
			<-controlDone
		}
		returnErr = errors.Join(returnErr, input.Close(), output.Close())
		handlerFailure.Lock()
		returnErr = errors.Join(returnErr, cleanupErr)
		handlerFailure.Unlock()
		if gate != nil {
			returnErr = errors.Join(returnErr, gate.result())
		}
		returnErr = errors.Join(returnErr, owner.Close())
	}()
	objects, err := workarchive.OpenExistingObjectStoreContext(ctx, c.ObjectPath, c.ObjectPolicy)
	if err != nil {
		return err
	}
	missing, err := objects.Missing(c.Session.Manifest)
	if err != nil || len(missing) != 0 {
		return errors.Join(errors.New("remote gate object scope is incomplete"), err)
	}
	c.Session.Objects = objects
	session, err := authoritystore.NewManagedCustodyServeSession(ctx, owner, c.Session)
	if err != nil {
		return err
	}
	gate = &remoteCustodyResponseGate{release: make(chan struct{}), timeout: c.Session.SessionConfig.RequestTimeout, output: output, cancel: cancel}
	terminal := make(chan error, 1)
	controlDone = make(chan struct{})
	go func() {
		defer close(controlDone)
		defer cancel()
		reader := bufio.NewReaderSize(input, 64)
		for {
			line, err := reader.ReadSlice('\n')
			if ctx.Err() != nil {
				terminal <- nil
				return
			}
			if errors.Is(err, io.EOF) && len(line) == 0 {
				terminal <- nil
				return
			}
			if err != nil {
				terminal <- errors.Join(errors.New("remote gate controls require a bounded complete LF-terminated line"), err)
				return
			}
			switch string(line) {
			case "release\n":
				if err := gate.releaseFirst(); err != nil {
					terminal <- err
					return
				}
			case "close\n":
				terminal <- nil
				return
			default:
				terminal <- errors.New("remote gate accepts only release or close followed by LF")
				return
			}
		}
	}()
	transportConfig := libp2ptransport.DefaultConfig()
	transportConfig.Listen = []string{options.listen}
	host, err = libp2ptransport.New(ctx, options.transportKey, transportConfig, nil)
	if err != nil {
		return err
	}
	if host.ID() != c.ServerPeerID {
		return errors.New("remote gate transport differs from pinned server")
	}
	if err := host.SetArchiveCustodyHandler([]types.Hash{c.Session.AuditorPeerID}, func(_ context.Context, peer types.Hash, stream network.Stream) {
		admission.Lock()
		if !accepting || ctx.Err() != nil {
			admission.Unlock()
			_ = stream.Reset()
			return
		}
		accepted.Add(1)
		admission.Unlock()
		defer accepted.Done()
		owned := &remoteCustodyGatedStream{Stream: stream, ctx: ctx, gate: gate}
		_, serveErr := session.Serve(ctx, peer, owned)
		if closeErr := owned.Close(); closeErr != nil {
			handlerFailure.Lock()
			cleanupErr = errors.Join(cleanupErr, closeErr)
			handlerFailure.Unlock()
			cancel()
		}
		if errors.Is(serveErr, authoritystore.ErrUncertain) {
			gate.fail(serveErr)
		}
	}); err != nil {
		return err
	}
	admission.Lock()
	accepting = true
	admission.Unlock()
	addresses := host.Addresses()
	if len(addresses) == 0 {
		return errors.New("remote gate requires a direct QUIC address")
	}
	if err := writePruneOutputLine(output, fmt.Sprintf("remote_custody_gate_ready listen=%s\n", addresses[0])); err != nil {
		return err
	}
	select {
	case controlErr := <-terminal:
		returnErr = controlErr
	case <-ctx.Done():
		select {
		case controlErr := <-terminal:
			returnErr = controlErr
		default:
		}
	}
	return returnErr
}

func startRemoteCustodyGateProcess(t testing.TB, f *managedCustodyServeCLIFixture) (*pruneEffectProcess, string) {
	t.Helper()
	arguments, err := json.Marshal(f.args("serve"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gate-argv.json")
	writePruneCLIFile(t, path, arguments)
	command := exec.Command(os.Args[0], "-test.run=^TestRemoteCustodyGatedServeHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "OMESH_REMOTE_GATE_ARGS="+path)
	p := &pruneEffectProcess{command: command, lines: make(chan string), done: make(chan struct{}), readerDone: make(chan struct{}), stopReader: make(chan struct{})}
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
			_ = command.Process.Kill()
			<-p.done
		}
		p.stopOnce.Do(func() { close(p.stopReader); _ = p.output.Close() })
		_ = p.input.Close()
		<-p.readerDone
	})
	ready := outputFields(p.line(t), "remote_custody_gate_ready")
	if ready["listen"] == "" {
		t.Fatal("missing gated server address", ready)
	}
	return p, ready["listen"]
}

type remoteCustodyGateAuditResult struct {
	response workarchive.CustodyResponse
	err      error
}

func startRemoteCustodyGateAudit(t testing.TB, f *managedCustodyServeCLIFixture, address string) <-chan remoteCustodyGateAuditResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	client, err := libp2ptransport.New(ctx, pruneCLIKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	stream, peer, err := client.OpenArchiveCustodyStream(ctx, address, f.config.ServerPeerID)
	if err != nil || peer != f.config.ServerPeerID {
		t.Fatal("open gated replica", err)
	}
	s := f.config.Session
	auditor, err := workarchive.NewCustodyAuditorSession(s.Manifest, s.InitialReceipt, s.CustodyPolicy, s.SessionConfig)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan remoteCustodyGateAuditResult, 1)
	go func() {
		response, _, err := auditor.Audit(ctx, stream, f.challenge)
		_ = client.Close()
		result <- remoteCustodyGateAuditResult{response: response, err: err}
	}()
	return result
}

func TestRemoteCustodyGatedServeLoopback(t *testing.T) {
	f := newManagedCustodyServeCLIFixture(t)
	before := f.snapshot(t)
	p, address := startRemoteCustodyGateProcess(t, f)
	first := startRemoteCustodyGateAudit(t, f, address)
	if fields := outputFields(p.line(t), "remote_custody_gate"); fields["phase"] != "before_first_response" || fields["journal_committed"] != "true" {
		t.Fatal("gate was not at committed response boundary", fields)
	}
	f.assertBusy(t)
	select {
	case result := <-first:
		t.Fatal("response escaped unreleased gate", result.err)
	case <-time.After(20 * time.Millisecond):
	}
	// Cancel after durable publication without delivering any response byte.
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal("gated cancellation did not drain", err, p.stderr.String())
	}
	if result := <-first; result.err == nil {
		t.Fatal("cancelled gate acknowledged delivery")
	}
	head, exists, err := f.journal.Head()
	if err != nil || !exists || head.Sequence != 1 {
		t.Fatal("first write gate preceded durable commit", head.Sequence, err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("gated cancellation changed authority")
	}
	// The same original owner and journal reopen; only the retained exact
	// response may be released. No authority attempt is resumed or completed.
	p, address = startRemoteCustodyGateProcess(t, f)
	second := startRemoteCustodyGateAudit(t, f, address)
	fields := outputFields(p.line(t), "remote_custody_gate")
	if fields["journal_committed"] != "true" {
		t.Fatal(fields)
	}
	f.assertBusy(t)
	p.send(t, "release")
	result := <-second
	if result.err != nil || result.response.RenewedReceipt != head.Record.RenewedReceipt || !reflect.DeepEqual(result.response.Proof, head.Record.Proof) || !reflect.DeepEqual(result.response.Batch, head.Record.Batch) {
		t.Fatal("reopened gate refreshed its retained response", result.err)
	}
	p.send(t, "close")
	if err := p.wait(t); err != nil {
		t.Fatal("released gate did not drain", err, p.stderr.String())
	}
	state, err := f.journal.State()
	if err != nil || state.Sequence != 1 || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("gate recovery repeated journal or authority transition", state.Sequence, err)
	}
}

func TestRemoteCustodyGatedServeControl(t *testing.T) {
	for _, command := range []string{"release", "wrong", "partial", "eof", "sigterm"} {
		t.Run(command, func(t *testing.T) {
			f := newManagedCustodyServeCLIFixture(t)
			before := f.snapshot(t)
			p, _ := startRemoteCustodyGateProcess(t, f)
			f.assertBusy(t)
			switch command {
			case "partial":
				_, _ = io.WriteString(p.input, "release")
				_ = p.input.Close()
			case "eof":
				_ = p.input.Close()
			case "sigterm":
				if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			default:
				p.send(t, command)
			}
			err := p.wait(t)
			if (command == "eof" || command == "sigterm") != (err == nil) {
				t.Fatal("control outcome was not fail-closed", command, err, p.stderr.String())
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("control changed original authority")
			}
			state, err := f.journal.State()
			if err != nil || state.Sequence != 0 {
				t.Fatal("control signed a response", state.Sequence, err)
			}
		})
	}
}
