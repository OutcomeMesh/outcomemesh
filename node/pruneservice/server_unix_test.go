//go:build linux || darwin

package pruneservice

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

//go:embed serviceclient/testdata/public_exchange.json
var pruneServerPublicExchange []byte

type pruneTestDuplex struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (d *pruneTestDuplex) Read(p []byte) (int, error)  { return d.in.Read(p) }
func (d *pruneTestDuplex) Write(p []byte) (int, error) { return d.out.Write(p) }

type pruneUnusedGuard struct{}

func (pruneUnusedGuard) Choose(context.Context, guardwire.Request) ([64]byte, error) {
	return [64]byte{}, errors.New("transport fixture cannot consume storage")
}

func pruneTransportFixture(t *testing.T) (wire.Descriptor, wire.Request, wire.Challenge, custodyfence.Command) {
	t.Helper()
	e, err := (prunefence.ServiceEnrollment{AssignmentID: f.Hash("assignment"), ScheduleID: f.Hash("schedule"), StorageID: f.Hash("storage"), StoragePairID: f.Hash("pair"), Service: f.Public(90), Issuer: f.Public(91), Guard: f.Public(92)}).Sign(f.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	d := wire.Descriptor{RootID: f.Hash("root"), ScopeID: f.Hash("scope"), ReviewID: f.Hash("review"), ConfigID: f.Hash("config"),
		Policy:  prunefence.Policy{Owner: f.Public(1), Controller: f.Public(2), Guard: f.Public(80), Threshold: 3, Witnesses: f.Scope().Witnesses, Service: &e},
		Binding: prunefence.Binding{AssignmentID: e.AssignmentID, RequestID: f.Hash("request"), OperationID: f.Hash("operation"), InventoryID: f.Hash("inventory"), ExecutorBindingID: f.Hash("executor"), StoragePairID: e.StoragePairID}, Transport: f.Public(93), OwnerUID: 101, ParticipantUID: 102}
	d, err = d.Sign(f.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	did, _ := d.ID()
	q, err := (wire.Request{DescriptorID: did, Nonce: [32]byte(f.Hash("nonce"))}).Sign(f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := prunefence.NewServiceIdentity(e, f.Key(90), pruneUnusedGuard{})
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	session, err := identity.NewSession(t.Context(), d.Policy, d.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	candidate, err := session.Candidate()
	if err != nil {
		t.Fatal(err)
	}
	qid, _ := q.ID()
	before, _ := q.IntentPosition()
	challenge, err := (wire.Challenge{DescriptorID: did, RequestID: qid, Before: before, Candidate: candidate}).Sign(d, q, f.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	_, command, err := candidate.Draft()
	if err != nil {
		t.Fatal(err)
	}
	command, err = command.Sign(f.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	return d, q, challenge, command
}

func TestPruneServerApprovalRequiresCompleteEOFBeforeReturningCommand(t *testing.T) {
	d, q, challenge, command := pruneTransportFixture(t)
	requestRaw, _ := q.CanonicalBytes()
	approvalRaw, _ := command.CanonicalBytes()
	finished := errors.New("mock owner received approval")
	for _, mode := range []string{"valid", "extra-byte", "second-frame", "truncated", "wrong-kind", "missing"} {
		t.Run(mode, func(t *testing.T) {
			var input bytes.Buffer
			if err := wire.WriteFrame(&input, wire.RequestFrame, requestRaw); err != nil {
				t.Fatal(err)
			}
			kind := uint8(wire.ApprovalFrame)
			if mode == "wrong-kind" {
				kind = wire.ResponseFrame
			}
			if mode != "missing" {
				if err := wire.WriteFrame(&input, kind, approvalRaw); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "extra-byte" {
				input.WriteByte(0)
			}
			if mode == "second-frame" {
				if err := wire.WriteFrame(&input, wire.ApprovalFrame, approvalRaw); err != nil {
					t.Fatal(err)
				}
			}
			raw := input.Bytes()
			if mode == "truncated" {
				raw = raw[:len(raw)-1]
			}
			stream := &pruneTestDuplex{in: bytes.NewReader(raw)}
			received := false
			err := exchangePruneRequest(t.Context(), stream, d, func(ctx context.Context, request wire.Request, approve func(context.Context, wire.Challenge) (custodyfence.Command, error)) (wire.Response, error) {
				if request != q {
					t.Fatal("server substituted signed request")
				}
				got, err := approve(ctx, challenge)
				if err != nil {
					return wire.Response{}, err
				}
				received = true
				if got != command {
					t.Fatal("server substituted signed approval")
				}
				return wire.Response{}, finished
			})
			if mode == "valid" {
				if !received || !errors.Is(err, finished) {
					t.Fatal("complete approval refused", err)
				}
			} else if received || err == nil {
				t.Fatal("incomplete or trailing input escaped to execution", err)
			}
			kind, raw, err = wire.ReadFrame(&stream.out)
			if err != nil || kind != wire.ChallengeFrame {
				t.Fatal("missing challenge", err)
			}
			got, err := wire.DecodeChallenge(raw)
			if err != nil || got.Verify(d, q) != nil || wire.RequireEOF(&stream.out) != nil {
				t.Fatal("challenge did not match original signed request", err)
			}
		})
	}
}

func TestPruneServerRejectsUnexpectedFrameBeforePayload(t *testing.T) {
	for _, kind := range []uint8{wire.RequestFrame, wire.ResponseFrame, wire.ChallengeFrame, 255} {
		var head [5]byte
		head[0] = kind
		binary.BigEndian.PutUint32(head[1:], 1<<30)
		r := bytes.NewReader(append(head[:], 99))
		if _, err := readPruneInput(r, wire.RequestFrame, wire.RequestBytes); !errors.Is(err, wire.ErrArtifact) || r.Len() != 1 {
			t.Fatal("invalid frame consumed payload", err, r.Len())
		}
	}
	if _, err := readPruneInput(bytes.NewReader([]byte{1, 0}), wire.RequestFrame, wire.RequestBytes); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("truncated header accepted", err)
	}
}

func TestPruneServerReplayRespondsBeforeWaitingForEOF(t *testing.T) {
	var artifacts [][]byte
	if err := json.Unmarshal(pruneServerPublicExchange, &artifacts); err != nil || len(artifacts) != 5 {
		t.Fatal("invalid public exchange fixture", err)
	}
	d, err := wire.DecodeDescriptor(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.DecodeRequest(artifacts[1])
	if err != nil {
		t.Fatal(err)
	}
	r, err := wire.DecodeResponse(artifacts[3])
	if err != nil || r.Verify(d, q) != nil {
		t.Fatal("invalid retained response", err)
	}
	for _, trailing := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "trailing"}[trailing], func(t *testing.T) {
			path := filepath.Join(pruneSocketTestDirectory(t), "exchange.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					done <- err
					return
				}
				done <- exchangePruneRequest(t.Context(), conn, d, func(_ context.Context, got wire.Request, _ func(context.Context, wire.Challenge) (custodyfence.Command, error)) (wire.Response, error) {
					if got != q {
						return wire.Response{}, wire.ErrArtifact
					}
					return r, nil
				})
			}()
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := wire.WriteFrame(conn, wire.RequestFrame, artifacts[1]); err != nil {
				t.Fatal(err)
			}
			kind, raw, err := wire.ReadFrame(conn)
			if err != nil || kind != wire.ResponseFrame || !bytes.Equal(raw, artifacts[3]) {
				t.Fatal("replay waited for another approval or premature EOF", err)
			}
			if trailing {
				if _, err := conn.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; (err != nil) != trailing {
				t.Fatal("incorrect replay input boundary", err)
			}
			if err := wire.RequireEOF(conn); err != nil {
				t.Fatal("unexpected replay output", err)
			}
		})
	}
}

func pruneSocketTestDirectory(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "omps-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPruneSocketIdentityAndExplicitInactiveCleanup(t *testing.T) {
	dir := pruneSocketTestDirectory(t)
	path := filepath.Join(dir, "service.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = l.Close() })
	id, err := SocketID(path)
	if err != nil || id.IsZero() {
		t.Fatal(err)
	}
	if err := CleanupSocket(path, id); err == nil {
		t.Fatal("active socket removed")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if again, err := SocketID(path); err != nil || again != id {
		t.Fatal("closing listener changed retained identity", err)
	}
	if err := CleanupSocket(path, f.Hash("unreviewed-socket")); err == nil {
		t.Fatal("unreviewed socket removed")
	}
	if !gatewayclient.Supported() {
		if err := CleanupSocket(path, id); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsupported cleanup accepted", err)
		}
		if err := Serve(t.Context(), nil, path, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsupported credentials accepted", err)
		}
		return
	}
	if err := CleanupSocket(path, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("stale socket remains", err)
	}
}

func TestPruneSocketRejectsSubstitutionAndUnsafeParents(t *testing.T) {
	dir := pruneSocketTestDirectory(t)
	path := filepath.Join(dir, "service.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	id, err := SocketID(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := os.Rename(path, filepath.Join(dir, "original.sock")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := SocketID(path); err == nil || CleanupSocket(path, id) == nil {
		t.Fatal("regular file substituted for reviewed socket")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "original.sock"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := SocketID(path); err == nil {
		t.Fatal("socket symlink accepted")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := checkPruneSocketParent(filepath.Join(dir, "another.sock")); err == nil {
		t.Fatal("writable socket parent accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkPruneSocketParent("relative.sock"); err == nil {
		t.Fatal("relative socket path accepted")
	}
	if err := checkPruneSocketParent(dir + "/../service.sock"); err == nil {
		t.Fatal("unclean socket path accepted")
	}
}
