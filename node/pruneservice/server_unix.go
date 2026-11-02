//go:build linux || darwin

package pruneservice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

// The participant may traverse public ancestors but cannot replace the socket
// or any parent. A root-owned sticky temporary directory is the sole exception.
func checkPruneSocketParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return ErrOwner
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return ErrOwner
	}
	for p := parent; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() {
			return ErrOwner
		}
		native, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (native.Uid != uint32(os.Geteuid()) && native.Uid != 0) ||
			(info.Mode().Perm()&0022 != 0 && !(native.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return ErrOwner
		}
		if p == "/" {
			return nil
		}
	}
}

// SocketID identifies only the original socket inode, never owner keys or
// execution history. Symbolic links and sockets owned by another UID are refused.
func SocketID(socket string) (types.Hash, error) {
	if err := checkPruneSocketParent(socket); err != nil {
		return types.Hash{}, err
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return types.Hash{}, ErrOwner
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		return types.Hash{}, ErrOwner
	}
	identity := fmt.Sprintf("%d/%d/%d/%d/%d", native.Dev, native.Ino, native.Uid, info.ModTime().Unix(), info.ModTime().Nanosecond())
	return types.DomainHash(wire.Domain+"socket/id", []byte(socket), []byte(identity)), nil
}

func syncPruneSocketDirectory(socket string) error {
	directory, err := os.Open(filepath.Dir(socket))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

// Serve retains the socket on every exit. Cancellation closes all accepted
// connections, cancels operations and waits for them before returning; the caller
// may close the original Owner only after this drain completes.
func Serve(ctx context.Context, owner *Owner, socket string, ready func(types.Hash) error) error {
	if !gatewayclient.Supported() {
		return ErrUnsupported
	}
	if ctx == nil || owner == nil {
		return ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkPruneSocketParent(socket); err != nil {
		return err
	}
	if err := owner.socketAllowed(socket); err != nil {
		return err
	}
	descriptor := owner.Descriptor()
	if _, err := descriptor.CanonicalBytes(); err != nil || descriptor.OwnerUID != uint32(os.Geteuid()) {
		return wire.ErrAccess
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		return ErrOwner
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	// Access depends on authenticated kernel credentials and signed requests;
	// granting connect permission never grants access to the private owner root.
	if err := os.Chmod(socket, 0666); err != nil {
		return err
	}
	id, err := SocketID(socket)
	if err != nil {
		return err
	}
	if err := syncPruneSocketDirectory(socket); err != nil {
		return err
	}
	run, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	connections := make(map[*net.UnixConn]struct{})
	var wait sync.WaitGroup
	slots := make(chan struct{}, 8)
	stopped := make(chan struct{})
	context.AfterFunc(run, func() {
		_ = listener.Close()
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		close(stopped)
	})
	defer func() {
		cancel()
		<-stopped
		wait.Wait()
	}()
	if ready != nil {
		if err := ready(id); err != nil {
			return err
		}
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if run.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		mu.Lock()
		if run.Err() != nil {
			mu.Unlock()
			<-slots
			_ = conn.Close()
			continue
		}
		connections[conn] = struct{}{}
		mu.Unlock()
		wait.Add(1)
		go func() {
			defer wait.Done()
			defer func() {
				mu.Lock()
				delete(connections, conn)
				mu.Unlock()
				_ = conn.Close()
				<-slots
			}()
			deadline := time.Now().Add(wire.ExchangeDeadline)
			if err := conn.SetDeadline(deadline); err != nil {
				return
			}
			uid, err := gatewayclient.PeerUID(conn)
			if err != nil || uid != descriptor.ParticipantUID {
				return
			}
			operation, stop := context.WithDeadline(run, deadline)
			defer stop()
			cancelled := make(chan struct{})
			closeOnCancel := context.AfterFunc(operation, func() {
				_ = conn.Close()
				close(cancelled)
			})
			defer func() {
				if !closeOnCancel() {
					<-cancelled
				}
			}()
			_ = exchangePruneRequest(operation, conn, descriptor, owner.Execute)
		}()
	}
}

// Only fixed-size inbound request and approval frames are permitted here. Check
// the expected type before allocation, including when a larger public response
// frame would be accepted by the generic wire reader.
func readPruneInput(r io.Reader, kind uint8, size int) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if head[0] != kind || binary.BigEndian.Uint32(head[1:]) != uint32(size) {
		return nil, wire.ErrArtifact
	}
	raw := make([]byte, size)
	_, err := io.ReadFull(r, raw)
	return raw, err
}

type pruneExecute func(context.Context, wire.Request, func(context.Context, wire.Challenge) (custodyfence.Command, error)) (wire.Response, error)

func exchangePruneRequest(ctx context.Context, conn io.ReadWriter, descriptor wire.Descriptor, execute pruneExecute) error {
	raw, err := readPruneInput(conn, wire.RequestFrame, wire.RequestBytes)
	if err != nil {
		return err
	}
	request, err := wire.DecodeRequest(raw)
	if err != nil {
		return err
	}
	if err := request.Authorize(descriptor); err != nil {
		return err
	}
	approved := false
	response, err := execute(ctx, request, func(approvalContext context.Context, challenge wire.Challenge) (custodyfence.Command, error) {
		if approved {
			return custodyfence.Command{}, wire.ErrAccess
		}
		approved = true
		if err := approvalContext.Err(); err != nil {
			return custodyfence.Command{}, err
		}
		if err := challenge.Verify(descriptor, request); err != nil {
			return custodyfence.Command{}, err
		}
		raw, err := challenge.CanonicalBytes()
		if err != nil {
			return custodyfence.Command{}, err
		}
		if err := wire.WriteFrame(conn, wire.ChallengeFrame, raw); err != nil {
			return custodyfence.Command{}, err
		}
		raw, err = readPruneInput(conn, wire.ApprovalFrame, custodyfence.CommandBytes)
		if err != nil {
			return custodyfence.Command{}, err
		}
		command, err := custodyfence.DecodeCommand(raw)
		if err != nil {
			return custodyfence.Command{}, err
		}
		if err := wire.RequireEOF(conn); err != nil {
			return custodyfence.Command{}, err
		}
		return command, approvalContext.Err()
	})
	if err != nil {
		return err
	}
	if err := response.Verify(descriptor, request); err != nil {
		return err
	}
	raw, err = response.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := wire.WriteFrame(conn, wire.ResponseFrame, raw); err != nil {
		return err
	}
	if !approved {
		// Exact replay returns its retained response before waiting for the client
		// to close its sending side; it never asks for another approval.
		return wire.RequireEOF(conn)
	}
	return nil
}

// CleanupSocket removes only the exact reviewed inactive socket. A live socket,
// replacement inode, unexpected dial failure or unconfirmed identity is refused.
func CleanupSocket(socket string, expectedID types.Hash) error {
	if !gatewayclient.Supported() {
		return ErrUnsupported
	}
	if expectedID.IsZero() {
		return ErrOwner
	}
	id, err := SocketID(socket)
	if err != nil || id != expectedID {
		return ErrOwner
	}
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err == nil {
		_ = conn.Close()
		return ErrOwner
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return ErrOwner
	}
	id, err = SocketID(socket)
	if err != nil || id != expectedID {
		return ErrOwner
	}
	if err := os.Remove(socket); err != nil {
		return err
	}
	return syncPruneSocketDirectory(socket)
}
