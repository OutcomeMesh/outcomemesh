//go:build linux || darwin

package custodygateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	client "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
)

// Socket directories are public to traverse but cannot be replaced by clients.
func checkSocketParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return ErrOwner
	}
	parent := filepath.Dir(path)
	r, e := filepath.EvalSymlinks(parent)
	if e != nil || r != parent {
		return ErrOwner
	}
	for p := parent; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() {
			return ErrOwner
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != uint32(os.Geteuid()) && s.Uid != 0 || st.Mode().Perm()&0022 != 0 && !(s.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return ErrOwner
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func SocketID(path string) (types.Hash, error) {
	if e := checkSocketParent(path); e != nil {
		return types.Hash{}, e
	}
	st, e := os.Lstat(path)
	if e != nil || st.Mode()&os.ModeSocket == 0 {
		return types.Hash{}, ErrOwner
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) {
		return types.Hash{}, ErrOwner
	}
	return types.DomainHash(wire.Domain+"socket/id", []byte(path), []byte(st.ModTime().String()), []byte(fmtIdentity(uint64(s.Dev), s.Ino))), nil
}
func fmtIdentity(dev uint64, ino uint64) string { return fmt.Sprintf("%d/%d", dev, ino) }

// Serve never removes an existing socket. The caller owns and closes Owner only
// after Serve has returned and all accepted operations have stopped.
func Serve(ctx context.Context, o *Owner, socket string, ready func(types.Hash) error) error {
	if ctx == nil || o == nil || !client.Supported() {
		return wire.ErrAccess
	}
	if e := checkSocketParent(socket); e != nil {
		return e
	}
	o.mu.Lock()
	e := o.check()
	o.mu.Unlock()
	if e != nil {
		return e
	}
	if _, e = os.Lstat(socket); !os.IsNotExist(e) {
		return ErrOwner
	}
	addr := &net.UnixAddr{Name: socket, Net: "unix"}
	l, e := net.ListenUnix("unix", addr)
	if e != nil {
		return e
	}
	l.SetUnlinkOnClose(false)
	// The socket admits connections; kernel peer UID and a signed ACL request
	// decide access before any operation. The private owner root stays 0700.
	if e = os.Chmod(socket, 0666); e != nil {
		l.Close()
		return e
	}
	id, e := SocketID(socket)
	if e != nil {
		l.Close()
		return e
	}
	defer l.Close()
	if e = syncDir(filepath.Dir(socket)); e != nil {
		return e
	}
	var mu sync.Mutex
	connections := map[*net.UnixConn]struct{}{}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	stop := context.AfterFunc(ctx, func() {
		l.Close()
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
	})
	defer stop()
	defer func() {
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}()
	if ready != nil {
		if e = ready(id); e != nil {
			return e
		}
	}
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		mu.Lock()
		connections[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots; mu.Lock(); delete(connections, c); mu.Unlock(); c.Close() }()
			c.SetDeadline(time.Now().Add(client.Deadline))
			uid, e := client.PeerUID(c)
			if e != nil || uid != o.descriptor.ParticipantUID {
				return
			}
			raw, e := client.ReadFrame(c, wire.MaximumRequestBytes)
			if e != nil {
				return
			}
			q, e := wire.DecodeRequest(raw)
			if e != nil {
				return
			}
			operation, cancel := context.WithTimeout(ctx, client.Deadline)
			defer cancel()
			raw, e = o.Execute(operation, q)
			if e != nil {
				return
			}
			_ = client.WriteFrame(c, raw)
		}()
	}
}

// CleanupSocket requires the independently reviewed exact socket identity and
// the exclusive original owner lock. It never removes key, log or lock files.
func CleanupSocket(root, socket string, pin types.Hash) error {
	if !client.Supported() || pin.IsZero() {
		return wire.ErrAccess
	}
	lock, e := lockExisting(filepath.Join(root, "owner.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	if _, e = ReadIdentity(root); e != nil {
		return e
	}
	id, e := SocketID(socket)
	if e != nil || id != pin {
		return ErrOwner
	}
	c, e := net.DialTimeout("unix", socket, time.Second)
	if e == nil {
		c.Close()
		return ErrOwner
	}
	if !errors.Is(e, syscall.ECONNREFUSED) {
		return ErrOwner
	}
	id, e = SocketID(socket)
	if e != nil || id != pin {
		return ErrOwner
	}
	if e = os.Remove(socket); e != nil {
		return e
	}
	return syncDir(filepath.Dir(socket))
}
