//go:build linux || darwin

package custodyguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func Handler(s *Store) http.Handler {
	active := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || (r.URL.Path != Route && r.URL.Path != RevocationRoute && r.URL.Path != ReplacementRoute) || r.URL.RawQuery != "" {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		size := wire.RequestBytes
		if r.URL.Path == RevocationRoute {
			size = wire.RevocationBytes
		}
		if r.URL.Path == ReplacementRoute {
			size = wire.ReplacementBytes
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, int64(size+1)))
		if e != nil || len(b) != size {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		var reply []byte
		if r.URL.Path == ReplacementRoute {
			q, err := wire.DecodeReplacement(b)
			if err != nil {
				http.Error(w, "refused", http.StatusBadRequest)
				return
			}
			var receipt wire.ReplacementReceipt
			receipt, e = s.Replace(r.Context(), q)
			if e == nil {
				reply, e = receipt.CanonicalBytes()
			}
		} else if r.URL.Path == RevocationRoute {
			q, err := wire.DecodeRevocation(b)
			if err != nil {
				http.Error(w, "refused", http.StatusBadRequest)
				return
			}
			var receipt wire.RevocationReceipt
			receipt, e = s.Revoke(r.Context(), q)
			if e == nil {
				reply, e = receipt.CanonicalBytes()
			}
		} else {
			q, err := wire.DecodeRequest(b)
			if err != nil {
				http.Error(w, "refused", http.StatusBadRequest)
				return
			}
			var seal [64]byte
			seal, e = s.Choose(r.Context(), q)
			reply = seal[:]
		}
		if e != nil {
			http.Error(w, "refused", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(reply)
	})
}

// Serve owns the listener, not the store. Bounds apply even before HTTP parsing.
func Serve(ctx context.Context, l net.Listener, s *Store) error {
	if ctx == nil || l == nil || s == nil {
		return ErrStore
	}
	address, ok := l.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return errors.New("guard HTTP must bind a loopback address; use an authenticated tunnel")
	}
	srv := &http.Server{Handler: Handler(s), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096}
	bounded := &limitedListener{Listener: l, slots: make(chan struct{}, 16)}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
		case <-done:
		}
	}()
	e := srv.Serve(bounded)
	if errors.Is(e, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return e
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	release func()
}

func (c *limitedConn) Close() error { e := c.Conn.Close(); c.release(); return e }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			var once sync.Once
			return &limitedConn{Conn: c, release: func() { once.Do(func() { <-l.slots }) }}, nil
		default:
			_ = c.Close()
		}
	}
}
