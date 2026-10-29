//go:build linux || darwin

package custodyguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const Route = "/outcomemesh/custody-guard/1"

// Client transports public signed choices. It never follows redirects or uses
// proxy environment variables. Authenticity comes from the pinned seal key;
// use a private network or TLS for confidentiality and resistance to traffic DoS.
type Client struct{ URL string }

func ValidateURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" && u.Path != "/" {
		return wire.ErrGuard
	}
	return nil
}
func (c Client) Choose(ctx context.Context, q wire.Request) (seal [64]byte, err error) {
	if ValidateURL(c.URL) != nil || ctx == nil {
		return seal, wire.ErrGuard
	}
	b, e := q.CanonicalBytes()
	if e != nil {
		return seal, e
	}
	u, _ := url.Parse(c.URL)
	u.Path = Route
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(b))
	if e != nil {
		return seal, e
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 4096, TLSHandshakeTimeout: 3 * time.Second}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := client.Do(req)
	if e != nil {
		return seal, e
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return seal, wire.ErrGuard
	}
	b, e = io.ReadAll(io.LimitReader(r.Body, wire.SealBytes+1))
	if e != nil || len(b) != wire.SealBytes {
		return seal, wire.ErrGuard
	}
	copy(seal[:], b)
	return seal, nil
}
func Handler(s *Store) http.Handler {
	active := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != Route || r.URL.RawQuery != "" {
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
		b, e := io.ReadAll(io.LimitReader(r.Body, wire.RequestBytes+1))
		if e != nil || len(b) != wire.RequestBytes {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		q, e := wire.DecodeRequest(b)
		if e != nil {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		seal, e := s.Choose(r.Context(), q)
		if e != nil {
			http.Error(w, "refused", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(seal[:])
	})
}

// Serve owns the listener, not the store. Bounds apply even before HTTP parsing.
func Serve(ctx context.Context, l net.Listener, s *Store) error {
	if ctx == nil || l == nil || s == nil {
		return ErrStore
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
