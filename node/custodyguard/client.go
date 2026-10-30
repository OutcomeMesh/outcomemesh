package custodyguard

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const Route = "/outcomemesh/custody-guard/1"
const RevocationRoute = "/outcomemesh/custody-guard/revoke/1"
const ReplacementRoute = "/outcomemesh/custody-guard/replace/1"

// Client transports public signed choices. It never follows redirects or uses
// proxy environment variables. Authenticity comes from the pinned seal key;
// use an authenticated tunnel for loopback HTTP, or HTTPS for remote endpoints.
type Client struct{ URL string }

func ValidateURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" && u.Path != "/" {
		return wire.ErrGuard
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return wire.ErrGuard
		}
	}
	return nil
}
func (c Client) Choose(ctx context.Context, q wire.Request) (seal [64]byte, err error) {
	b, e := q.CanonicalBytes()
	if e != nil {
		return seal, e
	}
	b, e = c.exchange(ctx, Route, b, wire.SealBytes)
	if e != nil {
		return seal, e
	}
	copy(seal[:], b)
	return seal, nil
}
func (c Client) Revoke(ctx context.Context, q wire.Revocation) (wire.RevocationReceipt, error) {
	b, e := q.CanonicalBytes()
	if e != nil {
		return wire.RevocationReceipt{}, e
	}
	b, e = c.exchange(ctx, RevocationRoute, b, wire.RevocationReceiptBytes)
	if e != nil {
		return wire.RevocationReceipt{}, e
	}
	return wire.DecodeRevocationReceipt(b)
}
func (c Client) Replace(ctx context.Context, q wire.Replacement) (wire.ReplacementReceipt, error) {
	b, err := q.CanonicalBytes()
	if err != nil {
		return wire.ReplacementReceipt{}, err
	}
	b, err = c.exchange(ctx, ReplacementRoute, b, wire.ReplacementReceiptBytes)
	if err != nil {
		return wire.ReplacementReceipt{}, err
	}
	return wire.DecodeReplacementReceipt(b)
}
func (c Client) exchange(ctx context.Context, route string, b []byte, size int) ([]byte, error) {
	if ValidateURL(c.URL) != nil || ctx == nil {
		return nil, wire.ErrGuard
	}
	u, _ := url.Parse(c.URL)
	u.Path = route
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 4096, TLSHandshakeTimeout: 3 * time.Second}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, wire.ErrGuard
	}
	b, e = io.ReadAll(io.LimitReader(r.Body, int64(size+1)))
	if e != nil || len(b) != size {
		return nil, wire.ErrGuard
	}
	return b, nil
}
