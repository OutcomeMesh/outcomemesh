//go:build linux || darwin

package serviceclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

type approver func(context.Context, wire.Challenge) (custodyfence.Command, error)

func unixListener(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	// A short name also fits Darwin's smaller sockaddr_un path limit.
	dir, err := os.MkdirTemp("", "ompc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func runExchange(t *testing.T, ctx context.Context, f exchangeFixture, approve approver, serve func(*net.UnixConn) error) (wire.Response, error) {
	t.Helper()
	l, path := unixListener(t)
	done := make(chan error, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		if err = c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		kind, raw, err := wire.ReadFrame(c)
		want, _ := f.q.CanonicalBytes()
		if err != nil || kind != wire.RequestFrame || !bytes.Equal(raw, want) {
			done <- fmt.Errorf("request frame: kind=%d err=%v", kind, err)
			return
		}
		done <- serve(c)
	}()
	var r wire.Response
	var err error
	if gatewayclient.Supported() {
		r, err = Call(ctx, path, f.d, f.q, approve)
	} else {
		// Exercise the protocol on Darwin without weakening Call's deliberate
		// Linux credential requirement. Only Call is exported to participants.
		var c net.Conn
		c, err = (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err == nil {
			bounded, cancel := context.WithTimeout(ctx, wire.ExchangeDeadline)
			r, err = exchange(bounded, c.(*net.UnixConn), f.d, f.q, approve)
			cancel()
			c.Close()
		}
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal("server:", e)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("server did not drain")
	}
	return r, err
}

func approveCandidate(ctx context.Context, c wire.Challenge) (custodyfence.Command, error) {
	if ctx.Err() != nil {
		return custodyfence.Command{}, ctx.Err()
	}
	_, draft, err := c.Candidate.Draft()
	if err != nil {
		return custodyfence.Command{}, err
	}
	return draft.Sign(fencetest.Key(1))
}
func sendArtifact(c *net.UnixConn, kind uint8, a interface{ CanonicalBytes() ([]byte, error) }) error {
	b, err := a.CanonicalBytes()
	if err != nil {
		return err
	}
	return wire.WriteFrame(c, kind, b)
}
func acceptApproval(c *net.UnixConn, challenge wire.Challenge) error {
	kind, b, err := wire.ReadFrame(c)
	if err != nil {
		return err
	}
	if kind != wire.ApprovalFrame {
		return wire.ErrArtifact
	}
	command, err := custodyfence.DecodeCommand(b)
	if err != nil {
		return err
	}
	scope, draft, err := challenge.Candidate.Draft()
	if err != nil {
		return err
	}
	draft.Signature = command.Signature
	if command != draft {
		return wire.ErrAccess
	}
	if err = command.Verify(scope); err != nil {
		return err
	}
	return wire.RequireEOF(c)
}

func TestExchangeRetainedResponsesNeverAskForApproval(t *testing.T) {
	f := loadFixture(t)
	for i, response := range []wire.Response{f.result, f.settlement} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var calls atomic.Int32
			got, err := runExchange(t, t.Context(), f, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
				calls.Add(1)
				return custodyfence.Command{}, errors.New("unexpected approval")
			}, func(c *net.UnixConn) error {
				if err := sendArtifact(c, wire.ResponseFrame, response); err != nil {
					return err
				}
				if err := wire.RequireEOF(c); err != nil {
					return err
				}
				return c.CloseWrite()
			})
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Fatal("replay requested live approval")
			}
			want, _ := response.CanonicalBytes()
			raw, _ := got.CanonicalBytes()
			if !bytes.Equal(raw, want) {
				t.Fatal("retained reply changed")
			}
		})
	}
}

func TestExchangeSignsOnlyExactCandidateAndHalfCloses(t *testing.T) {
	f := loadFixture(t)
	var calls atomic.Int32
	r, err := runExchange(t, t.Context(), f, func(ctx context.Context, c wire.Challenge) (custodyfence.Command, error) {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > wire.ExchangeDeadline {
			return custodyfence.Command{}, errors.New("unbounded approval context")
		}
		return approveCandidate(ctx, c)
	}, func(c *net.UnixConn) error {
		if err := sendArtifact(c, wire.ChallengeFrame, f.c); err != nil {
			return err
		}
		if err := acceptApproval(c, f.c); err != nil {
			return err
		}
		if err := sendArtifact(c, wire.ResponseFrame, f.result); err != nil {
			return err
		}
		return c.CloseWrite()
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("wrong approval count")
	}
	if err := r.Verify(f.d, f.q); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeRejectsSubstitutedChallengeBeforeApproval(t *testing.T) {
	f := loadFixture(t)
	other := f.q
	other.Nonce = [32]byte(fencetest.Hash("other exchange"))
	other, err := other.Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	c := f.c
	c.RequestID, _ = other.ID()
	c.Before, _ = other.IntentPosition()
	c, err = c.Sign(f.d, other, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	_, err = runExchange(t, t.Context(), f, func(ctx context.Context, c wire.Challenge) (custodyfence.Command, error) {
		calls.Add(1)
		return approveCandidate(ctx, c)
	}, func(conn *net.UnixConn) error {
		if err := sendArtifact(conn, wire.ChallengeFrame, c); err != nil {
			return err
		}
		return wire.RequireEOF(conn)
	})
	if err == nil || calls.Load() != 0 {
		t.Fatal("substitution reached approval", err, calls.Load())
	}
}

func TestExchangeRejectsWrongAndMissingApprovalWithoutSending(t *testing.T) {
	f := loadFixture(t)
	for name, approve := range map[string]approver{
		"missing": nil,
		"refused": func(context.Context, wire.Challenge) (custodyfence.Command, error) {
			return custodyfence.Command{}, errors.New("refused")
		},
		"wrong key": func(_ context.Context, c wire.Challenge) (custodyfence.Command, error) {
			_, draft, e := c.Candidate.Draft()
			if e != nil {
				return draft, e
			}
			return draft.Sign(fencetest.Key(2))
		},
		"different command": func(_ context.Context, c wire.Challenge) (custodyfence.Command, error) {
			_, draft, e := c.Candidate.Draft()
			if e != nil {
				return draft, e
			}
			draft.EvidenceID = fencetest.Hash("other candidate")
			return draft.Sign(fencetest.Key(1))
		},
		"mutated candidate": func(_ context.Context, c wire.Challenge) (custodyfence.Command, error) {
			c.Candidate.Policy.Service.StorageID = fencetest.Hash("other storage")
			return custodyfence.Command{}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runExchange(t, t.Context(), f, approve, func(c *net.UnixConn) error {
				if err := sendArtifact(c, wire.ChallengeFrame, f.c); err != nil {
					return err
				}
				return wire.RequireEOF(c)
			})
			if err == nil {
				t.Fatal("invalid approval accepted")
			}
		})
	}
}

func TestExchangeRejectsAnotherSignedResponse(t *testing.T) {
	f := loadFixture(t)
	other := f.q
	other.Nonce = [32]byte(fencetest.Hash("other retained request"))
	var err error
	other, err = other.Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	r := f.result
	r.RequestID, _ = other.ID()
	r, err = r.Sign(f.d, other, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	_, err = runExchange(t, t.Context(), f, nil, func(c *net.UnixConn) error {
		if err := sendArtifact(c, wire.ResponseFrame, r); err != nil {
			return err
		}
		if err := wire.RequireEOF(c); err != nil {
			return err
		}
		return c.CloseWrite()
	})
	if err == nil {
		t.Fatal("accepted another signed response")
	}
}

func TestExchangeRejectsUnexpectedFramesAndTrailingOutput(t *testing.T) {
	f := loadFixture(t)
	for name, serve := range map[string]func(*net.UnixConn) error{
		"request instead of reply": func(c *net.UnixConn) error { return sendArtifact(c, wire.RequestFrame, f.q) },
		"trailing output": func(c *net.UnixConn) error {
			if err := sendArtifact(c, wire.ResponseFrame, f.result); err != nil {
				return err
			}
			if _, err := c.Write([]byte{0}); err != nil {
				return err
			}
			return c.CloseWrite()
		},
		"second challenge": func(c *net.UnixConn) error {
			if err := sendArtifact(c, wire.ChallengeFrame, f.c); err != nil {
				return err
			}
			if err := acceptApproval(c, f.c); err != nil {
				return err
			}
			return sendArtifact(c, wire.ChallengeFrame, f.c)
		},
		"bad response signature": func(c *net.UnixConn) error {
			b, err := f.result.CanonicalBytes()
			if err != nil {
				return err
			}
			b[len(b)-1] ^= 1
			if err = wire.WriteFrame(c, wire.ResponseFrame, b); err != nil {
				return err
			}
			return c.CloseWrite()
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runExchange(t, t.Context(), f, approveCandidate, serve); err == nil {
				t.Fatal("accepted invalid reply")
			}
		})
	}
}

func TestExchangeDeadlineRequiresEOFAndCancelsBlockedApproval(t *testing.T) {
	f := loadFixture(t)
	t.Run("missing EOF", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := runExchange(t, ctx, f, nil, func(c *net.UnixConn) error {
			if err := sendArtifact(c, wire.ResponseFrame, f.result); err != nil {
				return err
			}
			if err := wire.RequireEOF(c); err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		})
		if err == nil || time.Since(start) > 2*time.Second {
			t.Fatal("missing EOF escaped deadline", err)
		}
	})
	t.Run("blocked approval", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered := make(chan struct{})
		release := make(chan struct{})
		go func() { <-entered; cancel() }()
		_, err := runExchange(t, ctx, f, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
			close(entered)
			<-release
			return custodyfence.Command{}, nil
		}, func(c *net.UnixConn) error {
			if err := sendArtifact(c, wire.ChallengeFrame, f.c); err != nil {
				return err
			}
			return wire.RequireEOF(c)
		})
		close(release)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("callback extended cancelled exchange", err)
		}
	})
}

func TestCallRejectsWrongKernelOwnerUID(t *testing.T) {
	if !gatewayclient.Supported() {
		t.Skip("kernel credential acceptance requires Linux")
	}
	f := loadFixture(t)
	f.d.OwnerUID++
	if f.d.OwnerUID == f.d.ParticipantUID {
		f.d.OwnerUID++
	}
	var err error
	f.d, err = f.d.Sign(fencetest.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	f.q.DescriptorID, _ = f.d.ID()
	f.q, err = f.q.Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	l, path := unixListener(t)
	defer l.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := Call(ctx, path, f.d, f.q, nil); !errors.Is(err, wire.ErrAccess) {
		t.Fatal("accepted wrong kernel owner", err)
	}
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if raw, err := io.ReadAll(c); err != nil || len(raw) != 0 {
		t.Fatal(err)
	}
}
