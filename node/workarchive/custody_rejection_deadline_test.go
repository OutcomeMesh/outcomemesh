package workarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Keep the client's final challenge Write from returning until the replica has
// rejected that sibling and closed its stream. Its next SetDeadline then really
// sees a closed net.Pipe; scheduler timing cannot choose another error path.
type custodyRejectedChallengeGate struct {
	net.Conn
	ctx              context.Context
	rejected         <-chan struct{}
	writes           int
	deadlineFailures int
}

func (s *custodyRejectedChallengeGate) Write(b []byte) (int, error) {
	n, err := s.Conn.Write(b)
	s.writes++
	if s.writes == 2 && err == nil && n == len(b) {
		select {
		case <-s.rejected:
		case <-s.ctx.Done():
			return n, s.ctx.Err()
		}
	}
	return n, err
}

func (s *custodyRejectedChallengeGate) SetDeadline(deadline time.Time) error {
	err := s.Conn.SetDeadline(deadline)
	if errors.Is(err, io.ErrClosedPipe) {
		s.deadlineFailures++
	}
	return err
}

func TestCustodySessionSiblingRejectionKeepsSessionErrorAfterRemoteClose(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "recovered"}[recovered], func(t *testing.T) {
			f := newCustodyRecordFixture(t)
			path := filepath.Join(t.TempDir(), "response.omcr")
			if recovered {
				if _, _, err := PublishCustodyRecordFile(path, f.record, f.manifest, f.receipt, f.policy); err != nil {
					t.Fatal(err)
				}
			}
			config := DefaultCustodySessionConfig()
			config.Now = func() uint64 { return 1002 }
			replica, err := NewDurableCustodyReplicaSession(f.manifest, f.receipt, f.store, f.policy, f.replicaKey, path, config)
			if err != nil {
				t.Fatal(err)
			}
			auditor, err := NewCustodyAuditorSession(f.manifest, f.receipt, f.policy, config)
			if err != nil {
				t.Fatal(err)
			}
			if !recovered {
				runCustodyPipeSession(t, replica, auditor, f.record.Challenge)
			}
			before, err := LoadCustodyRecordFile(path, f.manifest, f.receipt, f.policy)
			if err != nil {
				t.Fatal(err)
			}
			sibling := f.buildRecord(t, 132, 1002).Challenge
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			rejected := make(chan struct{})
			served := make(chan error, 1)
			go func() { _, err := replica.Serve(ctx, server); served <- err; close(rejected) }()
			gated := &custodyRejectedChallengeGate{Conn: client, ctx: ctx, rejected: rejected}
			response, report, err := auditor.Audit(ctx, gated, sibling)
			if !errors.Is(err, ErrCustodySession) || !errors.Is(err, io.ErrClosedPipe) || !reflect.DeepEqual(response, CustodyResponse{}) || report != (CustodyAuditReport{}) {
				t.Fatal("remote rejection lost session classification or returned evidence", err)
			}
			if gated.writes != 2 || gated.deadlineFailures != 1 {
				t.Fatal("did not reach post-challenge deadline failure")
			}
			if err := <-served; !errors.Is(err, ErrCustodySession) {
				t.Fatal("sibling accepted by replica", err)
			}
			after, err := LoadCustodyRecordFile(path, f.manifest, f.receipt, f.policy)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := before.CanonicalBytes()
			a, _ := after.CanonicalBytes()
			if !bytes.Equal(a, b) {
				t.Fatal("rejected sibling changed retained response")
			}
		})
	}
}

type custodyDeadlineErrorStream struct {
	err     error
	ioCalls int
}

func (s *custodyDeadlineErrorStream) Read([]byte) (int, error)    { s.ioCalls++; return 0, io.EOF }
func (s *custodyDeadlineErrorStream) Write(b []byte) (int, error) { s.ioCalls++; return len(b), nil }
func (s *custodyDeadlineErrorStream) Close() error                { return nil }
func (s *custodyDeadlineErrorStream) SetDeadline(time.Time) error { return s.err }

func TestCustodySessionDeadlineFailureNeverFallsThroughToIO(t *testing.T) {
	session := &CustodySession{config: DefaultCustodySessionConfig()}
	for _, cause := range []error{io.ErrClosedPipe, errors.New("deadline setup failed")} {
		stream := &custodyDeadlineErrorStream{err: cause}
		if _, err := session.readFrame(t.Context(), stream, 16); !errors.Is(err, ErrCustodySession) || !errors.Is(err, cause) {
			t.Fatal(err)
		}
		if err := session.writeFrame(t.Context(), stream, []byte{1}, 16); !errors.Is(err, ErrCustodySession) || !errors.Is(err, cause) {
			t.Fatal(err)
		}
		if stream.ioCalls != 0 {
			t.Fatal("deadline failure performed unbounded I/O")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := session.setDeadline(ctx, &custodyDeadlineErrorStream{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
