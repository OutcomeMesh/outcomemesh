package workarchive

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Force the auditor to finish validation and close after consuming the final
// frame, before the replica's successful final Write returns to Serve.
type custodyFinalWriteGate struct {
	net.Conn
	writes  int
	audited <-chan struct{}
	ctx     context.Context
}

func (s *custodyFinalWriteGate) Write(b []byte) (int, error) {
	n, err := s.Conn.Write(b)
	s.writes++
	if s.writes == 6 && err == nil && n == len(b) {
		select {
		case <-s.audited:
		case <-s.ctx.Done():
			return n, s.ctx.Err()
		}
	}
	return n, err
}

func TestCustodySessionCompletionKeepsPreinstalledDeadline(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "recovered"}[cached], func(t *testing.T) {
			f := newCustodyRecordFixture(t)
			journal, _, err := OpenOrCreateCustodyJournal(filepath.Join(t.TempDir(), "journal"), f.manifest, f.receipt, f.policy)
			if err != nil {
				t.Fatal(err)
			}
			if cached {
				if _, _, err := journal.Append(f.record); err != nil {
					t.Fatal(err)
				}
			}
			config := DefaultCustodySessionConfig()
			config.Now = func() uint64 { return 1002 }
			if cached {
				config.Now = func() uint64 { return 1100 }
			}
			replica, err := NewJournalCustodyReplicaSession(journal, f.store, f.replicaKey, config)
			if err != nil {
				t.Fatal(err)
			}
			auditor, err := NewCustodyAuditorSession(f.manifest, f.receipt, f.policy, config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			audited := make(chan struct{})
			done := make(chan error, 1)
			gated := &custodyFinalWriteGate{Conn: server, audited: audited, ctx: ctx}
			go func() { _, err := replica.Serve(ctx, gated); done <- err }()
			_, _, err = auditor.Audit(ctx, client, f.record.Challenge)
			close(audited)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("completed auditor rejected while resetting deadline", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if gated.writes != 6 {
				t.Fatal("missed final response write")
			}
			if state, err := journal.State(); err != nil || state.Sequence != 1 {
				t.Fatal("closure race changed journal", err)
			}
		})
	}
}

func TestCustodySessionCompletionStillRequiresEOFWithinExistingDeadline(t *testing.T) {
	session := &CustodySession{config: DefaultCustodySessionConfig()}
	t.Run("timeout", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		if err := server.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := session.awaitAuditorClose(ctx, server); !errors.Is(err, os.ErrDeadlineExceeded) || !errors.Is(err, ErrCustodySession) {
			t.Fatal("existing bound lost", err)
		}
	})
	t.Run("trailing-data", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		_ = server.SetDeadline(time.Now().Add(time.Second))
		done := make(chan struct{})
		go func() { _, _ = client.Write([]byte{1}); close(done) }()
		if err := session.awaitAuditorClose(t.Context(), server); !errors.Is(err, ErrCustodySession) {
			t.Fatal("data treated as closure", err)
		}
		<-done
	})
	t.Run("local-close-is-not-eof", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		_ = server.Close()
		if err := session.awaitAuditorClose(t.Context(), server); !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, ErrCustodySession) {
			t.Fatal("local close treated as acknowledgement", err)
		}
	})
}
