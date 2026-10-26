package workarchive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestCustodySessionServeExpectedRejectsBeforeFreshCachedAndRecoveredEffects(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	challengeID, err := fixture.record.Challenge.ID()
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := fixture.buildRecord(t, 171, 1_002).Challenge.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"fresh", "cached", "recovered"} {
		t.Run(phase, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			journal, _, err := OpenOrCreateCustodyJournal(root, fixture.manifest, fixture.receipt, fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			config := DefaultCustodySessionConfig()
			config.Now = func() uint64 { return 1_002 }
			session, err := NewJournalCustodyReplicaSession(journal, fixture.store, fixture.replicaKey, config)
			if err != nil {
				t.Fatal(err)
			}
			var originalResponse []byte
			if phase != "fresh" {
				stream := newExpectedCustodyStream(t, fixture.record.Challenge)
				report, err := session.ServeExpected(context.Background(), stream, challengeID)
				if err != nil || report.JournalSequence != 1 || !stream.closed || stream.written.Len() == 0 {
					t.Fatalf("first exact response report=%+v closed=%t error=%v", report, stream.closed, err)
				}
				originalResponse = append([]byte(nil), stream.written.Bytes()...)
			}
			if phase == "recovered" {
				session, err = NewJournalCustodyReplicaSession(journal, fixture.store, fixture.replicaKey, config)
				if err != nil {
					t.Fatal(err)
				}
			}
			beforeState, err := journal.State()
			if err != nil {
				t.Fatal(err)
			}
			beforeTree := snapshotExistingCustodyTree(t, root)
			cached, recovered := session.cachedResponse, session.recoveryResponse
			decision, err := journal.AcquireDecision()
			if err != nil {
				t.Fatal(err)
			}
			session.serveMu.Lock()
			stream := newExpectedCustodyStream(t, fixture.record.Challenge)
			done := make(chan error, 1)
			go func() {
				_, err := session.ServeExpected(context.Background(), stream, otherID)
				done <- err
			}()
			var serveErr error
			early := false
			select {
			case serveErr = <-done:
				early = true
			case <-time.After(time.Second):
			}
			session.serveMu.Unlock()
			_ = decision.Close()
			if !early {
				serveErr = <-done
				t.Fatal("mismatched challenge reached the held session or journal lock")
			}
			if !errors.Is(serveErr, ErrCustodySession) || !stream.closed || stream.written.Len() != 0 {
				t.Fatalf("mismatched challenge error=%v closed=%t response bytes=%d", serveErr, stream.closed, stream.written.Len())
			}
			if session.cachedResponse != cached || session.recoveryResponse != recovered {
				t.Fatal("mismatched challenge changed cached response")
			}
			state, err := journal.State()
			if err != nil || state != beforeState {
				t.Fatalf("mismatched challenge changed journal state=%+v error=%v", state, err)
			}
			assertExistingCustodyTreeUnchanged(t, root, beforeTree)
			// The rejected operation cannot consume or replace the legitimate
			// response, including the exact bytes retained across restart.
			accepted := newExpectedCustodyStream(t, fixture.record.Challenge)
			report, err := session.ServeExpected(context.Background(), accepted, challengeID)
			if err != nil || report.ChallengeID != challengeID || report.JournalSequence != 1 {
				t.Fatalf("exact challenge after rejection report=%+v error=%v", report, err)
			}
			if originalResponse != nil && !bytes.Equal(originalResponse, accepted.written.Bytes()) {
				t.Fatal("exact retry changed the durable response bytes")
			}
		})
	}
}

func TestCustodySessionServeExpectedRejectsZeroBeforeReading(t *testing.T) {
	stream := &expectedCustodyStream{reader: bytes.NewReader([]byte{1, 2, 3})}
	var session *CustodySession
	if _, err := session.ServeExpected(context.Background(), stream, types.Hash{}); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("zero expected ID error=%v", err)
	}
	if !stream.closed || stream.reads != 0 || stream.written.Len() != 0 {
		t.Fatalf("zero expected ID closed=%t reads=%d written=%d", stream.closed, stream.reads, stream.written.Len())
	}
}

type expectedCustodyStream struct {
	reader  *bytes.Reader
	written bytes.Buffer
	closed  bool
	reads   int
}

func newExpectedCustodyStream(t testing.TB, challenge CustodyChallenge) *expectedCustodyStream {
	t.Helper()
	encoded, err := challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(encoded)))
	return &expectedCustodyStream{reader: bytes.NewReader(append(prefix[:], encoded...))}
}

func (stream *expectedCustodyStream) Read(out []byte) (int, error) {
	stream.reads++
	return stream.reader.Read(out)
}

func (stream *expectedCustodyStream) Write(in []byte) (int, error) { return stream.written.Write(in) }
func (stream *expectedCustodyStream) Close() error                 { stream.closed = true; return nil }
func (*expectedCustodyStream) SetDeadline(time.Time) error         { return nil }
