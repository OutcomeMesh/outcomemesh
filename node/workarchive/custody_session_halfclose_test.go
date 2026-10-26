package workarchive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"
)

func TestCustodyAuditHalfCloseAcknowledgesVerifiedResponseBeforeReplicaEOF(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	auditor := newHalfCloseCustodyAuditor(t, fixture)
	stream := newHalfCloseCustodyStream(t, fixture.record)
	response, report, err := auditor.Audit(context.Background(), stream, fixture.record.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stream.events, []string{"close-write", "replica-eof", "close"}) {
		t.Fatalf("duplex finish order=%v", stream.events)
	}
	if stream.closeWrites != 1 || stream.closes != 1 || stream.reader.Len() != 0 {
		t.Fatalf("close-write=%d close=%d unread response=%d", stream.closeWrites, stream.closes, stream.reader.Len())
	}
	if stream.halfCloseDeadline.IsZero() || stream.eofDeadline != stream.halfCloseDeadline {
		t.Fatalf("final EOF lost the bounded frame deadline: half-close=%v EOF=%v", stream.halfCloseDeadline, stream.eofDeadline)
	}
	challenge, err := fixture.record.Challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream.written.Bytes(), halfCloseCustodyFrame(challenge)) {
		t.Fatal("audit changed the signed challenge frame")
	}
	proofID, _ := fixture.record.Proof.ID()
	renewedID, _ := fixture.record.RenewedReceipt.ID()
	if report.ProofID != proofID || report.RenewedReceiptID != renewedID ||
		response.Proof != fixture.record.Proof || response.RenewedReceipt != fixture.record.RenewedReceipt {
		t.Fatalf("verified response/report changed: report=%+v", report)
	}
}

func TestCustodyAuditHalfCloseRejectsFinishFailures(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	injected := errors.New("injected duplex finish failure")
	for _, mode := range []string{"close-write-error", "extra-byte", "replica-read-error"} {
		t.Run(mode, func(t *testing.T) {
			stream := newHalfCloseCustodyStream(t, fixture.record)
			wantEvents := []string{"close-write", "replica-eof", "close"}
			switch mode {
			case "close-write-error":
				stream.halfCloseErr = injected
				wantEvents = []string{"close-write", "close"}
			case "extra-byte":
				stream.trailing = []byte{1}
				wantEvents = []string{"close-write", "replica-data", "close"}
			case "replica-read-error":
				stream.eofErr = injected
			}
			response, report, err := newHalfCloseCustodyAuditor(t, fixture).Audit(context.Background(), stream, fixture.record.Challenge)
			if !errors.Is(err, ErrCustodySession) || (mode != "extra-byte" && !errors.Is(err, injected)) {
				t.Fatalf("finish error=%v", err)
			}
			if !reflect.DeepEqual(response, CustodyResponse{}) || report != (CustodyAuditReport{}) {
				t.Fatal("failed duplex finish returned a successful response or report")
			}
			if !reflect.DeepEqual(stream.events, wantEvents) || stream.closeWrites != 1 || stream.closes != 1 {
				t.Fatalf("finish order=%v close-write=%d close=%d", stream.events, stream.closeWrites, stream.closes)
			}
		})
	}
}

func TestCustodyAuditInvalidProofDoesNotHalfCloseAsAcknowledgment(t *testing.T) {
	fixture := newCustodyRecordFixture(t)
	// All three frames remain canonically encoded and signed. A proof for a
	// different challenge must fail verification before sending a success FIN.
	invalid := fixture.record
	invalid.Proof = fixture.buildRecord(t, 173, 1_002).Proof
	stream := newHalfCloseCustodyStream(t, invalid)
	if _, _, err := newHalfCloseCustodyAuditor(t, fixture).Audit(context.Background(), stream, fixture.record.Challenge); !errors.Is(err, ErrCustodySession) {
		t.Fatalf("unrelated signed proof error=%v", err)
	}
	if stream.reader.Len() != 0 {
		t.Fatal("fixture did not reach verification after all three response frames")
	}
	if stream.closeWrites != 0 || stream.closes != 1 || !reflect.DeepEqual(stream.events, []string{"close"}) {
		t.Fatalf("invalid proof was acknowledged: events=%v close-write=%d close=%d", stream.events, stream.closeWrites, stream.closes)
	}
}

func newHalfCloseCustodyAuditor(t testing.TB, fixture custodyRecordFixture) *CustodySession {
	t.Helper()
	config := DefaultCustodySessionConfig()
	config.Now = func() uint64 { return 1_002 }
	auditor, err := NewCustodyAuditorSession(fixture.manifest, fixture.receipt, fixture.policy, config)
	if err != nil {
		t.Fatal(err)
	}
	return auditor
}

func newHalfCloseCustodyStream(t testing.TB, record CustodyRecord) *halfCloseCustodyStream {
	t.Helper()
	batch, err := record.Batch.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := record.Proof.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := record.RenewedReceipt.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	for _, frame := range [][]byte{batch, proof, renewal} {
		_, _ = response.Write(halfCloseCustodyFrame(frame))
	}
	return &halfCloseCustodyStream{reader: bytes.NewReader(response.Bytes())}
}

func halfCloseCustodyFrame(encoded []byte) []byte {
	framed := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(encoded)))
	copy(framed[4:], encoded)
	return framed
}

type halfCloseCustodyStream struct {
	reader            *bytes.Reader
	written           bytes.Buffer
	events            []string
	closeWrites       int
	closes            int
	halfCloseErr      error
	eofErr            error
	trailing          []byte
	deadline          time.Time
	halfCloseDeadline time.Time
	eofDeadline       time.Time
}

func (stream *halfCloseCustodyStream) Read(out []byte) (int, error) {
	if stream.reader.Len() != 0 {
		return stream.reader.Read(out)
	}
	if stream.closeWrites != 1 || stream.closes != 0 {
		return 0, errors.New("replica EOF read outside the half-closed write scope")
	}
	stream.eofDeadline = stream.deadline
	if len(stream.trailing) != 0 {
		stream.events = append(stream.events, "replica-data")
		n := copy(out, stream.trailing)
		stream.trailing = stream.trailing[n:]
		return n, nil
	}
	stream.events = append(stream.events, "replica-eof")
	if stream.eofErr != nil {
		return 0, stream.eofErr
	}
	return 0, io.EOF
}

func (stream *halfCloseCustodyStream) Write(in []byte) (int, error) {
	return stream.written.Write(in)
}

func (stream *halfCloseCustodyStream) CloseWrite() error {
	stream.events = append(stream.events, "close-write")
	stream.closeWrites++
	stream.halfCloseDeadline = stream.deadline
	if stream.reader.Len() != 0 || stream.closes != 0 {
		return errors.New("acknowledged response before consuming all three frames")
	}
	return stream.halfCloseErr
}

func (stream *halfCloseCustodyStream) Close() error {
	stream.events = append(stream.events, "close")
	stream.closes++
	return nil
}

func (stream *halfCloseCustodyStream) SetDeadline(deadline time.Time) error {
	stream.deadline = deadline
	return nil
}
