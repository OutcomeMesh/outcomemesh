package tieexchange

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
)

func TestRequestRoundTripAndPublishedBinding(t *testing.T) {
	binding := testBinding()
	artifact := []byte("canonical-pair-artifact")
	var stream bytes.Buffer
	if err := WriteRequest(&stream, Request{Binding: binding, Artifact: artifact}); err != nil {
		t.Fatal(err)
	}
	request, err := ReadRequest(&stream, binding)
	if err != nil {
		t.Fatal(err)
	}
	if request.Binding != binding || !bytes.Equal(request.Artifact, artifact) || stream.Len() != 0 {
		t.Fatalf("request=%+v remaining=%d", request, stream.Len())
	}

	var wrong bytes.Buffer
	if err := WriteRequest(&wrong, Request{Binding: binding, Artifact: artifact}); err != nil {
		t.Fatal(err)
	}
	expected := binding
	expected.PairID = types.DomainHash("test/tieexchange/wrong-pair")
	if _, err := ReadRequest(&wrong, expected); !errors.Is(err, ErrBinding) {
		t.Fatalf("binding error=%v", err)
	}
}

func TestRequestRejectsLengthBeforeBodyAllocation(t *testing.T) {
	binding := testBinding()
	var stream bytes.Buffer
	if err := WriteRequest(&stream, Request{Binding: binding, Artifact: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	encoded := stream.Bytes()
	binary.BigEndian.PutUint64(encoded[82:90], uint64(tieproducer.MaximumPairArtifactBytes)+1)
	reader := &countingReader{reader: bytes.NewReader(encoded)}
	if _, err := ReadRequest(reader, binding); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit error=%v", err)
	}
	if reader.read != requestHeaderBytes {
		t.Fatalf("read %d bytes before rejection, want header %d", reader.read, requestHeaderBytes)
	}
	if err := WriteRequest(io.Discard, Request{
		Binding: binding, Artifact: make([]byte, tieproducer.MaximumPairArtifactBytes+1),
	}); !errors.Is(err, ErrLimit) {
		t.Fatalf("writer limit error=%v", err)
	}
}

func TestAcknowledgementRoundTripPinsObserver(t *testing.T) {
	binding := testBinding()
	observer := types.DomainHash("test/tieexchange/observer")
	receipt := types.DomainHash("test/tieexchange/receipt")
	var stream bytes.Buffer
	if err := WriteAcknowledgement(&stream, Acknowledgement{
		Binding: binding, ObserverPublicKey: observer, ReceiptTail: receipt,
	}); err != nil {
		t.Fatal(err)
	}
	acknowledgement, err := ReadAcknowledgement(&stream, binding, observer)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledgement.Binding != binding || acknowledgement.ObserverPublicKey != observer ||
		acknowledgement.ReceiptTail != receipt || stream.Len() != 0 {
		t.Fatalf("acknowledgement=%+v remaining=%d", acknowledgement, stream.Len())
	}

	var wrong bytes.Buffer
	if err := WriteAcknowledgement(&wrong, acknowledgement); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAcknowledgement(&wrong, binding, types.DomainHash("test/tieexchange/other-observer")); !errors.Is(err, ErrBinding) {
		t.Fatalf("observer pin error=%v", err)
	}
}

func TestConfirmationRoundTripPinsDurableReceipt(t *testing.T) {
	binding := testBinding()
	receipt := types.DomainHash("test/tieexchange/confirmed-receipt")
	var stream bytes.Buffer
	if err := WriteConfirmation(&stream, Confirmation{Binding: binding, ReceiptTail: receipt}); err != nil {
		t.Fatal(err)
	}
	confirmation, err := ReadConfirmation(&stream, binding, receipt)
	if err != nil || confirmation.Binding != binding || confirmation.ReceiptTail != receipt || stream.Len() != 0 {
		t.Fatalf("confirmation=%+v remaining=%d err=%v", confirmation, stream.Len(), err)
	}
	var wrong bytes.Buffer
	if err := WriteConfirmation(&wrong, confirmation); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfirmation(&wrong, binding, types.DomainHash("test/tieexchange/other-receipt")); !errors.Is(err, ErrBinding) {
		t.Fatalf("receipt pin error=%v", err)
	}

	var durable bytes.Buffer
	if err := WriteConfirmationAcknowledgement(&durable, ConfirmationAcknowledgement{
		Binding: binding, ReceiptTail: receipt,
	}); err != nil {
		t.Fatal(err)
	}
	acknowledgement, err := ReadConfirmationAcknowledgement(&durable, binding, receipt)
	if err != nil || acknowledgement.Binding != binding ||
		acknowledgement.ReceiptTail != receipt || durable.Len() != 0 {
		t.Fatalf("confirmation acknowledgement=%+v remaining=%d err=%v", acknowledgement, durable.Len(), err)
	}
	var wrongDurable bytes.Buffer
	if err := WriteConfirmationAcknowledgement(&wrongDurable, acknowledgement); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfirmationAcknowledgement(
		&wrongDurable, binding, types.DomainHash("test/tieexchange/other-durable-receipt"),
	); !errors.Is(err, ErrBinding) {
		t.Fatalf("durable receipt pin error=%v", err)
	}
}

func FuzzReadRequestNeverPanics(f *testing.F) {
	var seed bytes.Buffer
	binding := testBinding()
	_ = WriteRequest(&seed, Request{Binding: binding, Artifact: []byte{1, 2, 3}})
	f.Add(seed.Bytes())
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ReadRequest(bytes.NewReader(input), binding)
	})
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(output []byte) (int, error) {
	read, err := reader.reader.Read(output)
	reader.read += read
	return read, err
}

func testBinding() Binding {
	return Binding{
		PlanID: types.DomainHash("test/tieexchange/plan"),
		PairID: types.DomainHash("test/tieexchange/pair"), Sequence: 7,
	}
}
