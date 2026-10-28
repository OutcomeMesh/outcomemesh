package custodyv2

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
)

func WriteAdmissionDelivery(w io.Writer, delivery AdmissionDelivery) error {
	b, e := delivery.CanonicalBytes()
	if e != nil {
		return e
	}
	return writeFrame(w, b, MaximumAdmissionDeliveryBytes)
}

func ReadAdmissionDelivery(r io.Reader) (AdmissionDelivery, error) {
	b, e := readFrame(r, MaximumAdmissionDeliveryBytes)
	if e != nil {
		return AdmissionDelivery{}, e
	}
	return DecodeAdmissionDelivery(b)
}

func WriteAdmissionDeliveryReceipt(w io.Writer, receipt AdmissionDeliveryReceipt) error {
	b, e := receipt.CanonicalBytes()
	if e != nil {
		return e
	}
	return writeFrame(w, b, AdmissionDeliveryReceiptBytes)
}

func ReadAdmissionDeliveryReceipt(r io.Reader) (AdmissionDeliveryReceipt, error) {
	b, e := readFrame(r, AdmissionDeliveryReceiptBytes)
	if e != nil {
		return AdmissionDeliveryReceipt{}, e
	}
	return DecodeAdmissionDeliveryReceipt(b)
}

// exchangeAdmissionDelivery makes one already authenticated attempt. Even a
// valid-looking receipt is unusable until complete reply EOF and stream close.
// On uncertainty, the retained outbox stays unresolved for explicit exact retry.
func exchangeAdmissionDelivery(ctx context.Context, stream remotewire.Stream, delivery AdmissionDelivery, timeout time.Duration) (receipt AdmissionDeliveryReceipt, returnErr error) {
	if stream == nil {
		return receipt, ErrProtocol
	}
	defer func() {
		if e := stream.Close(); e != nil {
			receipt = AdmissionDeliveryReceipt{}
			returnErr = errors.Join(ErrUncertain, returnErr, e)
		}
	}()
	if e := delivery.Validate(); e != nil {
		return receipt, e
	}
	bounded, cleanup, e := remotewire.BoundStream(ctx, stream, timeout)
	if e != nil {
		return receipt, e
	}
	defer cleanup()
	uncertain := func(e error) (AdmissionDeliveryReceipt, error) {
		return AdmissionDeliveryReceipt{}, errors.Join(ErrUncertain, e, bounded.Err())
	}
	if e := WriteAdmissionDelivery(stream, delivery); e != nil {
		return uncertain(e)
	}
	if e := stream.CloseWrite(); e != nil {
		return uncertain(e)
	}
	receipt, e = ReadAdmissionDeliveryReceipt(stream)
	if e != nil {
		return uncertain(e)
	}
	if e := receipt.Verify(delivery); e != nil {
		return uncertain(e)
	}
	if e := remotewire.RequireEOF(stream); e != nil {
		return uncertain(e)
	}
	if e := bounded.Err(); e != nil {
		return uncertain(e)
	}
	return receipt, nil
}
