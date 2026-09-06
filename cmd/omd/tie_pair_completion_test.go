package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/tieexchange"
)

type testTieCompletionStream struct {
	reader          io.Reader
	closeWrite      func() error
	setReadDeadline func(time.Time) error
}

func (stream testTieCompletionStream) Read(output []byte) (int, error) {
	return stream.reader.Read(output)
}
func (stream testTieCompletionStream) CloseWrite() error {
	if stream.closeWrite != nil {
		return stream.closeWrite()
	}
	return nil
}
func (stream testTieCompletionStream) SetReadDeadline(deadline time.Time) error {
	if stream.setReadDeadline != nil {
		return stream.setReadDeadline(deadline)
	}
	return nil
}

type tieCompletionErrorReader struct{ err error }

func (reader tieCompletionErrorReader) Read([]byte) (int, error) { return 0, reader.err }

func TestTiePairCompletionAcceptsOnlyCoordinatorEOF(t *testing.T) {
	reset := errors.New("stream reset")
	for _, test := range []struct {
		name   string
		reader io.Reader
		want   error
	}{
		{"EOF", bytes.NewReader(nil), nil},
		{"trailing data", bytes.NewReader([]byte{1}), tieexchange.ErrProtocol},
		{"reset", tieCompletionErrorReader{reset}, reset},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := awaitTiePairCoordinatorClose(context.Background(), testTieCompletionStream{reader: test.reader})
			if !errors.Is(err, test.want) {
				t.Fatalf("completion error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestTiePairCompletionWaitsUntilEOFAndHonorsCancellation(t *testing.T) {
	for _, mode := range []string{"EOF", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, time.Second)
				defer stop()
			}
			reading := make(chan struct{})
			stream := testTieCompletionStream{reader: server, setReadDeadline: func(deadline time.Time) error {
				select {
				case <-reading:
				default:
					close(reading)
				}
				return server.SetReadDeadline(deadline)
			}}
			done := make(chan error, 1)
			go func() { done <- awaitTiePairCoordinatorClose(ctx, stream) }()
			select {
			case <-reading:
			case err := <-done:
				t.Fatalf("completion did not start a bounded read: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("completion did not install a read deadline")
			}
			select {
			case err := <-done:
				t.Fatalf("observer finished before coordinator EOF: %v", err)
			default:
			}
			switch mode {
			case "EOF":
				_ = client.Close()
			case "cancel":
				cancel()
			}
			select {
			case err := <-done:
				if mode == "EOF" && err != nil {
					t.Fatal(err)
				}
				if mode != "EOF" && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("read was not interrupted: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("completion wait exceeded its context bound")
			}
		})
	}
}

func TestTiePairCompletionDeadlineIsIndependentAndBounded(t *testing.T) {
	for _, shorterContext := range []bool{false, true} {
		ctx := context.Background()
		var stop context.CancelFunc
		if shorterContext {
			ctx, stop = context.WithTimeout(ctx, time.Second)
			defer stop()
		}
		before := time.Now()
		var applied time.Time
		stream := testTieCompletionStream{reader: bytes.NewReader(nil), setReadDeadline: func(deadline time.Time) error { applied = deadline; return nil }}
		if err := awaitTiePairCoordinatorClose(ctx, stream); err != nil {
			t.Fatal(err)
		}
		if shorterContext {
			want, _ := ctx.Deadline()
			if applied != want {
				t.Fatalf("read deadline=%v want=%v", applied, want)
			}
		} else if applied.Before(before.Add(tiePairCompletionTimeout)) || applied.After(time.Now().Add(tiePairCompletionTimeout)) {
			t.Fatalf("completion deadline is not bounded: %v", applied)
		}
	}
	if _, err := setTiePairCompletionDeadline(nil, nil); !errors.Is(err, tieexchange.ErrProtocol) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := setTiePairCompletionDeadline(ctx, testTieCompletionStream{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	failure := errors.New("deadline failed")
	if err := awaitTiePairCoordinatorClose(context.Background(), testTieCompletionStream{setReadDeadline: func(time.Time) error { return failure }}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestTiePairCoordinatorRetiresAfterFinalAcknowledgement(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	halfClosed := make(chan struct{})
	stream := testTieCompletionStream{
		reader: client, setReadDeadline: client.SetReadDeadline,
		closeWrite: func() error { close(halfClosed); return nil },
	}
	done := make(chan struct{})
	go func() { retireTiePairCoordinatorStream(context.Background(), stream); close(done) }()
	select {
	case <-halfClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not half-close after the final ACK")
	}
	select {
	case <-done:
		t.Fatal("coordinator closed its host without waiting for the observer")
	default:
	}
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("coordinator did not finish retirement")
	}

	// The final ACK was validated before this helper is called. A subsequent
	// connection close or drain timeout must not turn it into a new delivery.
	retireTiePairCoordinatorStream(context.Background(), testTieCompletionStream{reader: tieCompletionErrorReader{errors.New("host closed")}})
	retireTiePairCoordinatorStream(context.Background(), testTieCompletionStream{closeWrite: func() error { return errors.New("already closed") }})
}
