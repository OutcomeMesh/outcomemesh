package workarchive

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	MaximumObjectSessionBatches = 4
	MinimumObjectSessionTimeout = 100 * time.Millisecond
	MaximumObjectSessionTimeout = 10 * time.Minute
)

var ErrObjectSession = errors.New("invalid WorkGraph archive object session")

type ObjectSessionStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

type ObjectSessionConfig struct {
	RequestTimeout time.Duration
}

func DefaultObjectSessionConfig() ObjectSessionConfig {
	return ObjectSessionConfig{RequestTimeout: 2 * time.Minute}
}

func (config ObjectSessionConfig) Validate() error {
	if config.RequestTimeout < MinimumObjectSessionTimeout ||
		config.RequestTimeout > MaximumObjectSessionTimeout {
		return ErrObjectSession
	}
	return nil
}

type ObjectFetchReport struct {
	ManifestID    types.Hash
	Requests      uint16
	Objects       uint64
	AddedObjects  uint64
	ReusedObjects uint64
	ReceivedBytes uint64
	Complete      bool
}

type ObjectServeReport struct {
	ManifestID types.Hash
	Requests   uint16
	Objects    uint64
	SentBytes  uint64
}

type ObjectSession struct {
	manifest   Manifest
	manifestID types.Hash
	store      *ObjectStore
	config     ObjectSessionConfig
}

func NewObjectSession(
	manifest Manifest,
	store *ObjectStore,
	config ObjectSessionConfig,
) (*ObjectSession, error) {
	if manifest.Validate() != nil || store == nil || config.Validate() != nil {
		return nil, ErrObjectSession
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return nil, err
	}
	return &ObjectSession{
		manifest: manifest, manifestID: manifestID, store: store, config: config,
	}, nil
}

// Fetch runs one finite pull session. A false Complete result is normal: the
// caller may open another authenticated stream and resume from the same store.
func (session *ObjectSession) Fetch(
	ctx context.Context,
	stream ObjectSessionStream,
) (ObjectFetchReport, error) {
	if session == nil || ctx == nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		return ObjectFetchReport{}, ErrObjectSession
	}
	defer stream.Close()
	report := ObjectFetchReport{ManifestID: session.manifestID}
	for report.Requests < MaximumObjectSessionBatches {
		request, complete, err := BuildChunkRequest(
			session.manifest, session.store, MaximumObjectRequestIDs,
		)
		if err != nil {
			return report, err
		}
		if complete {
			report.Complete = true
			return report, nil
		}
		encodedRequest, err := request.CanonicalBytes()
		if err != nil {
			return report, err
		}
		if err := session.writeFrame(ctx, stream, encodedRequest); err != nil {
			return report, err
		}
		report.Requests++
		encodedBatch, err := session.readFrame(ctx, stream, MaximumObjectBatchBytes)
		if err != nil {
			return report, err
		}
		batch, err := DecodeChunkBatch(encodedBatch)
		if err != nil || !objectBatchAnswersRequest(batch, request) {
			return report, errors.Join(ErrObjectSession, err)
		}
		report.Objects += uint64(len(batch.Objects))
		for _, object := range batch.Objects {
			report.ReceivedBytes += uint64(len(object.Encoded))
		}
		applied, err := ApplyChunkBatch(session.store, session.manifest, batch)
		report.AddedObjects += applied.AddedObjects
		report.ReusedObjects += applied.ReusedObjects
		if err != nil {
			return report, errors.Join(ErrObjectSession, err)
		}
	}
	_, complete, err := BuildChunkRequest(
		session.manifest, session.store, MaximumObjectRequestIDs,
	)
	if err != nil {
		return report, err
	}
	report.Complete = complete
	return report, nil
}

// Serve answers one finite stream from a caller already authenticated and
// authorized by the transport. Repeated IDs cannot amplify bytes in-session.
func (session *ObjectSession) Serve(
	ctx context.Context,
	stream ObjectSessionStream,
) (ObjectServeReport, error) {
	if session == nil || ctx == nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		return ObjectServeReport{}, ErrObjectSession
	}
	defer stream.Close()
	report := ObjectServeReport{ManifestID: session.manifestID}
	served := make(map[types.Hash]struct{})
	for report.Requests < MaximumObjectSessionBatches {
		encodedRequest, err := session.readFrame(ctx, stream, MaximumObjectRequestBytes)
		if errors.Is(err, io.EOF) {
			return report, nil
		}
		if err != nil {
			return report, err
		}
		request, err := DecodeChunkRequest(encodedRequest)
		if err != nil {
			return report, errors.Join(ErrObjectSession, err)
		}
		for _, id := range request.IDs {
			if _, duplicate := served[id]; duplicate {
				return report, ErrObjectSession
			}
			served[id] = struct{}{}
		}
		batch, err := ServeChunkRequest(session.store, session.manifest, request)
		if err != nil {
			return report, errors.Join(ErrObjectSession, err)
		}
		encodedBatch, err := batch.CanonicalBytes()
		if err != nil {
			return report, err
		}
		if err := session.writeFrame(ctx, stream, encodedBatch); err != nil {
			return report, err
		}
		report.Requests++
		report.Objects += uint64(len(batch.Objects))
		for _, object := range batch.Objects {
			report.SentBytes += uint64(len(object.Encoded))
		}
	}
	return report, nil
}

func objectBatchAnswersRequest(batch ChunkBatch, request ChunkRequest) bool {
	if batch.ManifestID != request.ManifestID || len(batch.Objects) != len(request.IDs) {
		return false
	}
	for index, object := range batch.Objects {
		if object.ID != request.IDs[index] {
			return false
		}
	}
	return true
}

func (session *ObjectSession) readFrame(
	ctx context.Context,
	stream ObjectSessionStream,
	maximum int,
) ([]byte, error) {
	if err := session.setDeadline(ctx, stream); err != nil {
		return nil, err
	}
	return readObjectSessionFrame(stream, maximum)
}

func (session *ObjectSession) writeFrame(
	ctx context.Context,
	stream ObjectSessionStream,
	encoded []byte,
) error {
	if err := session.setDeadline(ctx, stream); err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > MaximumObjectBatchBytes {
		return ErrObjectSession
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(encoded)))
	if err := writeObjectSessionBytes(stream, prefix[:]); err != nil {
		return err
	}
	return writeObjectSessionBytes(stream, encoded)
}

func (session *ObjectSession) setDeadline(ctx context.Context, stream ObjectSessionStream) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(session.config.RequestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return stream.SetDeadline(deadline)
}

func readObjectSessionFrame(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil || maximum <= 0 || maximum > MaximumObjectBatchBytes {
		return nil, ErrObjectSession
	}
	var prefix [4]byte
	read, err := io.ReadFull(reader, prefix[:])
	if err != nil {
		if read == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, errors.Join(ErrObjectSession, err)
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || uint64(size) > uint64(maximum) {
		return nil, ErrObjectSession
	}
	encoded := make([]byte, int(size))
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return nil, errors.Join(ErrObjectSession, err)
	}
	return encoded, nil
}

func writeObjectSessionBytes(writer io.Writer, encoded []byte) error {
	for len(encoded) > 0 {
		written, err := writer.Write(encoded)
		if err != nil {
			return errors.Join(ErrObjectSession, err)
		}
		if written <= 0 || written > len(encoded) {
			return errors.Join(ErrObjectSession, io.ErrShortWrite)
		}
		encoded = encoded[written:]
	}
	return nil
}
