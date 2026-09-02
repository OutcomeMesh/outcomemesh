package workarchive

import (
	"bytes"
	"errors"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	ObjectExchangeVersion0    uint16 = 0
	MaximumObjectRequestIDs          = 64
	MaximumObjectBatchObjects        = 64
	MaximumObjectRequestBytes        = 8 + 2 + types.HashSize + 10 + MaximumObjectRequestIDs*types.HashSize
	MaximumObjectBatchBytes          = MaximumChunkBytes + 8*1024
)

var (
	ErrObjectRequest = errors.New("invalid WorkGraph archive object request")
	ErrObjectBatch   = errors.New("invalid WorkGraph archive object batch")
)

var (
	objectRequestMagic = [8]byte{'O', 'M', 'W', 'A', 'O', 'B', 'R', 'Q'}
	objectBatchMagic   = [8]byte{'O', 'M', 'W', 'A', 'O', 'B', 'B', 'T'}
)

type ChunkRequest struct {
	Version    uint16
	ManifestID types.Hash
	IDs        []types.Hash
}

type ChunkObject struct {
	ID      types.Hash
	Encoded []byte
}

type ChunkBatch struct {
	Version    uint16
	ManifestID types.Hash
	Objects    []ChunkObject
}

type ObjectApplyReport struct {
	AddedObjects  uint64
	ReusedObjects uint64
	AddedBytes    uint64
}

func BuildChunkRequest(
	manifest Manifest,
	store *ObjectStore,
	maximumObjects uint16,
) (ChunkRequest, bool, error) {
	if manifest.Validate() != nil || store == nil || maximumObjects == 0 ||
		maximumObjects > MaximumObjectRequestIDs {
		return ChunkRequest{}, false, ErrObjectRequest
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return ChunkRequest{}, false, err
	}
	missing, err := store.Missing(manifest)
	if err != nil {
		return ChunkRequest{}, false, err
	}
	if len(missing) == 0 {
		return ChunkRequest{}, true, nil
	}
	sort.Slice(missing, func(left, right int) bool {
		return types.CompareHash(missing[left], missing[right]) < 0
	})
	ids := make([]types.Hash, 0, min(int(maximumObjects), len(missing)))
	var encodedBytes uint64
	for _, id := range missing {
		if len(ids) == int(maximumObjects) {
			break
		}
		descriptor, exists := manifestDescriptor(manifest, id)
		if !exists || uint64(descriptor.EncodedBytes) > MaximumChunkBytes-encodedBytes {
			if len(ids) == 0 {
				return ChunkRequest{}, false, ErrObjectRequest
			}
			break
		}
		ids = append(ids, id)
		encodedBytes += uint64(descriptor.EncodedBytes)
	}
	request := ChunkRequest{
		Version: ObjectExchangeVersion0, ManifestID: manifestID, IDs: ids,
	}
	if request.Validate() != nil {
		return ChunkRequest{}, false, ErrObjectRequest
	}
	return request, false, nil
}

func ServeChunkRequest(
	store *ObjectStore,
	manifest Manifest,
	request ChunkRequest,
) (ChunkBatch, error) {
	if store == nil || manifest.Validate() != nil || request.Validate() != nil {
		return ChunkBatch{}, ErrObjectRequest
	}
	manifestID, err := manifest.ID()
	if err != nil || request.ManifestID != manifestID {
		return ChunkBatch{}, ErrObjectRequest
	}
	batch := ChunkBatch{
		Version: ObjectExchangeVersion0, ManifestID: manifestID,
		Objects: make([]ChunkObject, len(request.IDs)),
	}
	var encodedBytes uint64
	for index, id := range request.IDs {
		descriptor, exists := manifestDescriptor(manifest, id)
		if !exists || uint64(descriptor.EncodedBytes) > MaximumChunkBytes-encodedBytes {
			return ChunkBatch{}, ErrObjectRequest
		}
		encoded, err := store.Get(id)
		if err != nil || validateChunkObject(manifest, descriptor, encoded) != nil {
			return ChunkBatch{}, errors.Join(ErrObjectBatch, err)
		}
		batch.Objects[index] = ChunkObject{ID: id, Encoded: encoded}
		encodedBytes += uint64(len(encoded))
	}
	if batch.Validate() != nil {
		return ChunkBatch{}, ErrObjectBatch
	}
	return batch, nil
}

func ApplyChunkBatch(
	store *ObjectStore,
	manifest Manifest,
	batch ChunkBatch,
) (ObjectApplyReport, error) {
	if store == nil || manifest.Validate() != nil || batch.Validate() != nil {
		return ObjectApplyReport{}, ErrObjectBatch
	}
	manifestID, err := manifest.ID()
	if err != nil || batch.ManifestID != manifestID {
		return ObjectApplyReport{}, ErrObjectBatch
	}
	report := ObjectApplyReport{}
	for _, object := range batch.Objects {
		added, err := store.Put(manifest, object.ID, object.Encoded)
		if err != nil {
			return report, errors.Join(ErrObjectBatch, err)
		}
		if added {
			report.AddedObjects++
			report.AddedBytes += uint64(len(object.Encoded))
		} else {
			report.ReusedObjects++
		}
	}
	return report, nil
}

func (request ChunkRequest) Validate() error {
	if request.Version != ObjectExchangeVersion0 || request.ManifestID.IsZero() ||
		len(request.IDs) == 0 || len(request.IDs) > MaximumObjectRequestIDs {
		return ErrObjectRequest
	}
	for index, id := range request.IDs {
		if id.IsZero() || (index > 0 && types.CompareHash(request.IDs[index-1], id) >= 0) {
			return ErrObjectRequest
		}
	}
	return nil
}

func (request ChunkRequest) CanonicalBytes() ([]byte, error) {
	if request.Validate() != nil {
		return nil, ErrObjectRequest
	}
	encoder := codec.NewEncoder(MaximumObjectRequestBytes)
	encoder.Fixed(objectRequestMagic[:])
	encoder.U16(request.Version)
	encoder.Fixed(request.ManifestID[:])
	encoder.Uvarint(uint64(len(request.IDs)))
	for _, id := range request.IDs {
		encoder.Fixed(id[:])
	}
	return encoder.Bytes(), nil
}

func DecodeChunkRequest(input []byte) (ChunkRequest, error) {
	if len(input) == 0 || len(input) > MaximumObjectRequestBytes {
		return ChunkRequest{}, ErrObjectRequest
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(objectRequestMagic))
	if err != nil || !bytes.Equal(magic, objectRequestMagic[:]) {
		return ChunkRequest{}, ErrObjectRequest
	}
	request := ChunkRequest{}
	if request.Version, err = decoder.U16(); err != nil {
		return ChunkRequest{}, err
	}
	manifestID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return ChunkRequest{}, err
	}
	copy(request.ManifestID[:], manifestID)
	count, err := decoder.ListLength(MaximumObjectRequestIDs)
	if err != nil || count == 0 {
		return ChunkRequest{}, ErrObjectRequest
	}
	request.IDs = make([]types.Hash, count)
	for index := range request.IDs {
		encoded, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return ChunkRequest{}, decodeErr
		}
		copy(request.IDs[index][:], encoded)
	}
	if err := decoder.Finish(); err != nil || request.Validate() != nil {
		return ChunkRequest{}, ErrObjectRequest
	}
	return request, nil
}

func (batch ChunkBatch) Validate() error {
	if batch.Version != ObjectExchangeVersion0 || batch.ManifestID.IsZero() ||
		len(batch.Objects) == 0 || len(batch.Objects) > MaximumObjectBatchObjects {
		return ErrObjectBatch
	}
	total := 8 + 2 + types.HashSize + 10
	for index, object := range batch.Objects {
		if object.ID.IsZero() || len(object.Encoded) == 0 || len(object.Encoded) > MaximumChunkBytes ||
			(index > 0 && types.CompareHash(batch.Objects[index-1].ID, object.ID) >= 0) {
			return ErrObjectBatch
		}
		fieldBytes := types.HashSize + uvarintSize(uint64(len(object.Encoded))) + len(object.Encoded)
		if fieldBytes > MaximumObjectBatchBytes || total > MaximumObjectBatchBytes-fieldBytes {
			return ErrObjectBatch
		}
		total += fieldBytes
	}
	return nil
}

func (batch ChunkBatch) CanonicalBytes() ([]byte, error) {
	if batch.Validate() != nil {
		return nil, ErrObjectBatch
	}
	encoder := codec.NewEncoder(1024)
	encoder.Fixed(objectBatchMagic[:])
	encoder.U16(batch.Version)
	encoder.Fixed(batch.ManifestID[:])
	encoder.Uvarint(uint64(len(batch.Objects)))
	for _, object := range batch.Objects {
		encoder.Fixed(object.ID[:])
		encoder.BytesField(object.Encoded)
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumObjectBatchBytes {
		return nil, ErrObjectBatch
	}
	return encoded, nil
}

func DecodeChunkBatch(input []byte) (ChunkBatch, error) {
	if len(input) == 0 || len(input) > MaximumObjectBatchBytes {
		return ChunkBatch{}, ErrObjectBatch
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(objectBatchMagic))
	if err != nil || !bytes.Equal(magic, objectBatchMagic[:]) {
		return ChunkBatch{}, ErrObjectBatch
	}
	batch := ChunkBatch{}
	if batch.Version, err = decoder.U16(); err != nil {
		return ChunkBatch{}, err
	}
	manifestID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return ChunkBatch{}, err
	}
	copy(batch.ManifestID[:], manifestID)
	count, err := decoder.ListLength(MaximumObjectBatchObjects)
	if err != nil || count == 0 {
		return ChunkBatch{}, ErrObjectBatch
	}
	batch.Objects = make([]ChunkObject, count)
	for index := range batch.Objects {
		id, decodeErr := decoder.Fixed(types.HashSize)
		if decodeErr != nil {
			return ChunkBatch{}, decodeErr
		}
		copy(batch.Objects[index].ID[:], id)
		batch.Objects[index].Encoded, err = decoder.BytesField(MaximumChunkBytes)
		if err != nil {
			return ChunkBatch{}, err
		}
	}
	if err := decoder.Finish(); err != nil || batch.Validate() != nil {
		return ChunkBatch{}, ErrObjectBatch
	}
	return batch, nil
}
