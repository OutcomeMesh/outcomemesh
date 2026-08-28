package calibration

import (
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
)

const (
	manifestVersion      uint16 = 0
	MaximumManifestBytes        = 64 * 1024 * 1024
)

var manifestMagic = [8]byte{'O', 'M', 'T', 'E', 'L', 'E', 'M', '0'}

func EncodeManifest(records []Record, expected Binding) ([]byte, Aggregate, error) {
	aggregate, err := ValidateManifest(records, expected)
	if err != nil {
		return nil, Aggregate{}, err
	}
	encoder := codec.NewEncoder(16 + len(records)*512)
	encoder.Fixed(manifestMagic[:])
	encoder.U16(manifestVersion)
	encoder.Uvarint(uint64(len(records)))
	for _, record := range records {
		encoded := record.CanonicalBytes()
		if len(encoded) == 0 || len(encoded) > MaximumRecordBytes {
			return nil, Aggregate{}, ErrManifestLimit
		}
		encoder.BytesField(encoded)
	}
	encoded := encoder.Bytes()
	if len(encoded) > MaximumManifestBytes {
		return nil, Aggregate{}, ErrManifestLimit
	}
	return encoded, aggregate, nil
}

func DecodeManifest(input []byte, expected Binding) ([]Record, Aggregate, error) {
	if len(input) == 0 || len(input) > MaximumManifestBytes {
		return nil, Aggregate{}, ErrManifestLimit
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(manifestMagic))
	if err != nil || string(magic) != string(manifestMagic[:]) {
		return nil, Aggregate{}, ErrManifest
	}
	version, err := decoder.U16()
	if err != nil || version != manifestVersion {
		return nil, Aggregate{}, ErrManifest
	}
	count, err := decoder.ListLength(MaximumManifestRecords)
	if err != nil || count == 0 {
		return nil, Aggregate{}, ErrManifest
	}
	records := make([]Record, count)
	for index := range records {
		encoded, err := decoder.BytesField(MaximumRecordBytes)
		if err != nil {
			return nil, Aggregate{}, err
		}
		records[index], err = DecodeRecord(encoded)
		if err != nil {
			return nil, Aggregate{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return nil, Aggregate{}, err
	}
	aggregate, err := ValidateManifest(records, expected)
	if err != nil {
		return nil, Aggregate{}, err
	}
	return records, aggregate, nil
}

// SaveFile atomically replaces the local materialization of an append-only
// signed chain and fsyncs both file and directory. Historical mutation remains
// detectable through record links; a separately published tail ID is required
// to detect replacement with an older valid prefix.
func SaveFile(path string, records []Record, expected Binding) (Aggregate, error) {
	if path == "" {
		return Aggregate{}, ErrManifest
	}
	encoded, aggregate, err := EncodeManifest(records, expected)
	if err != nil {
		return Aggregate{}, err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return Aggregate{}, err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-telemetry-*")
	if err != nil {
		return Aggregate{}, err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return Aggregate{}, err
	}
	written, err := temporary.Write(encoded)
	if err != nil {
		return Aggregate{}, err
	}
	if written != len(encoded) {
		return Aggregate{}, io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return Aggregate{}, err
	}
	if err := temporary.Close(); err != nil {
		return Aggregate{}, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return Aggregate{}, err
	}
	committed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return Aggregate{}, err
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return Aggregate{}, err
	}
	return aggregate, nil
}

func LoadFile(path string, expected Binding) ([]Record, Aggregate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, Aggregate{}, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaximumManifestBytes+1))
	if err != nil {
		return nil, Aggregate{}, err
	}
	if len(encoded) > MaximumManifestBytes {
		return nil, Aggregate{}, ErrManifestLimit
	}
	return DecodeManifest(encoded, expected)
}
