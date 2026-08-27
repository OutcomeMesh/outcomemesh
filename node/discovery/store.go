package discovery

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
)

const (
	bookVersion  uint16 = 0
	MaxBookBytes        = 9 * 1024 * 1024
)

var (
	bookMagic       = [8]byte{'O', 'M', 'P', 'E', 'E', 'R', 'S', '0'}
	ErrBookEncoding = errors.New("invalid persisted peer address book")
)

// CanonicalBytes returns the deterministic local-policy encoding of all live
// records. It is not a consensus object and is never accepted from the wire.
func (book *Book) CanonicalBytes(now uint64) ([]byte, error) {
	if book == nil {
		return nil, ErrPolicy
	}
	records := book.List(now, book.maxRecords)
	encoder := codec.NewEncoder(16 + len(records)*256)
	encoder.Fixed(bookMagic[:])
	encoder.U16(bookVersion)
	encoder.U32(book.networkID)
	encoder.Uvarint(uint64(len(records)))
	for _, record := range records {
		encoded := record.CanonicalBytes()
		if len(encoded) == 0 || len(encoded) > MaxRecordBytes {
			return nil, ErrBookEncoding
		}
		encoder.BytesField(encoded)
	}
	result := encoder.Bytes()
	if len(result) > MaxBookBytes {
		return nil, ErrBookEncoding
	}
	return result, nil
}

func DecodeBook(input []byte, expectedNetwork uint32, policy Policy, now uint64) (*Book, error) {
	if len(input) == 0 || len(input) > MaxBookBytes {
		return nil, ErrBookEncoding
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(bookMagic))
	if err != nil || string(magic) != string(bookMagic[:]) {
		return nil, ErrBookEncoding
	}
	version, err := decoder.U16()
	if err != nil || version != bookVersion {
		return nil, ErrBookEncoding
	}
	networkID, err := decoder.U32()
	if err != nil || networkID == 0 || networkID != expectedNetwork {
		return nil, ErrNetwork
	}
	book, err := NewBookWithPolicy(networkID, policy)
	if err != nil {
		return nil, err
	}
	count, err := decoder.ListLength(uint64(policy.MaxRecords))
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0, count)
	for range count {
		encoded, err := decoder.BytesField(MaxRecordBytes)
		if err != nil {
			return nil, err
		}
		record, err := Decode(encoded)
		if err != nil {
			return nil, err
		}
		if err := record.Validate(now); errors.Is(err, ErrExpired) {
			continue
		} else if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	if err := book.AddBatch(records, now); err != nil {
		return nil, err
	}
	return book, nil
}

// SaveFile atomically replaces a local peerbook and fsyncs both file and
// directory. Peerbooks contain no private keys but are written with mode 0600.
func SaveFile(path string, book *Book, now uint64) error {
	if path == "" {
		return ErrBookEncoding
	}
	encoded, err := book.CanonicalBytes(now)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".outcomemesh-peers-*")
	if err != nil {
		return err
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
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func LoadFile(path string, expectedNetwork uint32, policy Policy, now uint64) (*Book, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaxBookBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxBookBytes {
		return nil, ErrBookEncoding
	}
	return DecodeBook(encoded, expectedNetwork, policy, now)
}
