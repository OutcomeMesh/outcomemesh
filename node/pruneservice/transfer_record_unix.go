//go:build linux || darwin

package pruneservice

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodygateway"
)

const transferPrefix = "transfer-"
const transferCommitted = "transfer-committed"
const maximumTransferBytes = 128 << 10

type signedTransfer struct {
	Review    TransferReview
	Signature [ed25519.SignatureSize]byte
}

func (r TransferReview) signedBytes(root string) ([]byte, error) {
	h, err := r.ID()
	if err != nil {
		return nil, err
	}
	key, err := readKey(filepath.Join(root, "transport-key"))
	if err != nil {
		return nil, err
	}
	defer clear(key)
	record := signedTransfer{Review: r}
	m := types.DomainHash(domain+"transfer/local-owner-sign/v0", h[:])
	copy(record.Signature[:], ed25519.Sign(key, m[:]))
	return json.Marshal(record)
}

func (r TransferReview) containers() (string, string) {
	if r.Bundle != (TransferBundle{}) {
		return r.Bundle.Source, r.Bundle.Destination
	}
	return r.Source, r.Destination
}

func nativeDirectoryID(path string) (types.Hash, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return types.Hash{}, err
	}
	n, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return types.Hash{}, ErrOwner
	}
	return types.DomainHash(domain+"transfer-directory/v0", []byte(fmt.Sprintf("%s\n%d/%d/%d/%d", path, n.Dev, n.Ino, n.Uid, info.Mode()))), nil
}

func absent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return false, err
}

func transferRecordName(s string) bool {
	if len(s) != len(transferPrefix)+64 || !strings.HasPrefix(s, transferPrefix) {
		return false
	}
	hexID := s[len(transferPrefix):]
	_, err := hex.DecodeString(hexID)
	return err == nil && hexID == strings.ToLower(hexID)
}

// The first exclusive create reserves its review ID in the name, even when a
// crash or short write leaves the record at zero bytes.
func findTransfer(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	var found string
	for _, e := range entries {
		if e.Name() == transferCommitted || !strings.HasPrefix(e.Name(), transferPrefix) {
			continue
		}
		if found != "" || !transferRecordName(e.Name()) || !e.Type().IsRegular() {
			return "", ErrOwner
		}
		found = e.Name()
	}
	return found, nil
}

func requireNoTransfer(root string) error {
	name, err := findTransfer(root)
	if err != nil {
		return err
	}
	missing, err := absent(filepath.Join(root, transferCommitted))
	if err != nil {
		return err
	}
	if name != "" || !missing {
		return ErrHeld
	}
	return nil
}

// A signed receipt alone cannot rebind an owner. Verify the original physical
// placement under its enrolled name, then the destination container and parent.
func destinationRecord(root string) (*TransferReview, error) {
	name, err := findTransfer(root)
	if err != nil || name == "" {
		return nil, errors.Join(ErrOwner, err)
	}
	raw, err := privateRead(filepath.Join(root, name), maximumTransferBytes)
	if err != nil {
		return nil, err
	}
	var record signedTransfer
	if err = json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonical) || record.Review.Destination != root {
		return nil, ErrOwner
	}
	r := record.Review
	h, err := r.ID()
	if err != nil {
		return nil, err
	}
	if name != transferPrefix+h.String() {
		return nil, ErrOwner
	}
	b, err := privateRead(filepath.Join(root, "identity"), 1024)
	if err != nil {
		return nil, err
	}
	var id Identity
	m := types.DomainHash(domain+"transfer/local-owner-sign/v0", h[:])
	if json.Unmarshal(b, &id) != nil || id.RootID != r.RootID || !ed25519.Verify(id.Transport[:], m[:], record.Signature[:]) {
		return nil, ErrOwner
	}
	idAt, err := rootIDAt(root, r.Source)
	if err != nil || idAt != id.RootID {
		return nil, errors.Join(ErrOwner, err)
	}
	source, dest := r.containers()
	cid, err := custodygateway.PlacementIDAt(dest, source, true)
	if err != nil || cid != r.ContainerID {
		return nil, errors.Join(ErrOwner, err)
	}
	pid, err := nativeDirectoryID(filepath.Dir(dest))
	if err != nil || pid != r.DestinationParentID {
		return nil, errors.Join(ErrOwner, err)
	}
	return &r, nil
}

func activeTransfer(root string) (*TransferReview, error) {
	r, err := readActiveTransfer(root)
	if err != nil || r == nil {
		return r, err
	}
	// Complete a previously interrupted commit-marker directory sync before use.
	return r, syncDirectory(root)
}

func readActiveTransfer(root string) (*TransferReview, error) {
	name, err := findTransfer(root)
	if err != nil {
		return nil, err
	}
	if name == "" {
		missing, err := absent(filepath.Join(root, transferCommitted))
		if err != nil || !missing {
			return nil, errors.Join(ErrHeld, err)
		}
		return nil, nil
	}
	r, err := destinationRecord(root)
	if err != nil {
		return nil, errors.Join(ErrHeld, err)
	}
	// Zero bytes are the entire commit marker. It is created only after the
	// two parent fsyncs and the destination's original-store revalidation.
	if _, err = privateRead(filepath.Join(root, transferCommitted), 0); err != nil {
		return nil, errors.Join(ErrHeld, err)
	}
	return r, nil
}

func transferForOpen(root string, moving *TransferReview) (*TransferReview, error) {
	if moving == nil {
		return activeTransfer(root)
	}
	if root == moving.Source {
		missing, err := absent(filepath.Join(root, transferCommitted))
		if err != nil || !missing {
			return nil, errors.Join(ErrOwner, err)
		}
		return nil, nil // the exact source marker or its prefix is checked under lock
	}
	r, err := destinationRecord(root)
	if err != nil {
		return nil, err
	}
	if r.Source != moving.Source || r.Destination != moving.Destination || r.Bundle != moving.Bundle || r.DescriptorID != moving.DescriptorID {
		return nil, ErrOwner
	}
	return r, nil
}

// For public placement checks only. It reads no signing key or runtime store.
func effectiveTransferConfig(root string, c Config) (Config, error) {
	r, err := readActiveTransfer(root)
	if err != nil {
		return Config{}, err
	}
	if r != nil && r.Bundle != (TransferBundle{}) {
		return relocatedConfig(c, r.Bundle)
	}
	return c, nil
}
