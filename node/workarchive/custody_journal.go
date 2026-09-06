package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	CustodyJournalHeaderVersion0 uint16 = 0
	CustodyJournalEntryVersion0  uint16 = 0
	custodyJournalSlotVersion0   uint16 = 0

	MaximumCustodyJournalHeaderBytes = MaximumReplicaReceiptBytes + 128
	MaximumCustodyJournalEntryBytes  = MaximumReplicaReceiptBytes + MaximumCustodyRecordBytes + 192
	maximumCustodyJournalSlotBytes   = 128
	custodyJournalSlotsPerBucket     = 1_024
)

const (
	custodyJournalEntryIDDomain  = "OMESH/workgraph/archive/custody-journal-entry/id/v0"
	custodyJournalPolicyIDDomain = "OMESH/workgraph/archive/custody-journal-policy/id/v0"
)

var ErrCustodyJournal = errors.New("invalid WorkGraph archive custody journal")

var (
	custodyJournalHeaderMagic = [8]byte{'O', 'M', 'W', 'A', 'C', 'J', 'H', 'D'}
	custodyJournalEntryMagic  = [8]byte{'O', 'M', 'W', 'A', 'C', 'J', 'E', 'N'}
	custodyJournalSlotMagic   = [8]byte{'O', 'M', 'W', 'A', 'C', 'J', 'S', 'L'}
)

const (
	custodyJournalHeaderName   = "header.omcj"
	custodyJournalLockName     = "journal.lock"
	custodyJournalObjectsName  = "objects"
	custodyJournalActiveName   = "active"
	custodyJournalSegmentsName = "segments"
	custodyJournalSlotsName    = "slots"
	custodyJournalPendingName  = "pending"
)

// CustodyJournalHeader fixes the manifest and initial receipt from which every
// journal state must be replayed. It is immutable after first publication.
type CustodyJournalHeader struct {
	Version        uint16
	ManifestID     types.Hash
	PolicyID       types.Hash
	InitialReceipt ReplicaReceipt
}

func (header CustodyJournalHeader) CanonicalBytes() ([]byte, error) {
	if header.verifyShape() != nil {
		return nil, ErrCustodyJournal
	}
	receipt, err := header.InitialReceipt.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(len(receipt) + 64)
	encoder.Fixed(custodyJournalHeaderMagic[:])
	encoder.U16(header.Version)
	encoder.Fixed(header.ManifestID[:])
	encoder.Fixed(header.PolicyID[:])
	encoder.BytesField(receipt)
	encoded := encoder.Bytes()
	if len(encoded) > MaximumCustodyJournalHeaderBytes {
		return nil, ErrCustodyJournal
	}
	return encoded, nil
}

func DecodeCustodyJournalHeader(input []byte) (CustodyJournalHeader, error) {
	if len(input) == 0 || len(input) > MaximumCustodyJournalHeaderBytes {
		return CustodyJournalHeader{}, ErrCustodyJournal
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(custodyJournalHeaderMagic))
	if err != nil || !bytes.Equal(magic, custodyJournalHeaderMagic[:]) {
		return CustodyJournalHeader{}, ErrCustodyJournal
	}
	var header CustodyJournalHeader
	if header.Version, err = decoder.U16(); err != nil {
		return CustodyJournalHeader{}, errors.Join(ErrCustodyJournal, err)
	}
	manifestID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return CustodyJournalHeader{}, errors.Join(ErrCustodyJournal, err)
	}
	copy(header.ManifestID[:], manifestID)
	policyID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return CustodyJournalHeader{}, errors.Join(ErrCustodyJournal, err)
	}
	copy(header.PolicyID[:], policyID)
	receipt, err := decoder.BytesField(MaximumReplicaReceiptBytes)
	if err != nil {
		return CustodyJournalHeader{}, errors.Join(ErrCustodyJournal, err)
	}
	header.InitialReceipt, err = DecodeReplicaReceipt(receipt)
	if err != nil {
		return CustodyJournalHeader{}, errors.Join(ErrCustodyJournal, err)
	}
	if decoder.Finish() != nil || header.verifyShape() != nil {
		return CustodyJournalHeader{}, ErrCustodyJournal
	}
	return header, nil
}

func (header CustodyJournalHeader) verifyShape() error {
	if header.Version != CustodyJournalHeaderVersion0 || header.ManifestID.IsZero() ||
		header.PolicyID.IsZero() ||
		header.InitialReceipt.verifySignature() != nil {
		return ErrCustodyJournal
	}
	return nil
}

// CustodyJournalEntry carries enough evidence to verify one renewal without
// trusting a mutable head file. PreviousEntryID turns the sequence into a
// hash-linked decision chain while PreviousReceipt makes every step explicit.
type CustodyJournalEntry struct {
	Version         uint16
	Sequence        uint64
	PreviousEntryID types.Hash
	PreviousReceipt ReplicaReceipt
	Record          CustodyRecord
}

func (entry CustodyJournalEntry) CanonicalBytes() ([]byte, error) {
	if entry.verifyShape() != nil {
		return nil, ErrCustodyJournal
	}
	previous, err := entry.PreviousReceipt.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	record, err := entry.Record.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(len(previous) + len(record) + 96)
	encoder.Fixed(custodyJournalEntryMagic[:])
	encoder.U16(entry.Version)
	encoder.U64(entry.Sequence)
	encoder.Fixed(entry.PreviousEntryID[:])
	encoder.BytesField(previous)
	encoder.BytesField(record)
	encoded := encoder.Bytes()
	if len(encoded) > MaximumCustodyJournalEntryBytes {
		return nil, ErrCustodyJournal
	}
	return encoded, nil
}

func DecodeCustodyJournalEntry(input []byte) (CustodyJournalEntry, error) {
	if len(input) == 0 || len(input) > MaximumCustodyJournalEntryBytes {
		return CustodyJournalEntry{}, ErrCustodyJournal
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(custodyJournalEntryMagic))
	if err != nil || !bytes.Equal(magic, custodyJournalEntryMagic[:]) {
		return CustodyJournalEntry{}, ErrCustodyJournal
	}
	var entry CustodyJournalEntry
	if entry.Version, err = decoder.U16(); err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	if entry.Sequence, err = decoder.U64(); err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	previousID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	copy(entry.PreviousEntryID[:], previousID)
	previous, err := decoder.BytesField(MaximumReplicaReceiptBytes)
	if err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	entry.PreviousReceipt, err = DecodeReplicaReceipt(previous)
	if err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	record, err := decoder.BytesField(MaximumCustodyRecordBytes)
	if err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	entry.Record, err = DecodeCustodyRecord(record)
	if err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	if decoder.Finish() != nil || entry.verifyShape() != nil {
		return CustodyJournalEntry{}, ErrCustodyJournal
	}
	return entry, nil
}

func (entry CustodyJournalEntry) ID() (types.Hash, error) {
	encoded, err := entry.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(custodyJournalEntryIDDomain, encoded), nil
}

func (entry CustodyJournalEntry) Verify(
	manifest Manifest,
	policy CustodyPolicy,
	sequence uint64,
	previousEntryID types.Hash,
	previousReceipt ReplicaReceipt,
) error {
	if sequence == 0 || entry.verifyShape() != nil || entry.Sequence != sequence ||
		entry.PreviousEntryID != previousEntryID || entry.PreviousReceipt != previousReceipt ||
		entry.Record.Verify(manifest, previousReceipt, policy) != nil {
		return ErrCustodyJournal
	}
	return nil
}

func (entry CustodyJournalEntry) verifyShape() error {
	if entry.Version != CustodyJournalEntryVersion0 || entry.Sequence == 0 ||
		entry.PreviousReceipt.verifySignature() != nil || entry.Record.verifyShape() != nil ||
		(entry.Sequence == 1) != entry.PreviousEntryID.IsZero() {
		return ErrCustodyJournal
	}
	return nil
}

type custodyJournalSlot struct {
	Version  uint16
	Sequence uint64
	EntryID  types.Hash
}

func (slot custodyJournalSlot) canonicalBytes() ([]byte, error) {
	if slot.Version != custodyJournalSlotVersion0 || slot.Sequence == 0 || slot.EntryID.IsZero() {
		return nil, ErrCustodyJournal
	}
	encoder := codec.NewEncoder(maximumCustodyJournalSlotBytes)
	encoder.Fixed(custodyJournalSlotMagic[:])
	encoder.U16(slot.Version)
	encoder.U64(slot.Sequence)
	encoder.Fixed(slot.EntryID[:])
	return encoder.Bytes(), nil
}

func decodeCustodyJournalSlot(input []byte) (custodyJournalSlot, error) {
	if len(input) == 0 || len(input) > maximumCustodyJournalSlotBytes {
		return custodyJournalSlot{}, ErrCustodyJournal
	}
	decoder := codec.NewDecoder(input)
	magic, err := decoder.Fixed(len(custodyJournalSlotMagic))
	if err != nil || !bytes.Equal(magic, custodyJournalSlotMagic[:]) {
		return custodyJournalSlot{}, ErrCustodyJournal
	}
	var slot custodyJournalSlot
	if slot.Version, err = decoder.U16(); err != nil {
		return custodyJournalSlot{}, errors.Join(ErrCustodyJournal, err)
	}
	if slot.Sequence, err = decoder.U64(); err != nil {
		return custodyJournalSlot{}, errors.Join(ErrCustodyJournal, err)
	}
	entryID, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return custodyJournalSlot{}, errors.Join(ErrCustodyJournal, err)
	}
	copy(slot.EntryID[:], entryID)
	if decoder.Finish() != nil || slot.Version != custodyJournalSlotVersion0 ||
		slot.Sequence == 0 || slot.EntryID.IsZero() {
		return custodyJournalSlot{}, ErrCustodyJournal
	}
	return slot, nil
}

// CustodyJournalState is derived by replaying every immutable slot from the
// header. Sequence zero means that no renewal has been appended yet.
type CustodyJournalState struct {
	InitialReceipt ReplicaReceipt
	CurrentReceipt ReplicaReceipt
	Sequence       uint64
	HeadEntryID    types.Hash
}

// CustodyJournal owns an append-only decision spine. Large entry bodies may be
// moved into immutable segments, but the sharded sequence slots never move.
type CustodyJournal struct {
	path     string
	header   CustodyJournalHeader
	manifest Manifest
	policy   CustodyPolicy
	limits   CustodyJournalLimits
	mu       sync.Mutex
}

func OpenOrCreateCustodyJournal(
	path string,
	manifest Manifest,
	initialReceipt ReplicaReceipt,
	policy CustodyPolicy,
) (*CustodyJournal, CustodyJournalState, error) {
	return OpenOrCreateCustodyJournalWithLimits(path, manifest, initialReceipt, policy, DefaultCustodyJournalLimits())
}

// OpenOrCreateCustodyJournalWithLimits applies local growth limits without
// changing the immutable custody policy. Existing evidence can still be replayed
// above these limits, up to the hard replay path ceiling.
func OpenOrCreateCustodyJournalWithLimits(
	path string,
	manifest Manifest,
	initialReceipt ReplicaReceipt,
	policy CustodyPolicy,
	limits CustodyJournalLimits,
) (*CustodyJournal, CustodyJournalState, error) {
	if err := limits.Validate(); err != nil {
		return nil, CustodyJournalState{}, err
	}
	if path == "" || policy.validate() != nil || manifest.Validate() != nil ||
		initialReceipt.verifySignature() != nil {
		return nil, CustodyJournalState{}, ErrCustodyJournal
	}
	manifestID, err := manifest.ID()
	if err != nil || initialReceipt.ManifestID != manifestID ||
		initialReceipt.Binding != manifest.Binding || initialReceipt.AnchorID != manifest.Anchor.ID {
		return nil, CustodyJournalState{}, ErrCustodyJournal
	}
	policyID, err := custodyJournalPolicyID(policy)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	header := CustodyJournalHeader{
		Version: CustodyJournalHeaderVersion0, ManifestID: manifestID,
		PolicyID: policyID, InitialReceipt: initialReceipt,
	}
	if err := makeCustodyJournalRoot(path); err != nil {
		return nil, CustodyJournalState{}, err
	}
	lock, err := acquireCustodyJournalLock(path)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	defer lock.Close()
	if err := initializeCustodyJournal(path, header, limits); err != nil {
		return nil, CustodyJournalState{}, err
	}
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	manifest, err = DecodeManifest(manifestBytes)
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	policy.TrustedAuditors = append([][ed25519.PublicKeySize]byte(nil), policy.TrustedAuditors...)
	journal := &CustodyJournal{path: path, header: header, manifest: manifest, policy: policy, limits: limits}
	state, err := journal.scan()
	if err != nil {
		return nil, CustodyJournalState{}, err
	}
	return journal, state, nil
}

func (journal *CustodyJournal) State() (CustodyJournalState, error) {
	if journal == nil {
		return CustodyJournalState{}, ErrCustodyJournal
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lock, err := acquireCustodyJournalLock(journal.path)
	if err != nil {
		return CustodyJournalState{}, err
	}
	defer lock.Close()
	return journal.scan()
}

// Head returns the final replay-verified entry. The boolean is false only for
// an initialized journal with no completed renewals.
func (journal *CustodyJournal) Head() (CustodyJournalEntry, bool, error) {
	if journal == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lock, err := acquireCustodyJournalLock(journal.path)
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	defer lock.Close()
	state, err := journal.scan()
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	if state.Sequence == 0 {
		return CustodyJournalEntry{}, false, nil
	}
	entry, err := journal.loadSequence(state.Sequence)
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	return entry, true, nil
}

// Append publishes the body before competing for one immutable sequence slot.
// The slot is the decision: identical challenges converge on its winner while
// a sibling challenge for the same predecessor is rejected.
func (journal *CustodyJournal) Append(
	record CustodyRecord,
) (CustodyJournalEntry, bool, error) {
	return journal.append(record, custodyJournalHooks{})
}

type custodyJournalHooks struct {
	afterBody func()
	afterSlot func()
	afterSeal func()
}

func (journal *CustodyJournal) append(
	record CustodyRecord,
	hooks custodyJournalHooks,
) (CustodyJournalEntry, bool, error) {
	if journal == nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lock, err := acquireCustodyJournalLock(journal.path)
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	defer lock.Close()
	state, err := journal.scan()
	if err != nil || state.Sequence == ^uint64(0) {
		return CustodyJournalEntry{}, false, errors.Join(ErrCustodyJournal, err)
	}
	if state.Sequence != 0 {
		head, loadErr := journal.loadSequence(state.Sequence)
		if loadErr != nil {
			return CustodyJournalEntry{}, false, loadErr
		}
		// An acknowledged response may be retried after its caller crashes before
		// observing success. Resolve that retry to the durable head. A different
		// challenge bound to the same predecessor is a sibling and cannot become
		// the following sequence.
		if record.Challenge.ReceiptID == head.Record.Challenge.ReceiptID {
			if record.Verify(journal.manifest, head.PreviousReceipt, journal.policy) != nil {
				return CustodyJournalEntry{}, false, ErrCustodyJournal
			}
			currentChallengeID, currentErr := head.Record.Challenge.ID()
			proposedChallengeID, proposedErr := record.Challenge.ID()
			if currentErr != nil || proposedErr != nil || currentChallengeID != proposedChallengeID {
				return CustodyJournalEntry{}, false, ErrCustodyJournal
			}
			return head, false, nil
		}
	}
	entry := CustodyJournalEntry{
		Version: CustodyJournalEntryVersion0, Sequence: state.Sequence + 1,
		PreviousEntryID: state.HeadEntryID, PreviousReceipt: state.CurrentReceipt,
		Record: record,
	}
	if entry.Verify(
		journal.manifest, journal.policy, entry.Sequence,
		state.HeadEntryID, state.CurrentReceipt,
	) != nil {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	encoded, err := entry.CanonicalBytes()
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	entryID := types.DomainHash(custodyJournalEntryIDDomain, encoded)
	slot := custodyJournalSlot{
		Version: custodyJournalSlotVersion0, Sequence: entry.Sequence, EntryID: entryID,
	}
	currentBody, bodyExists, err := journal.findBody(entryID)
	if err != nil || (bodyExists && !bytes.Equal(currentBody, encoded)) {
		return CustodyJournalEntry{}, false, errors.Join(ErrCustodyJournal, err)
	}
	if err := journal.admitAppend(bodyExists, uint64(len(encoded)), slot); err != nil {
		return CustodyJournalEntry{}, false, err
	}
	if err := journal.publishBody(entryID, encoded); err != nil {
		return CustodyJournalEntry{}, false, err
	}
	if hooks.afterBody != nil {
		hooks.afterBody()
	}
	created, err := journal.publishSlot(slot)
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	if hooks.afterSlot != nil {
		hooks.afterSlot()
	}
	current, err := journal.scan()
	if err != nil || current.Sequence < entry.Sequence {
		return CustodyJournalEntry{}, false, errors.Join(ErrCustodyJournal, err)
	}
	winner, err := journal.loadSequence(entry.Sequence)
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	if created {
		if winnerID, idErr := winner.ID(); idErr != nil || winnerID != entryID {
			return CustodyJournalEntry{}, false, ErrCustodyJournal
		}
		return winner, true, nil
	}
	currentChallengeID, err := winner.Record.Challenge.ID()
	if err != nil {
		return CustodyJournalEntry{}, false, err
	}
	proposedChallengeID, err := record.Challenge.ID()
	if err != nil || currentChallengeID != proposedChallengeID {
		return CustodyJournalEntry{}, false, ErrCustodyJournal
	}
	return winner, false, nil
}

// Rotate seals the current body directory under a random, non-semantic name.
// Sequence slots remain in place, and no evidence file is deleted or replaced.
func (journal *CustodyJournal) Rotate() (bool, error) {
	return journal.rotate(custodyJournalHooks{})
}

func (journal *CustodyJournal) rotate(hooks custodyJournalHooks) (bool, error) {
	if journal == nil {
		return false, ErrCustodyJournal
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	lock, err := acquireCustodyJournalLock(journal.path)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	if _, err := journal.scan(); err != nil {
		return false, err
	}
	active := journal.activePath()
	entries, err := os.ReadDir(active)
	if err != nil {
		return false, errors.Join(ErrCustodyJournal, err)
	}
	if len(entries) == 0 {
		return false, nil
	}
	usage, err := inventoryCustodyJournal(journal.path)
	if err != nil {
		return false, err
	}
	if err := usage.admit(journal.limits, 0, 1); err != nil {
		return false, err
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return false, err
	}
	segments := journal.segmentsPath()
	destination := filepath.Join(segments, "segment-"+hex.EncodeToString(nonce[:]))
	if err := os.Rename(active, destination); err != nil {
		return false, errors.Join(ErrCustodyJournal, err)
	}
	if err := syncDirectory(destination); err != nil {
		return false, errors.Join(ErrCustodyJournal, err)
	}
	if err := syncDirectory(segments); err != nil {
		return false, errors.Join(ErrCustodyJournal, err)
	}
	if err := syncDirectory(filepath.Dir(active)); err != nil {
		return false, errors.Join(ErrCustodyJournal, err)
	}
	if hooks.afterSeal != nil {
		hooks.afterSeal()
	}
	if err := ensureCustodyJournalDirectory(active); err != nil {
		return false, err
	}
	if err := syncDirectory(filepath.Dir(active)); err != nil {
		return false, err
	}
	if _, err := journal.scan(); err != nil {
		return false, err
	}
	return true, nil
}

func initializeCustodyJournal(path string, header CustodyJournalHeader, limits CustodyJournalLimits) error {
	if err := requireCustodyJournalDirectory(path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	for _, directory := range []string{
		filepath.Join(path, custodyJournalObjectsName),
		filepath.Join(path, custodyJournalObjectsName, custodyJournalActiveName),
		filepath.Join(path, custodyJournalObjectsName, custodyJournalSegmentsName),
		filepath.Join(path, custodyJournalSlotsName),
		filepath.Join(path, custodyJournalPendingName),
	} {
		if err := ensureCustodyJournalDirectory(directory); err != nil {
			return err
		}
	}
	encoded, err := header.CanonicalBytes()
	if err != nil {
		return err
	}
	headerPath := filepath.Join(path, custodyJournalHeaderName)
	if _, err := os.Lstat(headerPath); errors.Is(err, os.ErrNotExist) {
		usage, err := inventoryCustodyJournal(path)
		if err != nil {
			return err
		}
		if err := usage.admit(limits, 2*uint64(len(encoded)), 2); err != nil {
			return err
		}
	} else if err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	created, err := publishCustodyJournalBytes(
		filepath.Join(path, custodyJournalPendingName), headerPath, encoded,
	)
	if err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	current, err := readRegularArchiveFile(headerPath, MaximumCustodyJournalHeaderBytes)
	if err != nil || !bytes.Equal(current, encoded) {
		return ErrCustodyJournal
	}
	if created {
		return syncDirectory(path)
	}
	return nil
}

func (journal *CustodyJournal) scan() (CustodyJournalState, error) {
	if _, err := inventoryCustodyJournal(journal.path); err != nil {
		return CustodyJournalState{}, err
	}
	headerBytes, err := readRegularArchiveFile(
		filepath.Join(journal.path, custodyJournalHeaderName), MaximumCustodyJournalHeaderBytes,
	)
	if err != nil {
		return CustodyJournalState{}, errors.Join(ErrCustodyJournal, err)
	}
	header, err := DecodeCustodyJournalHeader(headerBytes)
	if err != nil || header != journal.header {
		return CustodyJournalState{}, errors.Join(ErrCustodyJournal, err)
	}
	manifestID, err := journal.manifest.ID()
	policyID, policyErr := custodyJournalPolicyID(journal.policy)
	if err != nil || policyErr != nil || header.ManifestID != manifestID ||
		header.PolicyID != policyID ||
		header.InitialReceipt.ManifestID != manifestID ||
		header.InitialReceipt.Binding != journal.manifest.Binding ||
		header.InitialReceipt.AnchorID != journal.manifest.Anchor.ID {
		return CustodyJournalState{}, ErrCustodyJournal
	}
	for _, directory := range []string{
		journal.path,
		filepath.Join(journal.path, custodyJournalObjectsName),
		journal.activePath(), journal.segmentsPath(),
		filepath.Join(journal.path, custodyJournalSlotsName),
		filepath.Join(journal.path, custodyJournalPendingName),
	} {
		if err := requireCustodyJournalDirectory(directory); err != nil {
			return CustodyJournalState{}, err
		}
	}
	if err := journal.validateLayout(); err != nil {
		return CustodyJournalState{}, err
	}
	bodies, err := journal.scanBodyPaths()
	if err != nil {
		return CustodyJournalState{}, err
	}
	slots, err := journal.scanSlots()
	if err != nil {
		return CustodyJournalState{}, err
	}
	state := CustodyJournalState{
		InitialReceipt: header.InitialReceipt, CurrentReceipt: header.InitialReceipt,
	}
	referenced := make(map[types.Hash]struct{}, len(slots))
	for index, slot := range slots {
		expectedSequence := uint64(index) + 1
		if slot.Sequence != expectedSequence {
			return CustodyJournalState{}, ErrCustodyJournal
		}
		paths, exists := bodies[slot.EntryID]
		if !exists {
			return CustodyJournalState{}, ErrCustodyJournal
		}
		encoded, err := loadCustodyJournalBodyPaths(slot.EntryID, paths)
		if err != nil {
			return CustodyJournalState{}, err
		}
		entry, err := DecodeCustodyJournalEntry(encoded)
		if err != nil || entry.Verify(
			journal.manifest, journal.policy, expectedSequence,
			state.HeadEntryID, state.CurrentReceipt,
		) != nil {
			return CustodyJournalState{}, ErrCustodyJournal
		}
		entryID, err := entry.ID()
		if err != nil || entryID != slot.EntryID {
			return CustodyJournalState{}, ErrCustodyJournal
		}
		state.Sequence = expectedSequence
		state.HeadEntryID = entryID
		state.CurrentReceipt = entry.Record.RenewedReceipt
		referenced[entryID] = struct{}{}
	}
	// Losing bodies from a same-slot race are allowed, but they still have to
	// be canonical and content-addressed. Validate them one at a time so replay
	// memory is bounded by one entry rather than total journal history.
	for entryID, paths := range bodies {
		if _, exists := referenced[entryID]; exists {
			continue
		}
		if _, err := loadCustodyJournalBodyPaths(entryID, paths); err != nil {
			return CustodyJournalState{}, err
		}
	}
	return state, nil
}

func (journal *CustodyJournal) validateLayout() error {
	rootEntries, err := os.ReadDir(journal.path)
	if err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	expectedRoot := map[string]bool{
		custodyJournalHeaderName:  false,
		custodyJournalLockName:    false,
		custodyJournalObjectsName: true,
		custodyJournalSlotsName:   true,
		custodyJournalPendingName: true,
	}
	for _, entry := range rootEntries {
		wantDirectory, exists := expectedRoot[entry.Name()]
		if !exists || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() != wantDirectory {
			return ErrCustodyJournal
		}
		delete(expectedRoot, entry.Name())
	}
	if len(expectedRoot) != 0 {
		return ErrCustodyJournal
	}
	objects := filepath.Join(journal.path, custodyJournalObjectsName)
	objectEntries, err := os.ReadDir(objects)
	if err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	expectedObjects := map[string]struct{}{
		custodyJournalActiveName: {}, custodyJournalSegmentsName: {},
	}
	for _, entry := range objectEntries {
		if _, exists := expectedObjects[entry.Name()]; !exists || !entry.IsDir() ||
			entry.Type()&os.ModeSymlink != 0 {
			return ErrCustodyJournal
		}
		delete(expectedObjects, entry.Name())
	}
	if len(expectedObjects) != 0 {
		return ErrCustodyJournal
	}
	pendingEntries, err := os.ReadDir(filepath.Join(journal.path, custodyJournalPendingName))
	if err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	for _, entry := range pendingEntries {
		if !strings.HasPrefix(entry.Name(), ".outcomemesh-custody-journal-") ||
			entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrCustodyJournal
		}
		info, err := os.Lstat(filepath.Join(journal.path, custodyJournalPendingName, entry.Name()))
		if err != nil || !info.Mode().IsRegular() {
			return errors.Join(ErrCustodyJournal, err)
		}
	}
	return nil
}

func (journal *CustodyJournal) scanBodyPaths() (map[types.Hash][]string, error) {
	result := make(map[types.Hash][]string)
	directories := []string{journal.activePath()}
	segments, err := os.ReadDir(journal.segmentsPath())
	if err != nil {
		return nil, errors.Join(ErrCustodyJournal, err)
	}
	for _, segment := range segments {
		if !segment.IsDir() || !validCustodyJournalSegmentName(segment.Name()) ||
			segment.Type()&os.ModeSymlink != 0 {
			return nil, ErrCustodyJournal
		}
		directories = append(directories, filepath.Join(journal.segmentsPath(), segment.Name()))
	}
	for _, directory := range directories {
		if err := requireCustodyJournalDirectory(directory); err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, errors.Join(ErrCustodyJournal, err)
		}
		for _, item := range entries {
			entryID, ok := custodyJournalBodyNameID(item.Name())
			if !ok || item.IsDir() || item.Type()&os.ModeSymlink != 0 {
				return nil, ErrCustodyJournal
			}
			path := filepath.Join(directory, item.Name())
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
				info.Size() > int64(MaximumCustodyJournalEntryBytes) {
				return nil, errors.Join(ErrCustodyJournal, err)
			}
			result[entryID] = append(result[entryID], path)
		}
		if err := syncDirectory(directory); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func loadCustodyJournalBodyPaths(entryID types.Hash, paths []string) ([]byte, error) {
	if entryID.IsZero() || len(paths) == 0 {
		return nil, ErrCustodyJournal
	}
	var result []byte
	for _, path := range paths {
		encoded, err := readRegularArchiveFile(path, MaximumCustodyJournalEntryBytes)
		if err != nil {
			return nil, errors.Join(ErrCustodyJournal, err)
		}
		entry, err := DecodeCustodyJournalEntry(encoded)
		if err != nil {
			return nil, err
		}
		verifiedID, err := entry.ID()
		if err != nil || verifiedID != entryID ||
			(result != nil && !bytes.Equal(result, encoded)) {
			return nil, ErrCustodyJournal
		}
		result = encoded
	}
	return result, nil
}

func (journal *CustodyJournal) scanSlots() ([]custodyJournalSlot, error) {
	root := filepath.Join(journal.path, custodyJournalSlotsName)
	buckets, err := os.ReadDir(root)
	if err != nil {
		return nil, errors.Join(ErrCustodyJournal, err)
	}
	var slots []custodyJournalSlot
	seen := make(map[uint64]struct{})
	for _, bucket := range buckets {
		bucketIndex, ok := custodyJournalBucketNameIndex(bucket.Name())
		if !ok || !bucket.IsDir() || bucket.Type()&os.ModeSymlink != 0 {
			return nil, ErrCustodyJournal
		}
		bucketPath := filepath.Join(root, bucket.Name())
		if err := requireCustodyJournalDirectory(bucketPath); err != nil {
			return nil, err
		}
		items, err := os.ReadDir(bucketPath)
		if err != nil {
			return nil, errors.Join(ErrCustodyJournal, err)
		}
		for _, item := range items {
			sequence, ok := custodyJournalSlotNameSequence(item.Name())
			if !ok || item.IsDir() || item.Type()&os.ModeSymlink != 0 ||
				(sequence-1)/custodyJournalSlotsPerBucket != bucketIndex {
				return nil, ErrCustodyJournal
			}
			if _, exists := seen[sequence]; exists {
				return nil, ErrCustodyJournal
			}
			encoded, err := readRegularArchiveFile(
				filepath.Join(bucketPath, item.Name()), maximumCustodyJournalSlotBytes,
			)
			if err != nil {
				return nil, errors.Join(ErrCustodyJournal, err)
			}
			slot, err := decodeCustodyJournalSlot(encoded)
			if err != nil || slot.Sequence != sequence {
				return nil, ErrCustodyJournal
			}
			seen[sequence] = struct{}{}
			slots = append(slots, slot)
		}
		if err := syncDirectory(bucketPath); err != nil {
			return nil, err
		}
	}
	sort.Slice(slots, func(left, right int) bool { return slots[left].Sequence < slots[right].Sequence })
	return slots, nil
}

func (journal *CustodyJournal) publishBody(entryID types.Hash, encoded []byte) error {
	if entryID.IsZero() || len(encoded) == 0 || len(encoded) > MaximumCustodyJournalEntryBytes {
		return ErrCustodyJournal
	}
	if current, found, err := journal.findBody(entryID); err != nil {
		return err
	} else if found {
		if !bytes.Equal(current, encoded) {
			return ErrCustodyJournal
		}
		return nil
	}
	pending, err := writeCustodyJournalTemporary(
		filepath.Join(journal.path, custodyJournalPendingName), encoded,
	)
	if err != nil {
		return err
	}
	defer os.Remove(pending)
	destination := filepath.Join(journal.activePath(), custodyJournalBodyName(entryID))
	if err := os.Link(pending, destination); err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	return syncDirectory(journal.activePath())
}

func (journal *CustodyJournal) publishSlot(slot custodyJournalSlot) (bool, error) {
	encoded, err := slot.canonicalBytes()
	if err != nil {
		return false, err
	}
	bucket := journal.slotBucketPath(slot.Sequence)
	if err := ensureCustodyJournalDirectory(bucket); err != nil {
		return false, err
	}
	created, err := publishCustodyJournalBytes(
		filepath.Join(journal.path, custodyJournalPendingName),
		filepath.Join(bucket, custodyJournalSlotName(slot.Sequence)), encoded,
	)
	if err != nil {
		return false, errors.Join(ErrCustodyJournal, err)
	}
	return created, nil
}

func (journal *CustodyJournal) loadSequence(sequence uint64) (CustodyJournalEntry, error) {
	if sequence == 0 {
		return CustodyJournalEntry{}, ErrCustodyJournal
	}
	slotBytes, err := readRegularArchiveFile(
		filepath.Join(journal.slotBucketPath(sequence), custodyJournalSlotName(sequence)),
		maximumCustodyJournalSlotBytes,
	)
	if err != nil {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	slot, err := decodeCustodyJournalSlot(slotBytes)
	if err != nil || slot.Sequence != sequence {
		return CustodyJournalEntry{}, ErrCustodyJournal
	}
	body, found, err := journal.findBody(slot.EntryID)
	if err != nil || !found {
		return CustodyJournalEntry{}, errors.Join(ErrCustodyJournal, err)
	}
	entry, err := DecodeCustodyJournalEntry(body)
	if err != nil {
		return CustodyJournalEntry{}, err
	}
	entryID, err := entry.ID()
	if err != nil || entryID != slot.EntryID {
		return CustodyJournalEntry{}, ErrCustodyJournal
	}
	return entry, nil
}

func (journal *CustodyJournal) findBody(entryID types.Hash) ([]byte, bool, error) {
	name := custodyJournalBodyName(entryID)
	paths := []string{filepath.Join(journal.activePath(), name)}
	segments, err := os.ReadDir(journal.segmentsPath())
	if err != nil {
		return nil, false, errors.Join(ErrCustodyJournal, err)
	}
	for _, segment := range segments {
		if !segment.IsDir() || !validCustodyJournalSegmentName(segment.Name()) ||
			segment.Type()&os.ModeSymlink != 0 {
			return nil, false, ErrCustodyJournal
		}
		paths = append(paths, filepath.Join(journal.segmentsPath(), segment.Name(), name))
	}
	var result []byte
	for _, path := range paths {
		encoded, readErr := readRegularArchiveFile(path, MaximumCustodyJournalEntryBytes)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return nil, false, errors.Join(ErrCustodyJournal, readErr)
		}
		if result != nil && !bytes.Equal(result, encoded) {
			return nil, false, ErrCustodyJournal
		}
		result = encoded
	}
	return result, result != nil, nil
}

func publishCustodyJournalBytes(pendingDirectory, destination string, encoded []byte) (bool, error) {
	if len(encoded) == 0 {
		return false, ErrCustodyJournal
	}
	// Reopening or retrying a durable decision must not allocate a new temporary
	// file, including when the filesystem or local growth budget is full.
	if _, err := readRegularArchiveFile(destination, MaximumCustodyJournalHeaderBytes); err == nil {
		return false, syncDirectory(filepath.Dir(destination))
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	pending, err := writeCustodyJournalTemporary(pendingDirectory, encoded)
	if err != nil {
		return false, err
	}
	defer os.Remove(pending)
	if err := os.Link(pending, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, err
		}
		_, readErr := readRegularArchiveFile(destination, MaximumCustodyJournalHeaderBytes)
		if readErr != nil {
			return false, readErr
		}
		return false, syncDirectory(filepath.Dir(destination))
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return false, err
	}
	return true, nil
}

func writeCustodyJournalTemporary(directory string, encoded []byte) (string, error) {
	if err := ensureCustodyJournalDirectory(directory); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, ".outcomemesh-custody-journal-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	written, err := file.Write(encoded)
	if err != nil || written != len(encoded) {
		_ = os.Remove(path)
		if err == nil {
			err = io.ErrShortWrite
		}
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	closed = true
	return path, nil
}

func ensureCustodyJournalDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.Join(ErrCustodyJournal, err)
	}
	if err := requireCustodyJournalDirectory(path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return errors.Join(ErrCustodyJournal, err)
	}
	return nil
}

func makeCustodyJournalRoot(path string) error {
	path = filepath.Clean(path)
	if _, err := os.Lstat(path); err == nil {
		if err := requireCustodyJournalDirectory(path); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return ErrCustodyJournal
	}
	if err := makeCustodyJournalRoot(parent); err != nil {
		return err
	}
	return ensureCustodyJournalDirectory(path)
}

func requireCustodyJournalDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrCustodyJournal, err)
	}
	return nil
}

func (journal *CustodyJournal) activePath() string {
	return filepath.Join(journal.path, custodyJournalObjectsName, custodyJournalActiveName)
}

func (journal *CustodyJournal) segmentsPath() string {
	return filepath.Join(journal.path, custodyJournalObjectsName, custodyJournalSegmentsName)
}

func (journal *CustodyJournal) slotBucketPath(sequence uint64) string {
	return filepath.Join(
		journal.path, custodyJournalSlotsName,
		fmt.Sprintf("bucket-%016x", (sequence-1)/custodyJournalSlotsPerBucket),
	)
}

func custodyJournalPolicyID(policy CustodyPolicy) (types.Hash, error) {
	if policy.validate() != nil {
		return types.Hash{}, ErrCustodyJournal
	}
	encoder := codec.NewEncoder(
		32 + len(policy.TrustedAuditors)*ed25519.PublicKeySize,
	)
	encoder.U16(CustodyJournalHeaderVersion0)
	encoder.Uvarint(uint64(len(policy.TrustedAuditors)))
	for _, key := range policy.TrustedAuditors {
		encoder.Fixed(key[:])
	}
	encoder.U64(policy.MaximumChallengeLifetime)
	encoder.U64(policy.MaximumProofAge)
	encoder.U64(policy.MaximumRenewalTerm)
	return types.DomainHash(custodyJournalPolicyIDDomain, encoder.Bytes()), nil
}

func custodyJournalBodyName(id types.Hash) string {
	return id.String() + ".omce"
}

func custodyJournalBodyNameID(name string) (types.Hash, bool) {
	var id types.Hash
	if len(name) != types.HashSize*2+len(".omce") || !strings.HasSuffix(name, ".omce") {
		return id, false
	}
	decoded, err := hex.DecodeString(strings.TrimSuffix(name, ".omce"))
	if err != nil || len(decoded) != types.HashSize {
		return id, false
	}
	copy(id[:], decoded)
	return id, !id.IsZero() && custodyJournalBodyName(id) == name
}

func custodyJournalSlotName(sequence uint64) string {
	return fmt.Sprintf("slot-%020d.omcs", sequence)
}

func custodyJournalSlotNameSequence(name string) (uint64, bool) {
	if len(name) != len("slot-")+20+len(".omcs") || !strings.HasPrefix(name, "slot-") ||
		!strings.HasSuffix(name, ".omcs") {
		return 0, false
	}
	sequence, err := strconv.ParseUint(name[len("slot-"):len("slot-")+20], 10, 64)
	return sequence, err == nil && sequence != 0 && custodyJournalSlotName(sequence) == name
}

func custodyJournalBucketNameIndex(name string) (uint64, bool) {
	if len(name) != len("bucket-")+16 || !strings.HasPrefix(name, "bucket-") {
		return 0, false
	}
	index, err := strconv.ParseUint(strings.TrimPrefix(name, "bucket-"), 16, 64)
	return index, err == nil && fmt.Sprintf("bucket-%016x", index) == name
}

func validCustodyJournalSegmentName(name string) bool {
	if len(name) != len("segment-")+32 || !strings.HasPrefix(name, "segment-") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(name, "segment-"))
	return err == nil && len(decoded) == 16 && "segment-"+hex.EncodeToString(decoded) == name
}
