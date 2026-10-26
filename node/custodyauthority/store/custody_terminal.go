package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	CustodyTerminalVersion0     uint16 = 0
	MaximumCustodyTerminalBytes        = 8 + 2 + types.HashSize + 30 + custodyauthority.MaximumEntryBytes +
		workarchive.MaximumCustodyAuditIntentBytes + workarchive.MaximumCustodyJournalEntryBytes
)

var (
	ErrCustodyTerminal   = errors.New("custody terminal evidence does not match the selected admission and committed journal head")
	custodyTerminalMagic = [8]byte{'O', 'M', 'C', 'A', 'T', 'R', 'M', '0'}
)

// CustodyTerminal retains one exact signed admission and historical committed
// response. Its ID is the Complete EvidenceID. It is neither a fresh proof nor
// execution permission; live capture/apply must separately hold current owners.
type CustodyTerminal struct {
	Version      uint16
	AssignmentID types.Hash
	Admission    custodyauthority.Entry
	Intent       workarchive.CustodyAuditIntent
	Entry        workarchive.CustodyJournalEntry
}

func (terminal CustodyTerminal) validateShape() error {
	if terminal.Version != CustodyTerminalVersion0 || terminal.AssignmentID.IsZero() ||
		terminal.Intent.Validate() != nil || terminal.Intent.AssignmentID != terminal.AssignmentID {
		return ErrCustodyTerminal
	}
	c, intent, entry := terminal.Admission.Command, terminal.Intent, terminal.Entry
	if c.Kind != custodyauthority.Admit || c.AssignmentID != terminal.AssignmentID ||
		entry.Sequence != intent.PriorSequence+1 || entry.PreviousEntryID != intent.PriorHeadID ||
		!custodyIntentMatchesChallenge(intent, entry.Record.Challenge) {
		return ErrCustodyTerminal
	}
	previous, err := entry.PreviousReceipt.ID()
	if err != nil || previous != intent.PriorReceiptID {
		return errors.Join(ErrCustodyTerminal, err)
	}
	var operation types.Hash
	switch c.Purpose {
	case custodyauthority.Audit:
		if c.ActorPublicKey != intent.ConsumerPublicKey {
			return ErrCustodyTerminal
		}
		operation, err = intent.ID()
	case custodyauthority.Serve:
		operation, err = entry.Record.Challenge.ID()
	default:
		return ErrCustodyTerminal
	}
	if err != nil || operation != c.OperationID {
		return errors.Join(ErrCustodyTerminal, err)
	}
	return nil
}

func (terminal CustodyTerminal) CanonicalBytes() ([]byte, error) {
	if err := terminal.validateShape(); err != nil {
		return nil, err
	}
	admission, err := terminal.Admission.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrCustodyTerminal, err)
	}
	intent, err := terminal.Intent.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	entry, err := terminal.Entry.CanonicalBytes()
	if err != nil {
		return nil, errors.Join(ErrCustodyTerminal, err)
	}
	e := codec.NewEncoder(len(admission) + len(intent) + len(entry) + 72)
	e.Fixed(custodyTerminalMagic[:])
	e.U16(terminal.Version)
	e.Fixed(terminal.AssignmentID[:])
	e.BytesField(admission)
	e.BytesField(intent)
	e.BytesField(entry)
	b := e.Bytes()
	if len(b) > MaximumCustodyTerminalBytes {
		return nil, ErrCustodyTerminal
	}
	return b, nil
}

func DecodeCustodyTerminal(input []byte) (CustodyTerminal, error) {
	if len(input) == 0 || len(input) > MaximumCustodyTerminalBytes {
		return CustodyTerminal{}, ErrCustodyTerminal
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, custodyTerminalMagic[:]) {
		return CustodyTerminal{}, ErrCustodyTerminal
	}
	var terminal CustodyTerminal
	if terminal.Version, err = d.U16(); err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	id, err := d.Fixed(types.HashSize)
	if err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	copy(terminal.AssignmentID[:], id)
	admission, err := d.BytesField(custodyauthority.MaximumEntryBytes)
	if err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	if terminal.Admission, err = custodyauthority.DecodeEntry(admission); err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	intent, err := d.BytesField(workarchive.MaximumCustodyAuditIntentBytes)
	if err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	if terminal.Intent, err = workarchive.DecodeCustodyAuditIntent(intent); err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	entry, err := d.BytesField(workarchive.MaximumCustodyJournalEntryBytes)
	if err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	if terminal.Entry, err = workarchive.DecodeCustodyJournalEntry(entry); err != nil {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	if d.Finish() != nil || terminal.validateShape() != nil {
		return CustodyTerminal{}, ErrCustodyTerminal
	}
	return terminal, nil
}

func (terminal CustodyTerminal) ID() (types.Hash, error) {
	b, err := terminal.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/custody-terminal/id/v0", b), nil
}

// Validate replays all proof/signature checks at the record's original
// RespondedAt. It deliberately never supplies a new clock or renews evidence.
// Source continuity and current ticket authority remain capture/apply checks.
func (terminal CustodyTerminal) Validate(scope CustodyCommandScope) error {
	if err := ValidateCustodyCommandScope(scope); err != nil {
		return err
	}
	if _, err := terminal.CanonicalBytes(); err != nil {
		return err
	}
	if terminal.AssignmentID != scope.AssignmentID || terminal.Intent != scope.Intent {
		return ErrCustodyTerminal
	}
	if err := ValidateCustodyCommandChallenge(scope, terminal.Entry.Record.Challenge); err != nil {
		return errors.Join(ErrCustodyTerminal, err)
	}
	if err := validateCustodyAdmission(scope, terminal.Admission, terminal.Entry.Record.Challenge); err != nil {
		return errors.Join(ErrCustodyTerminal, err)
	}
	if err := terminal.Entry.Verify(scope.Manifest, scope.CustodyPolicy, scope.Intent.PriorSequence+1,
		scope.Intent.PriorHeadID, scope.PreviousReceipt); err != nil {
		return errors.Join(ErrCustodyTerminal, err)
	}
	return nil
}

// LoadCustodyTerminalFile reads only a bounded regular file and requires its
// independently retained canonical ID. It opens no live owner or source root.
func LoadCustodyTerminalFile(path string, pinnedID types.Hash) (CustodyTerminal, error) {
	if pinnedID.IsZero() {
		return CustodyTerminal{}, ErrCustodyTerminal
	}
	b, err := readRegular(path, MaximumCustodyTerminalBytes)
	if err != nil {
		return CustodyTerminal{}, err
	}
	terminal, err := DecodeCustodyTerminal(b)
	if err != nil {
		return CustodyTerminal{}, err
	}
	id, err := terminal.ID()
	if err != nil || id != pinnedID {
		return CustodyTerminal{}, errors.Join(ErrCustodyTerminal, err)
	}
	return terminal, nil
}

// PublishCustodyTerminalFile publishes exact no-replace bytes in an existing
// dedicated owner-controlled directory. Existing files are fully compared,
// including on retries under disk pressure. It creates no parent or source root.
func PublishCustodyTerminalFile(ctx context.Context, path string, terminal CustodyTerminal) (returnErr error) {
	if ctx == nil {
		return ErrCustodyTerminal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := terminal.CanonicalBytes()
	if err != nil {
		return err
	}
	path, err = storePath(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if existing, err := readRegular(path, len(b)); err == nil {
		if !bytes.Equal(existing, b) {
			return ErrCustodyTerminal
		}
		if err := syncPath(path); err != nil {
			return err
		}
		return syncDirectory(parent)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(parent, ".outcomemesh-terminal-*")
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, f.Close())
		}
		if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	if n, err := f.Write(b); err != nil || n != len(b) {
		return errors.Join(io.ErrShortWrite, err)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, err := readRegular(path, len(b))
	if err != nil || !bytes.Equal(existing, b) {
		return errors.Join(ErrCustodyTerminal, err)
	}
	if err := syncPath(path); err != nil {
		return err
	}
	return syncDirectory(parent)
}
