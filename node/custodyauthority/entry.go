package custodyauthority

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

type Kind uint8

const (
	Admit Kind = 1 + iota
	Complete
	Stop
	Retire
	RemoteBegin
	RemoteDrained
	MigrateSchedule
	ScheduleVersion2    uint16 = 2
	LegacyCommandBytes         = 8 + 2 + 5*types.HashSize + 8 + 2 + ed25519.PublicKeySize + ed25519.SignatureSize
	LegacyEntryBytes           = 8 + 2 + LegacyCommandBytes + ed25519.PublicKeySize + ed25519.SignatureSize
	MaximumCommandBytes        = LegacyCommandBytes + types.HashSize
	MaximumEntryBytes          = LegacyEntryBytes + types.HashSize
)

var (
	ErrCommand   = errors.New("invalid custody authority command")
	ErrEntry     = errors.New("invalid custody authority entry")
	commandMagic = [8]byte{'O', 'M', 'C', 'A', 'C', 'M', 'N', 'D'}
	entryMagic   = [8]byte{'O', 'M', 'C', 'A', 'E', 'N', 'T', 'R'}
)

// Command is signed by a consumer (Admit/Complete), the assignment authority
// (Stop/Retire), the original replica (V2 MigrateSchedule), or the remote
// control key (V1 RemoteBegin/RemoteDrained).
// ExpectedSequence/Head are compare-and-append inputs, not proof
// of current remote state. Unused fields must be zero. EvidenceID is a terminal
// effect/disposition commitment for Complete, a reviewed stop-intent reference
// for Stop, and the exact committed stop entry ID for Retire.
type Command struct {
	Version          uint16
	ScheduleID       types.Hash // nonzero only in schedule-bound v2 commands
	AssignmentID     types.Hash
	ExpectedSequence uint64
	ExpectedHead     types.Hash
	Kind             Kind
	Purpose          Purpose
	OperationID      types.Hash
	TicketID         types.Hash
	EvidenceID       types.Hash
	ActorPublicKey   [ed25519.PublicKeySize]byte
	Signature        [ed25519.SignatureSize]byte
}

// Entry is the authority's co-signature over one exact consumer/control command.
// Its ID identifies an admitted ticket. A signature alone is not a live grant:
// a future adapter must persist ordered acceptance before exposing the entry,
// and bind its use to a current, single-execution consumer operation.
type Entry struct {
	Version            uint16
	Command            Command
	AuthorityPublicKey [ed25519.PublicKeySize]byte
	Signature          [ed25519.SignatureSize]byte
}

func (command Command) validateShape() error {
	if (command.Version != Version0 && command.Version != Version1 && command.Version != ScheduleVersion2) || command.AssignmentID.IsZero() || command.ExpectedHead.IsZero() ||
		(command.Version == ScheduleVersion2) != !command.ScheduleID.IsZero() || command.ExpectedSequence == ^uint64(0) || types.Hash(command.ActorPublicKey).IsZero() {
		return ErrCommand
	}
	switch command.Kind {
	case MigrateSchedule:
		if command.Version != ScheduleVersion2 || command.Purpose != 0 || !command.OperationID.IsZero() || !command.TicketID.IsZero() || !command.EvidenceID.IsZero() {
			return ErrCommand
		}
	case Admit:
		if (command.Purpose != Audit && command.Purpose != Serve && command.Purpose != Prune) ||
			command.OperationID.IsZero() || !command.TicketID.IsZero() || !command.EvidenceID.IsZero() {
			return ErrCommand
		}
	case Complete:
		if command.Purpose != 0 || !command.OperationID.IsZero() || command.TicketID.IsZero() || command.EvidenceID.IsZero() {
			return ErrCommand
		}
	case Stop, Retire:
		if command.Purpose != 0 || !command.OperationID.IsZero() || !command.TicketID.IsZero() || command.EvidenceID.IsZero() {
			return ErrCommand
		}
	case RemoteBegin:
		if command.Version != Version1 || command.Purpose != Serve || command.OperationID.IsZero() || command.TicketID.IsZero() || command.EvidenceID.IsZero() {
			return ErrCommand
		}
	case RemoteDrained:
		if command.Version != Version1 || command.Purpose != 0 || command.OperationID.IsZero() || command.TicketID.IsZero() || command.EvidenceID.IsZero() {
			return ErrCommand
		}
	default:
		return ErrCommand
	}
	return nil
}

func (command Command) unsignedBytes() ([]byte, error) {
	if err := command.validateShape(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumCommandBytes)
	e.Fixed(commandMagic[:])
	e.U16(command.Version)
	e.Fixed(command.AssignmentID[:])
	e.U64(command.ExpectedSequence)
	e.Fixed(command.ExpectedHead[:])
	e.U8(uint8(command.Kind))
	e.U8(uint8(command.Purpose))
	for _, id := range []types.Hash{command.OperationID, command.TicketID, command.EvidenceID} {
		e.Fixed(id[:])
	}
	if command.Version == ScheduleVersion2 {
		e.Fixed(command.ScheduleID[:])
	}
	e.Fixed(command.ActorPublicKey[:])
	return e.Bytes(), nil
}

func (command Command) CanonicalBytes() ([]byte, error) {
	unsigned, err := command.unsignedBytes()
	if err != nil {
		return nil, err
	}
	message := types.DomainHash(authorityDomain(command.Version, "command/signature"), unsigned)
	if !ed25519.Verify(command.ActorPublicKey[:], message[:], command.Signature[:]) {
		return nil, ErrCommand
	}
	return append(unsigned, command.Signature[:]...), nil
}

func (command Command) Sign(key ed25519.PrivateKey) (Command, error) {
	if !validKey(key) {
		return Command{}, ErrCommand
	}
	var public [ed25519.PublicKeySize]byte
	copy(public[:], key.Public().(ed25519.PublicKey))
	if !types.Hash(command.ActorPublicKey).IsZero() && command.ActorPublicKey != public {
		return Command{}, ErrCommand
	}
	command.ActorPublicKey = public
	unsigned, err := command.unsignedBytes()
	if err != nil {
		return Command{}, err
	}
	message := types.DomainHash(authorityDomain(command.Version, "command/signature"), unsigned)
	copy(command.Signature[:], ed25519.Sign(key, message[:]))
	return command, nil
}

func DecodeCommand(input []byte) (Command, error) {
	if len(input) != LegacyCommandBytes && len(input) != MaximumCommandBytes {
		return Command{}, ErrCommand
	}
	d := codec.NewDecoder(input)
	magic, _ := d.Fixed(len(commandMagic))
	var c Command
	c.Version, _ = d.U16()
	decodeFixed(d, c.AssignmentID[:])
	c.ExpectedSequence, _ = d.U64()
	decodeFixed(d, c.ExpectedHead[:])
	kind, _ := d.U8()
	c.Kind = Kind(kind)
	purpose, _ := d.U8()
	c.Purpose = Purpose(purpose)
	for _, id := range []*types.Hash{&c.OperationID, &c.TicketID, &c.EvidenceID} {
		decodeFixed(d, id[:])
	}
	if c.Version == ScheduleVersion2 {
		decodeFixed(d, c.ScheduleID[:])
	}
	decodeFixed(d, c.ActorPublicKey[:])
	decodeFixed(d, c.Signature[:])
	if !bytes.Equal(magic, commandMagic[:]) || d.Finish() != nil {
		return Command{}, ErrCommand
	}
	if _, err := c.CanonicalBytes(); err != nil {
		return Command{}, err
	}
	return c, nil
}

func (entry Entry) unsignedBytes() ([]byte, error) {
	if (entry.Version != Version0 && entry.Version != Version1 && entry.Version != ScheduleVersion2) || entry.Version != entry.Command.Version || types.Hash(entry.AuthorityPublicKey).IsZero() {
		return nil, ErrEntry
	}
	command, err := entry.Command.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(MaximumEntryBytes)
	e.Fixed(entryMagic[:])
	e.U16(entry.Version)
	e.Fixed(command)
	e.Fixed(entry.AuthorityPublicKey[:])
	return e.Bytes(), nil
}

func (entry Entry) CanonicalBytes() ([]byte, error) {
	unsigned, err := entry.unsignedBytes()
	if err != nil {
		return nil, err
	}
	message := types.DomainHash(authorityDomain(entry.Version, "entry/signature"), unsigned)
	if !ed25519.Verify(entry.AuthorityPublicKey[:], message[:], entry.Signature[:]) {
		return nil, ErrEntry
	}
	return append(unsigned, entry.Signature[:]...), nil
}

// SignEntry does not admit, persist, or publish a command. State.ValidateNext
// and ordered durable publication are separate responsibilities.
func SignEntry(command Command, key ed25519.PrivateKey) (Entry, error) {
	if !validKey(key) {
		return Entry{}, ErrEntry
	}
	e := Entry{Version: command.Version, Command: command}
	copy(e.AuthorityPublicKey[:], key.Public().(ed25519.PublicKey))
	unsigned, err := e.unsignedBytes()
	if err != nil {
		return Entry{}, err
	}
	message := types.DomainHash(authorityDomain(e.Version, "entry/signature"), unsigned)
	copy(e.Signature[:], ed25519.Sign(key, message[:]))
	return e, nil
}

func DecodeEntry(input []byte) (Entry, error) {
	if len(input) != LegacyEntryBytes && len(input) != MaximumEntryBytes {
		return Entry{}, ErrEntry
	}
	d := codec.NewDecoder(input)
	magic, _ := d.Fixed(len(entryMagic))
	var e Entry
	e.Version, _ = d.U16()
	commandSize := LegacyCommandBytes
	if e.Version == ScheduleVersion2 {
		commandSize = MaximumCommandBytes
	}
	command, _ := d.Fixed(commandSize)
	var err error
	if e.Command, err = DecodeCommand(command); err != nil {
		return Entry{}, err
	}
	decodeFixed(d, e.AuthorityPublicKey[:])
	decodeFixed(d, e.Signature[:])
	if !bytes.Equal(magic, entryMagic[:]) || d.Finish() != nil {
		return Entry{}, ErrEntry
	}
	if _, err := e.CanonicalBytes(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func (entry Entry) ID() (types.Hash, error) {
	encoded, err := entry.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(authorityDomain(entry.Version, "entry/id"), encoded), nil
}

func validKey(key ed25519.PrivateKey) bool {
	return len(key) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key)
}
