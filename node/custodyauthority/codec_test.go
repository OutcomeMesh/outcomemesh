package custodyauthority

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestAuthorityCanonicalGoldenHistory(t *testing.T) {
	a, entries, final := testHistory(t)
	encoded, err := a.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAssignment(encoded)
	if err != nil || !reflect.DeepEqual(a, decoded) {
		t.Fatal("assignment round trip", err)
	}
	id, _ := a.ID()
	if id.String() != "0a971f736838505235eef8d8f342e3370e574681f71cc3c3f033b459e40b9931" || len(encoded) != 451 {
		t.Fatalf("assignment=%s bytes=%d", id, len(encoded))
	}
	wantEntries := []string{
		"a9054c2e49821a3dbe12bee0fced4616c2b7c211ef71ef52c99477643998cb6d",
		"d90ef8040cf4251489860ea36c25c008ceb2a112c9f44798f2d08479b64b2396",
		"d8fb8af2bce85728f50eae473d9f1889927bfbd0742d61336b6ab4041d681779",
		"47abddf64308e60e98d28aefcaa9b633b429fbaa85f6e765c1b165dbc7df83e1",
		"43c31b2150ea26bac7a8355c377f57e21314d60091ab1e32983fdf8eae331745",
		"4ef0bac9e865e9b107fca609ed9c0134dcce41db3e094d4890ccac97347b9586",
	}
	for index, entry := range entries {
		encoded, err := entry.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) != MaximumEntryBytes {
			t.Fatalf("entry bytes=%d", len(encoded))
		}
		decoded, err := DecodeEntry(encoded)
		if err != nil || decoded != entry {
			t.Fatal("entry round trip", err)
		}
		command, _ := entry.Command.CanonicalBytes()
		if len(command) != MaximumCommandBytes {
			t.Fatalf("command bytes=%d", len(command))
		}
		decodedCommand, err := DecodeCommand(command)
		if err != nil || decodedCommand != entry.Command {
			t.Fatal("command round trip", err)
		}
		id, _ := entry.ID()
		if id.String() != wantEntries[index] {
			t.Fatalf("entry[%d]=%s", index, id)
		}
	}
	state, err := Replay(decoded, id, entries, Position{final.Sequence, final.HeadID})
	if err != nil || !reflect.DeepEqual(testSnapshot(t, state), final) {
		t.Fatal("golden replay", err)
	}
}

func TestAuthorityCodecsRejectTruncationMutationAndCrossDomainSignatures(t *testing.T) {
	a, entries, _ := testHistory(t)
	assignment, _ := a.CanonicalBytes()
	command, _ := entries[0].Command.CanonicalBytes()
	entry, _ := entries[0].CanonicalBytes()
	for _, item := range []struct {
		name   string
		data   []byte
		decode func([]byte) error
	}{
		{"assignment", assignment, func(b []byte) error { _, e := DecodeAssignment(b); return e }},
		{"command", command, func(b []byte) error { _, e := DecodeCommand(b); return e }},
		{"entry", entry, func(b []byte) error { _, e := DecodeEntry(b); return e }},
	} {
		t.Run(item.name, func(t *testing.T) {
			for length := 0; length < len(item.data); length++ {
				if item.decode(item.data[:length]) == nil {
					t.Fatalf("accepted truncated length=%d", length)
				}
			}
			if item.decode(append(append([]byte(nil), item.data...), 0)) == nil {
				t.Fatal("accepted trailing byte")
			}
			changed := append([]byte(nil), item.data...)
			changed[8], changed[9] = 0, 1
			if item.decode(changed) == nil {
				t.Fatal("accepted unknown version")
			}
			changed[0] ^= 1
			if item.decode(changed) == nil {
				t.Fatal("accepted wrong magic")
			}
		})
	}
	for index := range command {
		changed := append([]byte(nil), command...)
		changed[index] ^= 1
		if _, err := DecodeCommand(changed); err == nil {
			t.Fatalf("accepted command mutation at %d", index)
		}
	}
	for index := range entry {
		changed := append([]byte(nil), entry...)
		changed[index] ^= 1
		if _, err := DecodeEntry(changed); err == nil {
			t.Fatalf("accepted entry mutation at %d", index)
		}
	}
	c := entries[0].Command
	unsigned, _ := c.unsignedBytes()
	wrongDomain := types.DomainHash("OMESH/workgraph/archive/replica-receipt/signature/v0", unsigned)
	copy(c.Signature[:], ed25519.Sign(testKey(4), wrongDomain[:]))
	if _, err := c.CanonicalBytes(); !errors.Is(err, ErrCommand) {
		t.Fatal("receipt-domain signature became authority command", err)
	}
	e := entries[0]
	unsigned, _ = e.unsignedBytes()
	wrongDomain = types.DomainHash("OMESH/custody-authority/command/signature/v0", unsigned)
	copy(e.Signature[:], ed25519.Sign(testKey(1), wrongDomain[:]))
	if _, err := e.CanonicalBytes(); !errors.Is(err, ErrEntry) {
		t.Fatal("command-domain signature became authority entry", err)
	}
	if _, err := DecodeCommand(entry); err == nil {
		t.Fatal("entry decoded as command")
	}
	if _, err := DecodeEntry(command); err == nil {
		t.Fatal("command decoded as entry")
	}
	if _, err := DecodeAssignment(make([]byte, MaximumAssignmentBytes+1)); !errors.Is(err, ErrAssignment) {
		t.Fatal(err)
	}
}

func TestAuthorityAssignmentRejectsAliasedKeysAndUnboundedMembership(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Assignment)
	}{
		{"zero-network", func(a *Assignment) { a.NetworkID = 0 }},
		{"zero-incarnation", func(a *Assignment) { a.IncarnationID = types.Hash{} }},
		{"authority-is-replica", func(a *Assignment) { a.AuthorityPublicKey = a.ReplicaPublicKey }},
		{"authority-is-auditor", func(a *Assignment) { a.AuthorityPublicKey = a.Auditors[0] }},
		{"consumer-is-authority", func(a *Assignment) { a.Consumers[0].PublicKey = a.AuthorityPublicKey }},
		{"consumer-is-evidence-key", func(a *Assignment) { a.Consumers[0].PublicKey = a.ReplicaPublicKey }},
		{"empty-auditors", func(a *Assignment) { a.Auditors = nil }},
		{"duplicate-auditors", func(a *Assignment) { a.Auditors = append(a.Auditors, a.Auditors[0]) }},
		{"duplicate-consumers", func(a *Assignment) { a.Consumers[1] = a.Consumers[0] }},
		{"unsorted-consumers", func(a *Assignment) { a.Consumers[0], a.Consumers[1] = a.Consumers[1], a.Consumers[0] }},
		{"missing-purpose", func(a *Assignment) {
			for i := range a.Consumers {
				a.Consumers[i].Purposes = Audit
			}
		}},
		{"unknown-purpose", func(a *Assignment) { a.Consumers[0].Purposes = 128 }},
		{"zero-key", func(a *Assignment) { a.Consumers[0].PublicKey = [ed25519.PublicKeySize]byte{} }},
		{"operations-zero", func(a *Assignment) { a.MaximumOperations = 0 }},
		{"operations-overflow", func(a *Assignment) { a.MaximumOperations = MaximumOperations + 1 }},
		{"pending-zero", func(a *Assignment) { a.MaximumPending = 0 }},
		{"pending-overflow", func(a *Assignment) { a.MaximumPending = MaximumPending + 1 }},
		{"pending-exceeds-total", func(a *Assignment) { a.MaximumPending = uint16(a.MaximumOperations + 1) }},
		{"too-many-consumers", func(a *Assignment) { a.Consumers = make([]Consumer, MaximumMembers+1) }},
		{"too-many-auditors", func(a *Assignment) { a.Auditors = make([][ed25519.PublicKeySize]byte, MaximumMembers+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testAssignment()
			tc.mutate(&a)
			if _, err := a.CanonicalBytes(); !errors.Is(err, ErrAssignment) {
				t.Fatal("invalid assignment accepted", err)
			}
		})
	}
	a := testAssignment()
	a.MaximumOperations = MaximumOperations
	a.MaximumPending = MaximumPending
	if _, err := a.ID(); err != nil {
		t.Fatal("hard limits must be inclusive", err)
	}
}

func TestAuthorityCommandsRequireExactShapesAndConsistentPrivateKeys(t *testing.T) {
	_, entries, _ := testHistory(t)
	for _, tc := range []struct {
		name    string
		command Command
		mutate  func(*Command)
	}{
		{"unknown-kind", entries[0].Command, func(c *Command) { c.Kind = 5 }},
		{"max-sequence", entries[0].Command, func(c *Command) { c.ExpectedSequence = ^uint64(0) }},
		{"multi-purpose", entries[0].Command, func(c *Command) { c.Purpose = AllPurposes }},
		{"admit-with-ticket", entries[0].Command, func(c *Command) { c.TicketID = testHash(88) }},
		{"admit-with-evidence", entries[0].Command, func(c *Command) { c.EvidenceID = testHash(88) }},
		{"complete-with-purpose", entries[3].Command, func(c *Command) { c.Purpose = Audit }},
		{"complete-without-ticket", entries[3].Command, func(c *Command) { c.TicketID = types.Hash{} }},
		{"complete-without-evidence", entries[3].Command, func(c *Command) { c.EvidenceID = types.Hash{} }},
		{"stop-with-operation", entries[2].Command, func(c *Command) { c.OperationID = testHash(88) }},
		{"retire-without-stop", entries[5].Command, func(c *Command) { c.EvidenceID = types.Hash{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.command
			tc.mutate(&c)
			if _, err := c.unsignedBytes(); !errors.Is(err, ErrCommand) {
				t.Fatal("accepted malformed command", err)
			}
		})
	}
	c := entries[0].Command
	for _, key := range []ed25519.PrivateKey{nil, make([]byte, ed25519.PrivateKeySize), testKey(5)} {
		if _, err := c.Sign(key); !errors.Is(err, ErrCommand) {
			t.Fatal("accepted inconsistent or wrong key", err)
		}
	}
	key := testKey(4)
	key[len(key)-1] ^= 1
	if _, err := c.Sign(key); !errors.Is(err, ErrCommand) {
		t.Fatal("accepted seed/public mismatch", err)
	}
	if _, err := SignEntry(c, key); !errors.Is(err, ErrEntry) {
		t.Fatal("authority accepted seed/public mismatch", err)
	}
}

func FuzzDecodeAuthorityAssignment(f *testing.F) {
	seed, _ := testAssignment().CanonicalBytes()
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte("OMCAASGN"))
	f.Fuzz(func(t *testing.T, input []byte) {
		a, err := DecodeAssignment(input)
		if err != nil {
			return
		}
		encoded, err := a.CanonicalBytes()
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("noncanonical assignment accepted", err)
		}
	})
}

func FuzzDecodeAuthorityEntry(f *testing.F) {
	_, entries, _ := testHistory(f)
	for _, entry := range entries {
		encoded, _ := entry.CanonicalBytes()
		f.Add(encoded)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		entry, err := DecodeEntry(input)
		if err != nil {
			return
		}
		encoded, err := entry.CanonicalBytes()
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("noncanonical entry accepted", err)
		}
	})
}

func FuzzDecodeAuthorityCommand(f *testing.F) {
	_, entries, _ := testHistory(f)
	for _, entry := range entries {
		encoded, _ := entry.Command.CanonicalBytes()
		f.Add(encoded)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		command, err := DecodeCommand(input)
		if err != nil {
			return
		}
		encoded, err := command.CanonicalBytes()
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("noncanonical command accepted", err)
		}
	})
}
