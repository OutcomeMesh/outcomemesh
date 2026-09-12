package custodyauthority

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func reviewedPruneDraft(t testing.TB) (Assignment, Command) {
	t.Helper()
	a := testAssignment()
	id, err := a.ID()
	if err != nil {
		t.Fatal(err)
	}
	return a, Command{AssignmentID: id, ExpectedHead: id, Kind: Admit, Purpose: Prune,
		OperationID: testHash(50), ActorPublicKey: testPublic(6)}
}

func TestReviewedPruneSigningPreservesExistingMessages(t *testing.T) {
	a, draft := reviewedPruneDraft(t)
	for _, kind := range []Kind{Admit, Complete} {
		t.Run(map[Kind]string{Admit: "admit", Complete: "complete"}[kind], func(t *testing.T) {
			c := draft
			if kind == Complete {
				c.Kind, c.Purpose, c.OperationID = Complete, 0, types.Hash{}
				c.ExpectedSequence, c.ExpectedHead = 1, testHash(51)
				c.TicketID, c.EvidenceID = testHash(51), testHash(52)
			}
			original := c
			review, err := PruneCommandReviewID(a, c)
			if err != nil {
				t.Fatal(err)
			}
			unsigned, _ := c.unsignedBytes()
			if review != types.DomainHash("OMESH/custody-authority/command/signature/v0", unsigned) || c != original {
				t.Fatal("review changed the message or draft")
			}
			signed, err := SignReviewedPruneCommand(a, c, review, testKey(6))
			legacy, _ := c.Sign(testKey(6))
			if err != nil || signed != legacy || !ed25519.Verify(signed.ActorPublicKey[:], review[:], signed.Signature[:]) {
				t.Fatalf("consumer message compatibility: %v", err)
			}
			entryReview, err := PruneEntryReviewID(a, signed)
			if err != nil || entryReview == review {
				t.Fatalf("entry review: %v", err)
			}
			entry, err := CosignReviewedPruneCommand(a, signed, entryReview, testKey(1))
			legacyEntry, _ := SignEntry(signed, testKey(1))
			if err != nil || entry != legacyEntry || !ed25519.Verify(entry.AuthorityPublicKey[:], entryReview[:], entry.Signature[:]) {
				t.Fatalf("authority message compatibility: %v", err)
			}
			encoded, _ := entry.CanonicalBytes()
			decoded, err := DecodeEntry(encoded)
			if err != nil || decoded != entry {
				t.Fatalf("existing codec: %v", err)
			}
			if again, err := CosignReviewedPruneCommand(a, signed, entryReview, testKey(1)); err != nil || again != entry {
				t.Fatalf("exact retry: %v", err)
			}
		})
	}
}

func TestReviewedPruneSigningRejectsInvalidDrafts(t *testing.T) {
	a, draft := reviewedPruneDraft(t)
	review, _ := PruneCommandReviewID(a, draft)
	cases := map[string]func(*Command){
		"signature":           func(c *Command) { c.Signature[0] = 1 },
		"version":             func(c *Command) { c.Version++ },
		"assignment":          func(c *Command) { c.AssignmentID = testHash(99) },
		"zero head":           func(c *Command) { c.ExpectedHead = types.Hash{} },
		"initial head":        func(c *Command) { c.ExpectedHead = testHash(55) },
		"later initial head":  func(c *Command) { c.ExpectedSequence = 1 },
		"too late admit":      func(c *Command) { c.ExpectedSequence = 7; c.ExpectedHead = testHash(55) },
		"sequence overflow":   func(c *Command) { c.ExpectedSequence = ^uint64(0); c.ExpectedHead = testHash(55) },
		"no actor":            func(c *Command) { c.ActorPublicKey = [32]byte{} },
		"other purpose actor": func(c *Command) { c.ActorPublicKey = testPublic(4) },
		"authority actor":     func(c *Command) { c.ActorPublicKey = testPublic(1) },
		"evidence actor":      func(c *Command) { c.ActorPublicKey = testPublic(2) },
		"unknown actor":       func(c *Command) { c.ActorPublicKey = testPublic(99) },
		"audit":               func(c *Command) { c.Purpose = Audit },
		"mixed purpose":       func(c *Command) { c.Purpose = AllPurposes },
		"empty operation":     func(c *Command) { c.OperationID = types.Hash{} },
		"extra ticket":        func(c *Command) { c.TicketID = testHash(55) },
		"extra evidence":      func(c *Command) { c.EvidenceID = testHash(55) },
		"stop": func(c *Command) {
			c.Kind = Stop
			c.Purpose = 0
			c.OperationID = types.Hash{}
			c.EvidenceID = testHash(55)
			c.ActorPublicKey = testPublic(1)
		},
		"retire": func(c *Command) {
			c.Kind = Retire
			c.Purpose = 0
			c.OperationID = types.Hash{}
			c.EvidenceID = testHash(55)
			c.ActorPublicKey = testPublic(1)
		},
		"unknown kind": func(c *Command) { c.Kind = 99 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := draft
			mutate(&c)
			if id, err := PruneCommandReviewID(a, c); err == nil || !id.IsZero() {
				t.Fatal("invalid draft accepted")
			}
			if got, err := SignReviewedPruneCommand(a, c, review, testKey(6)); err == nil || got != (Command{}) {
				t.Fatal("invalid draft signed")
			}
		})
	}
	for _, sequence := range []uint64{0, 1, 6, 7, 8, 9} {
		c := draft
		c.Kind, c.Purpose, c.OperationID = Complete, 0, types.Hash{}
		c.TicketID, c.EvidenceID = testHash(51), testHash(52)
		c.ExpectedSequence = sequence
		if sequence > 0 {
			c.ExpectedHead = testHash(53)
		}
		_, err := PruneCommandReviewID(a, c)
		if (err == nil) != (sequence >= 1 && sequence <= 8) {
			t.Fatalf("completion sequence %d: %v", sequence, err)
		}
	}
	if id, err := PruneCommandReviewID(Assignment{}, draft); err == nil || !id.IsZero() {
		t.Fatal("invalid assignment accepted")
	}
}

func TestReviewedPruneSigningRequiresExactPinsAndKeys(t *testing.T) {
	a, draft := reviewedPruneDraft(t)
	review, _ := PruneCommandReviewID(a, draft)
	for _, expected := range []types.Hash{{}, testHash(77)} {
		if c, err := SignReviewedPruneCommand(a, draft, expected, nil); !errors.Is(err, ErrPruneReview) || c != (Command{}) {
			t.Fatalf("review checked after key or signature returned: %v", err)
		}
	}
	corrupt := append(ed25519.PrivateKey(nil), testKey(6)...)
	corrupt[40] ^= 1
	for _, key := range []ed25519.PrivateKey{nil, make([]byte, 63), testKey(1), testKey(4), testKey(45), corrupt} {
		copyBefore := append([]byte(nil), key...)
		if c, err := SignReviewedPruneCommand(a, draft, review, key); err == nil || c != (Command{}) {
			t.Fatal("wrong key signed")
		}
		if !bytes.Equal(key, copyBefore) {
			t.Fatal("caller key mutated")
		}
	}
	changed := draft
	changed.OperationID = testHash(88)
	changedReview, _ := PruneCommandReviewID(a, changed)
	if changedReview == review {
		t.Fatal("review did not bind operation")
	}
	if c, err := SignReviewedPruneCommand(a, changed, review, testKey(6)); err == nil || c != (Command{}) {
		t.Fatal("stale review signed changed operation")
	}
	signed, _ := SignReviewedPruneCommand(a, draft, review, testKey(6))
	if _, err := PruneCommandReviewID(a, signed); err == nil {
		t.Fatal("re-signing populated draft")
	}
	entryReview, _ := PruneEntryReviewID(a, signed)
	for _, expected := range []types.Hash{{}, review, testHash(77)} {
		if e, err := CosignReviewedPruneCommand(a, signed, expected, nil); !errors.Is(err, ErrPruneReview) || e != (Entry{}) {
			t.Fatalf("co-sign review checked after key: %v", err)
		}
	}
	for _, key := range []ed25519.PrivateKey{nil, make([]byte, 63), testKey(6), testKey(45), corrupt} {
		if e, err := CosignReviewedPruneCommand(a, signed, entryReview, key); err == nil || e != (Entry{}) {
			t.Fatal("wrong authority key co-signed")
		}
	}
	for _, c := range []Command{draft, func() Command { c := signed; c.Signature[0] ^= 1; return c }(), func() Command { c := signed; c.ExpectedHead = testHash(77); return c }()} {
		if id, err := PruneEntryReviewID(a, c); err == nil || !id.IsZero() {
			t.Fatal("unverified consumer command reviewed")
		}
		if e, err := CosignReviewedPruneCommand(a, c, entryReview, testKey(1)); err == nil || e != (Entry{}) {
			t.Fatal("unverified consumer command co-signed")
		}
	}
}
