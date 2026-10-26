package custodyauthority

import (
	"crypto/ed25519"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestReviewedCustodySigningPreservesExistingMessages(t *testing.T) {
	a := testAssignment()
	id, _ := a.ID()
	for _, purpose := range []Purpose{Audit, Serve} {
		actor := byte(4)
		if purpose == Serve {
			actor = 5
		}
		for _, kind := range []Kind{Admit, Complete} {
			draft := Command{AssignmentID: id, ExpectedHead: id, Kind: Admit, Purpose: purpose,
				OperationID: testHash(60), ActorPublicKey: testPublic(actor)}
			if kind == Complete {
				draft.Kind, draft.Purpose, draft.OperationID = Complete, 0, types.Hash{}
				draft.ExpectedSequence, draft.ExpectedHead = 1, testHash(61)
				draft.TicketID, draft.EvidenceID = testHash(61), testHash(62)
			}
			original := draft
			review, err := CustodyCommandReviewID(a, draft, purpose)
			if err != nil {
				t.Fatal(err)
			}
			unsigned, _ := draft.unsignedBytes()
			if review != types.DomainHash("OMESH/custody-authority/command/signature/v0", unsigned) || draft != original {
				t.Fatal("changed existing message or draft")
			}
			signed, err := SignReviewedCustodyCommand(a, draft, purpose, review, testKey(actor))
			legacy, _ := draft.Sign(testKey(actor))
			if err != nil || signed != legacy || !ed25519.Verify(signed.ActorPublicKey[:], review[:], signed.Signature[:]) {
				t.Fatal("incompatible consumer signature", err)
			}
			entryReview, err := CustodyEntryReviewID(a, signed, purpose)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := CosignReviewedCustodyCommand(a, signed, purpose, entryReview, testKey(1))
			legacyEntry, _ := SignEntry(signed, testKey(1))
			if err != nil || entry != legacyEntry || !ed25519.Verify(entry.AuthorityPublicKey[:], entryReview[:], entry.Signature[:]) {
				t.Fatal("incompatible authority signature", err)
			}
		}
	}
}

func TestReviewedCustodySigningRejectsSubstitutionAndOtherPurposes(t *testing.T) {
	a := testAssignment()
	id, _ := a.ID()
	draft := Command{AssignmentID: id, ExpectedHead: id, Kind: Admit, Purpose: Audit,
		OperationID: testHash(60), ActorPublicKey: testPublic(4)}
	review, _ := CustodyCommandReviewID(a, draft, Audit)
	for _, mutate := range []func(*Command){
		func(c *Command) { c.OperationID = testHash(61) },
		func(c *Command) { c.ActorPublicKey = testPublic(5) },
		func(c *Command) { c.ActorPublicKey = [32]byte{} },
		func(c *Command) { c.ExpectedHead = testHash(61) },
		func(c *Command) { c.ExpectedSequence = 1 },
		func(c *Command) { c.Signature[0] = 1 },
		func(c *Command) { c.Kind, c.Purpose, c.OperationID, c.EvidenceID = Stop, 0, types.Hash{}, testHash(62) },
	} {
		changed := draft
		mutate(&changed)
		if _, err := SignReviewedCustodyCommand(a, changed, Audit, review, testKey(4)); err == nil {
			t.Fatal("signed altered draft")
		}
	}
	for _, purpose := range []Purpose{0, Serve, Prune, AllPurposes} {
		if _, err := CustodyCommandReviewID(a, draft, purpose); err == nil {
			t.Fatal("accepted unrelated purpose", purpose)
		}
	}
	if _, err := SignReviewedCustodyCommand(a, draft, Audit, types.Hash{}, testKey(4)); err == nil {
		t.Fatal("signed without independent review")
	}
	malformed := append(ed25519.PrivateKey(nil), testKey(4)...)
	malformed[len(malformed)-1] ^= 1
	if _, err := SignReviewedCustodyCommand(a, draft, Audit, review, malformed); err == nil {
		t.Fatal("accepted inconsistent private key")
	}
	signed, _ := SignReviewedCustodyCommand(a, draft, Audit, review, testKey(4))
	entryReview, _ := CustodyEntryReviewID(a, signed, Audit)
	signed.Signature[0] ^= 1
	if _, err := CosignReviewedCustodyCommand(a, signed, Audit, entryReview, testKey(1)); err == nil {
		t.Fatal("co-signed invalid consumer signature")
	}
}
