package custodyauthority

import (
	"crypto/ed25519"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestV1CustodyReviewUsesExactV1MessagesAndRejectsV0(t *testing.T) {
	a := remoteTestAssignment(t)
	id, _ := a.ID()
	for _, purpose := range []Purpose{Audit, Serve} {
		actor := byte(4)
		if purpose == Serve {
			actor = 5
		}
		for _, kind := range []Kind{Admit, Complete} {
			draft := Command{Version: Version1, AssignmentID: id, ExpectedHead: id, Kind: Admit, Purpose: purpose, OperationID: testHash(60), ActorPublicKey: testPublic(actor)}
			if kind == Complete {
				draft.Kind, draft.Purpose, draft.OperationID = Complete, 0, types.Hash{}
				draft.ExpectedSequence, draft.ExpectedHead = 4, testHash(61)
				draft.TicketID, draft.EvidenceID = testHash(62), testHash(63)
			}
			review, err := V1CustodyCommandReviewID(a, draft, purpose)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := draft.unsignedBytes()
			if review != types.DomainHash("OMESH/custody-authority/command/signature/v1", b) {
				t.Fatal("incorrect V1 domain")
			}
			command, err := SignReviewedV1CustodyCommand(a, draft, purpose, review, testKey(actor))
			legacy, _ := draft.Sign(testKey(actor))
			if err != nil || command != legacy || !ed25519.Verify(command.ActorPublicKey[:], review[:], command.Signature[:]) {
				t.Fatal("changed V1 signature", err)
			}
			entryReview, err := V1CustodyEntryReviewID(a, command, purpose)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := CosignReviewedV1CustodyCommand(a, command, purpose, entryReview, testKey(1))
			expected, _ := SignEntry(command, testKey(1))
			if err != nil || entry != expected {
				t.Fatal("changed V1 authority signature", err)
			}
			if _, err := CustodyCommandReviewID(a, draft, purpose); err == nil {
				t.Fatal("legacy workflow admitted V1")
			}
			if _, err := SignReviewedV1CustodyCommand(a, draft, purpose, review, testKey(1)); err == nil {
				t.Fatal("authority used as consumer")
			}
			command.Signature[0] ^= 1
			if _, err := CosignReviewedV1CustodyCommand(a, command, purpose, entryReview, testKey(1)); err == nil {
				t.Fatal("co-signed corrupt actor signature")
			}
		}
	}
	v0 := testAssignment()
	v0ID, _ := v0.ID()
	if _, err := V1CustodyCommandReviewID(v0, Command{AssignmentID: v0ID, ExpectedHead: v0ID, Kind: Admit, Purpose: Audit, OperationID: testHash(60), ActorPublicKey: testPublic(4)}, Audit); err == nil {
		t.Fatal("V1 workflow admitted V0")
	}
}

func TestV1CustodyReviewRejectsAlteredDraftRolesAndBounds(t *testing.T) {
	a := remoteTestAssignment(t)
	id, _ := a.ID()
	draft := Command{Version: Version1, AssignmentID: id, ExpectedHead: id, Kind: Admit, Purpose: Audit, OperationID: testHash(60), ActorPublicKey: testPublic(4)}
	review, _ := V1CustodyCommandReviewID(a, draft, Audit)
	for _, mutate := range []func(*Command){
		func(c *Command) { c.Version = Version0 },
		func(c *Command) { c.AssignmentID = testHash(61) },
		func(c *Command) { c.ExpectedHead = testHash(61) },
		func(c *Command) { c.ExpectedSequence = 1 },
		func(c *Command) { c.OperationID = testHash(61) },
		func(c *Command) { c.ActorPublicKey = a.RemoteControlPublicKey },
		func(c *Command) { c.Signature[0] = 1 },
	} {
		c := draft
		mutate(&c)
		if _, err := SignReviewedV1CustodyCommand(a, c, Audit, review, testKey(4)); err == nil {
			t.Fatal("signed substituted draft")
		}
	}
	for _, purpose := range []Purpose{0, Serve, Prune, AllPurposes} {
		if _, err := V1CustodyCommandReviewID(a, draft, purpose); err == nil {
			t.Fatal("accepted incorrect purpose", purpose)
		}
	}
	for _, kind := range []Kind{Stop, Retire, RemoteBegin, RemoteDrained} {
		c := draft
		c.Kind = kind
		if _, err := V1CustodyCommandReviewID(a, c, Audit); err == nil {
			t.Fatal("ordinary consumer reviewed a control command")
		}
	}
	draft.ExpectedSequence, draft.ExpectedHead = 4*uint64(a.MaximumOperations), testHash(61)
	if _, err := V1CustodyCommandReviewID(a, draft, Audit); err == nil {
		t.Fatal("used reserved final positions")
	}
}
