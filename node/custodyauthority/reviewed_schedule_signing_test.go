package custodyauthority

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	"testing"
)

func TestReviewedScheduledAdmissionRetainsExactScopeAndBudget(t *testing.T) {
	a := testAssignment()
	aid, _ := a.ID()
	for _, purpose := range []Purpose{Audit, Serve} {
		seed := byte(4)
		if purpose == Serve {
			seed = 5
		}
		c := Command{Version: ScheduleVersion2, AssignmentID: aid, ScheduleID: testHash(70), ExpectedSequence: 1, ExpectedHead: testHash(71), Kind: Admit, Purpose: purpose, OperationID: testHash(72), ActorPublicKey: testPublic(seed)}
		review, err := ScheduledCustodyCommandReviewID(a, c, purpose)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := SignReviewedScheduledCustodyCommand(a, c, purpose, review, testKey(seed))
		if err != nil {
			t.Fatal(err)
		}
		er, err := ScheduledCustodyEntryReviewID(a, signed, purpose)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := CosignReviewedScheduledCustodyCommand(a, signed, purpose, er, testKey(1))
		want, wantErr := SignEntry(signed, testKey(1))
		if err != nil || wantErr != nil || entry != want {
			t.Fatal("signature message changed", err)
		}
		for _, mutate := range []func(*Command){
			func(c *Command) { c.ScheduleID = types.Hash{} },
			func(c *Command) { c.ScheduleID = testHash(74) },
			func(c *Command) { c.OperationID = testHash(75) },
			func(c *Command) { c.ExpectedHead = testHash(76) },
			func(c *Command) { c.ExpectedSequence++ },
			func(c *Command) { c.Purpose = Prune },
		} {
			bad := c
			mutate(&bad)
			if _, err := SignReviewedScheduledCustodyCommand(a, bad, purpose, review, testKey(seed)); err == nil {
				t.Fatal("signed substituted admission")
			}
		}
		for _, sequence := range []uint64{0, 2 * uint64(a.MaximumOperations), ^uint64(0)} {
			bad := c
			bad.ExpectedSequence = sequence
			if _, err := ScheduledCustodyCommandReviewID(a, bad, purpose); err == nil {
				t.Fatal("expanded spent-operation budget", sequence)
			}
		}
		c.ExpectedSequence = 2*uint64(a.MaximumOperations) - 1
		if _, err := ScheduledCustodyCommandReviewID(a, c, purpose); err != nil {
			t.Fatal("last original operation refused", err)
		}
		if _, err := CustodyCommandReviewID(a, c, purpose); err == nil {
			t.Fatal("legacy signing accepted scheduled admission")
		}
	}
}

func TestReviewedScheduledCompletionExactSignaturesAndLimits(t *testing.T) {
	a := testAssignment()
	aid, _ := a.ID()
	c := Command{Version: ScheduleVersion2, AssignmentID: aid, ScheduleID: testHash(70), ExpectedSequence: 2, ExpectedHead: testHash(71), Kind: Complete, TicketID: testHash(72), EvidenceID: testHash(73), ActorPublicKey: testPublic(4)}
	review, err := ScheduledCustodyCommandReviewID(a, c, Audit)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignReviewedScheduledCustodyCommand(a, c, Audit, review, testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.Sign(testKey(4))
	if err != nil || signed != want {
		t.Fatal("wrong v2 signature")
	}
	er, err := ScheduledCustodyEntryReviewID(a, signed, Audit)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := CosignReviewedScheduledCustodyCommand(a, signed, Audit, er, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := SignEntry(want, testKey(1))
	if entry != expected {
		t.Fatal("wrong v2 cosignature")
	}
	id, _ := entry.ID()
	if id.String() != "a2140ed64a446e75bc486a57bd795f1897bd66aacf6fbc615e8571fa91bc6f9b" {
		t.Fatal("scheduled completion vector changed", id)
	}
	for _, mutate := range []func(*Command){
		func(c *Command) { c.ScheduleID = testHash(74) }, func(c *Command) { c.Version = Version0; c.ScheduleID = types.Hash{} },
		func(c *Command) { c.ExpectedSequence++ }, func(c *Command) { c.TicketID = testHash(75) }, func(c *Command) { c.EvidenceID = testHash(76) }, func(c *Command) { c.ActorPublicKey = testPublic(5) },
	} {
		changed := c
		mutate(&changed)
		if _, err := SignReviewedScheduledCustodyCommand(a, changed, Audit, review, testKey(4)); err == nil {
			t.Fatal("signed substitution")
		}
	}
	for _, n := range []uint64{0, 1, 2*uint64(a.MaximumOperations) + 2} {
		changed := c
		changed.ExpectedSequence = n
		if _, err := ScheduledCustodyCommandReviewID(a, changed, Audit); err == nil {
			t.Fatal("invalid history bound", n)
		}
	}
	c.ExpectedSequence = 2*uint64(a.MaximumOperations) + 1
	if _, err := ScheduledCustodyCommandReviewID(a, c, Audit); err != nil {
		t.Fatal("full budget cannot drain", err)
	}
	if _, err := CustodyCommandReviewID(a, c, Audit); err == nil {
		t.Fatal("legacy review widened")
	}
	if _, err := ScheduledCustodyCommandReviewID(a, c, Prune); err == nil {
		t.Fatal("unreviewed purpose")
	}
}
