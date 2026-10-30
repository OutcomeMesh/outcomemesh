package custodyauthority

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	"testing"
)

func TestReviewedScheduledPruneRejectsSubstitutionAndWrongRole(t *testing.T) {
	a := testAssignment()
	aid, _ := a.ID()
	for _, kind := range []Kind{Admit, Complete} {
		t.Run(map[Kind]string{Admit: "admit", Complete: "complete"}[kind], func(t *testing.T) {
			c := Command{Version: ScheduleVersion2, AssignmentID: aid, ScheduleID: testHash(70), ExpectedSequence: 2, ExpectedHead: testHash(71), Kind: kind, ActorPublicKey: testPublic(6)}
			if kind == Admit {
				c.Purpose = Prune
				c.OperationID = testHash(72)
			} else {
				c.TicketID = testHash(72)
				c.EvidenceID = testHash(73)
			}
			review, err := ScheduledPruneCommandReviewID(a, c)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := SignReviewedScheduledPruneCommand(a, c, review, testKey(6))
			if err != nil {
				t.Fatal(err)
			}
			er, err := ScheduledPruneEntryReviewID(a, signed)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := CosignReviewedScheduledPruneCommand(a, signed, er, testKey(1))
			if err != nil {
				t.Fatal(err)
			}
			want, _ := SignEntry(signed, testKey(1))
			if entry != want {
				t.Fatal("v2 cosigning changed")
			}
			for _, mutate := range []func(*Command){func(c *Command) { c.ScheduleID = testHash(74) }, func(c *Command) { c.ExpectedHead = testHash(74) }, func(c *Command) { c.ExpectedSequence++ }, func(c *Command) { c.AssignmentID = testHash(74) }, func(c *Command) { c.ActorPublicKey = testPublic(4) }, func(c *Command) { c.ScheduleID = types.Hash{}; c.Version = Version0 }, func(c *Command) { c.Signature[0] = 1 }, func(c *Command) {
				if kind == Admit {
					c.OperationID = testHash(74)
				} else {
					c.EvidenceID = testHash(74)
				}
			}} {
				bad := c
				mutate(&bad)
				if _, err := SignReviewedScheduledPruneCommand(a, bad, review, testKey(6)); err == nil {
					t.Fatal("substituted command signed")
				}
			}
			if _, err := SignReviewedScheduledPruneCommand(a, c, review, testKey(4)); err == nil {
				t.Fatal("audit actor signed prune")
			}
			if _, err := CosignReviewedScheduledPruneCommand(a, signed, er, testKey(6)); err == nil {
				t.Fatal("consumer cosigned authority")
			}
			corrupt := signed
			corrupt.Signature[0] ^= 1
			if _, err := ScheduledPruneEntryReviewID(a, corrupt); err == nil {
				t.Fatal("invalid consumer signature cosigned")
			}
			if _, err := PruneCommandReviewID(a, c); err == nil {
				t.Fatal("v0 helper accepted v2")
			}
			if _, err := ScheduledCustodyCommandReviewID(a, c, Prune); err == nil {
				t.Fatal("audit/serve helper accepted prune")
			}
			for _, n := range []uint64{0, 1, 2*uint64(a.MaximumOperations) + 2} {
				bad := c
				bad.ExpectedSequence = n
				if kind == Admit && n == 1 {
					continue
				}
				if _, err := ScheduledPruneCommandReviewID(a, bad); err == nil {
					t.Fatal("invalid original budget bound", n)
				}
			}
		})
	}
}
