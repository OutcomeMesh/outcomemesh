package scheduledwire

import (
	"bytes"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
)

func TestPruneScheduledNoLegacyFallbackAndExactIntentPins(t *testing.T) {
	r := request(t)
	raw, _ := r.CanonicalBytes()
	if _, err := admissionwire.DecodeRequest(raw); err == nil {
		t.Fatal("legacy admission accepted scheduled request")
	}
	if _, err := completionwire.DecodeRequest(raw); err == nil {
		t.Fatal("legacy completion accepted scheduled request")
	}
	// The fixed offsets below are independent of the encoder's field loop.
	i, _ := r.Intent.CanonicalBytes()
	if len(i) != 648 || !bytes.Equal(i[:10], []byte("OMCPSINT\x00\x00")) || !bytes.Equal(i[74:106], r.Intent.PlanID[:]) || !bytes.Equal(i[202:234], r.Intent.ReviewID[:]) {
		t.Fatal("intent field layout changed")
	}
	for _, version := range []uint16{0, 1} {
		c := r.Intent.Entry.Command
		c.Version = version
		c.ScheduleID = types.Hash{}
		c, err := c.Sign(key(6))
		if err != nil {
			t.Fatal(err)
		}
		e, err := custodyauthority.SignEntry(c, key(7))
		if err != nil {
			t.Fatal(err)
		}
		bad := r.Intent
		bad.Entry = e
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("legacy intent accepted")
		}
		if version == 0 {
			b, err := (admissionwire.Request{Nonce: r.Nonce, Entry: e}).CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(b); err == nil {
				t.Fatal("legacy request accepted")
			}
		}
	}
	for _, mutate := range []func(*Intent){
		func(i *Intent) { i.ClientPeerID = types.Hash{} }, func(i *Intent) { i.ServerPeerID = i.ClientPeerID },
		func(i *Intent) { i.PlanID = types.Hash{} }, func(i *Intent) { i.RequestID = hash(100) },
		func(i *Intent) { i.ExecutorBindingID = types.Hash{} }, func(i *Intent) { i.ReviewID = types.Hash{} },
		func(i *Intent) { i.InventoryID = hash(100) },
	} {
		bad := r.Intent
		mutate(&bad)
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("invalid intent binding accepted")
		}
	}
	for _, kind := range []custodyauthority.Kind{custodyauthority.Complete, custodyauthority.Stop, custodyauthority.Retire, custodyauthority.Admit} {
		bad := r.Intent
		c := bad.Entry.Command
		c.Kind, c.Purpose, c.OperationID, c.TicketID, c.EvidenceID = kind, 0, types.Hash{}, types.Hash{}, hash(90)
		if kind == custodyauthority.Complete {
			c.TicketID = hash(91)
			bad.InventoryID = hash(92)
		}
		if kind == custodyauthority.Admit {
			c.Purpose = custodyauthority.Serve
			c.OperationID = bad.RequestID
			c.EvidenceID = types.Hash{}
		}
		c, err := c.Sign(key(6))
		if err != nil {
			t.Fatal(err)
		}
		bad.Entry, err = custodyauthority.SignEntry(c, key(7))
		if err != nil {
			t.Fatal(err)
		}
		_, err = bad.CanonicalBytes()
		if (err == nil) != (kind == custodyauthority.Complete) {
			t.Fatal("incorrect command family", kind, err)
		}
	}
}
