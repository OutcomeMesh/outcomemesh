package custodyv2

import (
	"bytes"
	"crypto/ed25519"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/transport"
)

func modelAdmissionDelivery(t testing.TB, role AdmissionDeliveryRole) AdmissionDelivery {
	t.Helper()
	c := requiredProfileContext(t)
	b := requiredRuntimeBinding(t, c)
	cid, _ := c.ID()
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	bid, _ := b.ID()
	sender, _ := transport.PeerIDFromPublicKey(c.Plan.ClientTransportPublicKey[:])
	recipient, _ := transport.PeerIDFromPublicKey(c.Assignment.Base.RemoteTransportPublicKey[:])
	public := c.Assignment.Base.RemoteControlPublicKey
	if role == AdmissionDeliveryAuthority {
		public = c.Assignment.Base.AuthorityPublicKey
		key := f.Public(48)
		recipient, _ = transport.PeerIDFromPublicKey(key[:])
	}
	enrollment := AdmissionDeliveryEnrollment{Version: Version2, ContextID: cid, ScopeID: sid, BindingID: bid, SenderPeerID: sender, RecipientPeerID: recipient, PlacementID: f.Hash("delivery-private-salted-placement"), Nonce: f.Hash("delivery-receiver-random-nonce"), Role: role, ReceiptPublicKey: public}
	d := AdmissionDelivery{Version: Version2, Enrollment: enrollment, Context: c, Binding: b}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAdmissionDeliveryModelRoundTripAndDeterministicReceipt(t *testing.T) {
	for _, role := range []AdmissionDeliveryRole{AdmissionDeliveryAuthority, AdmissionDeliveryTarget} {
		d := modelAdmissionDelivery(t, role)
		enrollment, err := d.Enrollment.CanonicalBytes()
		if err != nil || len(enrollment) != MaximumAdmissionDeliveryEnrollmentBytes {
			t.Fatal("enrollment framing", len(enrollment), err)
		}
		e, err := DecodeAdmissionDeliveryEnrollment(enrollment)
		if err != nil || e != d.Enrollment || e.Verify(d.Context) != nil {
			t.Fatal("enrollment round trip", err)
		}
		raw, err := d.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeAdmissionDelivery(raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := decoded.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, again) || decoded.Validate() != nil {
			t.Fatal("delivery round trip", err)
		}
		seed := byte(14)
		if role == AdmissionDeliveryAuthority {
			seed = 1
		}
		r, err := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(seed))
		if err != nil || r.Verify(decoded) != nil {
			t.Fatal("receipt not tied to exact delivery", err)
		}
		rawReceipt, err := r.CanonicalBytes()
		if err != nil || len(rawReceipt) != AdmissionDeliveryReceiptBytes {
			t.Fatal("receipt framing", len(rawReceipt), err)
		}
		cold, err := DecodeAdmissionDeliveryReceipt(rawReceipt)
		if err != nil || cold != r || cold.Verify(d) != nil {
			t.Fatal("receipt round trip", err)
		}
		other, err := (AdmissionDeliveryReceipt{}).Sign(decoded, f.Key(seed))
		if err != nil || r != other {
			t.Fatal("exact retry refreshed or replaced acknowledgement", err)
		}
		if _, err := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(49)); err == nil {
			t.Fatal("foreign role key acknowledged proof retention")
		}
		if _, err := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(seed)[:63]); err == nil {
			t.Fatal("truncated private key accepted")
		}
		// Neither a generic signature over the receipt ID nor another role's
		// signature domain is a retained-proof acknowledgement.
		unsigned, _ := r.unsignedBytes()
		h := types.DomainHash("OMESH/custody/v2/required/admission-delivery/receipt/id", unsigned)
		copy(other.Signature[:], ed25519.Sign(f.Key(seed), h[:]))
		if other.Verify(d) == nil {
			t.Fatal("receipt ID domain reused as signing authority")
		}
	}
}

func TestAdmissionDeliveryEnrollmentPinsSignedRolesAndIndependentRecipient(t *testing.T) {
	d := modelAdmissionDelivery(t, AdmissionDeliveryTarget)
	for name, mutate := range map[string]func(*AdmissionDeliveryEnrollment){
		"version":     func(e *AdmissionDeliveryEnrollment) { e.Version = 3 },
		"context":     func(e *AdmissionDeliveryEnrollment) { e.ContextID = f.Hash("other-context") },
		"scope":       func(e *AdmissionDeliveryEnrollment) { e.ScopeID = f.Hash("other-scope") },
		"bindingzero": func(e *AdmissionDeliveryEnrollment) { e.BindingID = types.Hash{} },
		"sender":      func(e *AdmissionDeliveryEnrollment) { e.SenderPeerID = f.Hash("other-sender") },
		"recipient":   func(e *AdmissionDeliveryEnrollment) { e.RecipientPeerID = f.Hash("other-recipient") },
		"same-peer":   func(e *AdmissionDeliveryEnrollment) { e.RecipientPeerID = e.SenderPeerID },
		"zero-peer":   func(e *AdmissionDeliveryEnrollment) { e.RecipientPeerID = types.Hash{} },
		"placement":   func(e *AdmissionDeliveryEnrollment) { e.PlacementID = types.Hash{} },
		"nonce":       func(e *AdmissionDeliveryEnrollment) { e.Nonce = types.Hash{} },
		"role":        func(e *AdmissionDeliveryEnrollment) { e.Role = AdmissionDeliveryRole(3) },
		"signer":      func(e *AdmissionDeliveryEnrollment) { e.ReceiptPublicKey = f.Public(49) },
		"authority-as-target": func(e *AdmissionDeliveryEnrollment) {
			e.ReceiptPublicKey = d.Context.Assignment.Base.AuthorityPublicKey
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := d.Enrollment
			mutate(&e)
			if e.Verify(d.Context) == nil {
				t.Fatal("invalid enrollment authorized delivery")
			}
		})
	}
	if d.Enrollment.Verify(fixtureContext(t)) == nil {
		t.Fatal("legacy policy acquired required-profile delivery")
	}
	invalid := d.Context
	invalid.Plan.AuthoritySignature[0] ^= 1
	if d.Enrollment.Verify(invalid) == nil {
		t.Fatal("invalid signed context authorized enrollment")
	}
	a := modelAdmissionDelivery(t, AdmissionDeliveryAuthority)
	// The assignment contains no A transport key. A different nonzero A peer
	// is a different valid descriptor, whose independent ID must be pinned.
	old, _ := a.Enrollment.ID()
	a.Enrollment.RecipientPeerID = f.Hash("explicit-independent-A-recipient")
	if a.Enrollment.Verify(a.Context) != nil {
		t.Fatal("explicit A transport enrollment rejected")
	}
	changed, _ := a.Enrollment.ID()
	if old == changed {
		t.Fatal("A transport substitution retained the independent pin")
	}
	a.Enrollment.ReceiptPublicKey = d.Context.Assignment.Base.RemoteControlPublicKey
	if a.Enrollment.Verify(a.Context) == nil {
		t.Fatal("B control key acknowledged A enrollment")
	}
}

func TestAdmissionDeliveryBindsCompleteProofAndExactEnrollment(t *testing.T) {
	d := modelAdmissionDelivery(t, AdmissionDeliveryTarget)
	originalID, _ := d.ID()
	originalEnrollment, _ := d.Enrollment.ID()
	r, err := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(14))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AdmissionDelivery){
		"version":                  func(d *AdmissionDelivery) { d.Version = 3 },
		"context":                  func(d *AdmissionDelivery) { d.Enrollment.ContextID = f.Hash("other-context") },
		"binding-id":               func(d *AdmissionDelivery) { d.Enrollment.BindingID = f.Hash("other-binding") },
		"missing-chain":            func(d *AdmissionDelivery) { d.Binding.Chain = nil },
		"weak-quorum":              func(d *AdmissionDelivery) { d.Binding.Chain[0].Votes = d.Binding.Chain[0].Votes[:2] },
		"wrong-genesis-descriptor": func(d *AdmissionDelivery) { d.Binding.Genesis.CustodyPolicy.MaximumProofAge++ },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := d.CanonicalBytes()
			value, err := DecodeAdmissionDelivery(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&value)
			if value.Validate() == nil || r.Verify(value) == nil {
				t.Fatal("altered proof remained acknowledged")
			}
		})
	}
	// Another valid QC subset is another immutable binding/delivery. It must
	// never match the original receiver or outbox identity by semantic Admit ID.
	raw, _ := d.CanonicalBytes()
	alternate, _ := DecodeAdmissionDelivery(raw)
	q := &alternate.Binding.Chain[0]
	q.Votes = nil
	for _, seed := range []byte{70, 71, 73} {
		v, err := signAdmissionVote(q.Entry, f.Key(seed))
		if err != nil {
			t.Fatal(err)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if alternate.Binding.Verify(alternate.Context) != nil {
		t.Fatal("alternate QC fixture is invalid")
	}
	if alternate.Validate() == nil {
		t.Fatal("alternate valid proof adopted under old binding pin")
	}
	alternate.Enrollment.BindingID, _ = alternate.Binding.ID()
	if alternate.Validate() != nil || r.Verify(alternate) == nil {
		t.Fatal("alternate valid proof reused original receipt")
	}
	id, _ := alternate.ID()
	eid, _ := alternate.Enrollment.ID()
	if id == originalID || eid == originalEnrollment {
		t.Fatal("alternate QC subset retained original delivery identity")
	}
	for _, mutate := range []func(*AdmissionDeliveryEnrollment){
		func(e *AdmissionDeliveryEnrollment) { e.PlacementID = f.Hash("new-salted-placement") },
		func(e *AdmissionDeliveryEnrollment) { e.Nonce = f.Hash("new-enrollment-nonce") },
	} {
		value := d
		mutate(&value.Enrollment)
		id, err := value.ID()
		if err != nil || id == originalID || r.Verify(value) == nil {
			t.Fatal("new physical enrollment reused original delivery", err)
		}
	}
	for _, mutate := range []func(*AdmissionDeliveryReceipt){
		func(r *AdmissionDeliveryReceipt) { r.Version = 3 },
		func(r *AdmissionDeliveryReceipt) { r.DeliveryID = f.Hash("other-delivery") },
		func(r *AdmissionDeliveryReceipt) { r.EnrollmentID = f.Hash("other-enrollment") },
		func(r *AdmissionDeliveryReceipt) { r.ContextID = f.Hash("other-context") },
		func(r *AdmissionDeliveryReceipt) { r.ScopeID = f.Hash("other-scope") },
		func(r *AdmissionDeliveryReceipt) { r.BindingID = f.Hash("other-binding") },
		func(r *AdmissionDeliveryReceipt) { r.Role = AdmissionDeliveryAuthority },
		func(r *AdmissionDeliveryReceipt) { r.Signature[0] ^= 1 },
	} {
		changed := r
		mutate(&changed)
		if changed.Verify(d) == nil {
			t.Fatal("changed acknowledgement accepted")
		}
	}
}

func TestAdmissionDeliveryDecodersRejectNonCanonicalAndOversizedPackets(t *testing.T) {
	d := modelAdmissionDelivery(t, AdmissionDeliveryTarget)
	raw, _ := d.CanonicalBytes()
	e, _ := d.Enrollment.CanonicalBytes()
	r, _ := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(14))
	ack, _ := r.CanonicalBytes()
	for _, item := range []struct {
		raw    []byte
		decode func([]byte) error
	}{
		{raw, func(b []byte) error { _, err := DecodeAdmissionDelivery(b); return err }},
		{e, func(b []byte) error { _, err := DecodeAdmissionDeliveryEnrollment(b); return err }},
		{ack, func(b []byte) error { _, err := DecodeAdmissionDeliveryReceipt(b); return err }},
	} {
		for _, n := range []int{0, 1, 8, 9, 10, len(item.raw) - 1} {
			if item.decode(item.raw[:n]) == nil {
				t.Fatal("truncated public packet decoded", n)
			}
		}
		if item.decode(append(append([]byte{}, item.raw...), 0)) == nil {
			t.Fatal("trailing public packet bytes decoded")
		}
		changed := append([]byte{}, item.raw...)
		changed[0] ^= 1
		if item.decode(changed) == nil {
			t.Fatal("foreign packet magic decoded")
		}
		changed = append([]byte{}, item.raw...)
		changed[9] = 3
		if item.decode(changed) == nil {
			t.Fatal("foreign packet version decoded")
		}
	}
	if _, err := DecodeAdmissionDelivery(make([]byte, MaximumAdmissionDeliveryBytes+1)); err == nil {
		t.Fatal("oversized delivery packet decoded")
	}
	// A redundant uvarint byte cannot produce a second delivery identity.
	overlong := append([]byte{}, raw[:10]...)
	overlong = append(overlong, 0x8b, 0x82, 0x00) // enrollment length 267, overlong
	overlong = append(overlong, raw[12:]...)
	if _, err := DecodeAdmissionDelivery(overlong); err == nil {
		t.Fatal("overlong enrollment length decoded")
	}
	b, _ := d.Binding.CanonicalBytes()
	if got, err := deliveryBindingBytes(d.Binding, len(b)); err != nil || !bytes.Equal(got, b) {
		t.Fatal("exact binding boundary rejected", err)
	}
	if _, err := deliveryBindingBytes(d.Binding, len(b)-1); err == nil {
		t.Fatal("binding preflight limit ignored")
	}
	// The framing cannot advertise allocation outside the channel cap.
	out := codec.NewEncoder(32)
	out.Fixed([]byte("OMCVDLV2"))
	out.U16(Version2)
	out.Uvarint(uint64(MaximumAdmissionDeliveryEnrollmentBytes + 1))
	if _, err := DecodeAdmissionDelivery(out.Bytes()); err == nil {
		t.Fatal("oversized nested enrollment decoded")
	}
}

func TestAdmissionDeliveryGoldenDomains(t *testing.T) {
	d := modelAdmissionDelivery(t, AdmissionDeliveryTarget)
	eid, _ := d.Enrollment.ID()
	id, _ := d.ID()
	r, _ := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(14))
	rid, _ := r.ID()
	if eid.String() != "fe5493db2038d73c046a7d0bc3eab95e23b4c72d738fbdaf107d1fa8fd36ee83" || id.String() != "7574bacbff84084d870ea34ac309e34ed48f6614f19c813b7e138dbb54b60f51" || rid.String() != "9dd7861877a155fbad4592bcc1a0547a882f0480a25832354ef42e34cbc9c828" {
		t.Fatal("public enrollment, delivery or deterministic receipt vector changed", eid, id, rid)
	}
	for _, item := range []struct {
		id     types.Hash
		domain string
		raw    []byte
	}{
		{eid, "OMESH/custody/v2/required/admission-delivery/enrollment/id", func() []byte { b, _ := d.Enrollment.CanonicalBytes(); return b }()},
		{id, "OMESH/custody/v2/required/admission-delivery/id", func() []byte { b, _ := d.CanonicalBytes(); return b }()},
		{rid, "OMESH/custody/v2/required/admission-delivery/receipt/id", func() []byte { b, _ := r.CanonicalBytes(); return b }()},
	} {
		if item.id != types.DomainHash(item.domain, item.raw) || item.id == types.DomainHash("OMESH/custody/v2/required/admission-binding/id", item.raw) {
			t.Fatal("delivery domain separated incorrectly")
		}
	}
}

func FuzzAdmissionDeliveryPublicPackets(fz *testing.F) {
	for _, role := range []AdmissionDeliveryRole{AdmissionDeliveryAuthority, AdmissionDeliveryTarget} {
		d := modelAdmissionDelivery(fz, role)
		e, _ := d.Enrollment.CanonicalBytes()
		raw, _ := d.CanonicalBytes()
		seed := byte(14)
		if role == AdmissionDeliveryAuthority {
			seed = 1
		}
		r, _ := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(seed))
		ack, _ := r.CanonicalBytes()
		fz.Add(e)
		fz.Add(raw)
		fz.Add(ack)
	}
	fz.Fuzz(func(t *testing.T, raw []byte) {
		if e, err := DecodeAdmissionDeliveryEnrollment(raw); err == nil {
			again, err := e.CanonicalBytes()
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("enrollment canonical round trip", err)
			}
		}
		if d, err := DecodeAdmissionDelivery(raw); err == nil {
			again, err := d.CanonicalBytes()
			if err != nil || !bytes.Equal(raw, again) || d.Validate() != nil {
				t.Fatal("delivery canonical round trip", err)
			}
		}
		if r, err := DecodeAdmissionDeliveryReceipt(raw); err == nil {
			again, err := r.CanonicalBytes()
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("receipt canonical round trip", err)
			}
		}
	})
}
