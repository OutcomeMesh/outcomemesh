package custodyv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"time"
)

func modelEnrolledDelivery(t testing.TB, role AdmissionDeliveryRole) AdmissionDelivery {
	t.Helper()
	c, g := enrolledContext(t)
	ad := requiredRuntimeBinding(t, c)
	proof := enrollmentFor(t, c, ad, g)
	cid, _ := c.ID()
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	bid, _ := ad.ID()
	rid, _ := proof.ID()
	sender, _ := transport.PeerIDFromPublicKey(c.Plan.ClientTransportPublicKey[:])
	pub := f.Public(15)
	key := f.Public(14)
	if role == AdmissionDeliveryAuthority {
		pub = f.Public(48)
		key = f.Public(1)
	}
	recipient, _ := transport.PeerIDFromPublicKey(pub[:])
	e := AdmissionDeliveryEnrollment{Version: PolicyVersionEnrolled, ContextID: cid, ScopeID: sid, BindingID: bid, RegistryEnrollmentID: rid, SenderPeerID: sender, RecipientPeerID: recipient, PlacementID: f.Hash("delivery-private-salted-placement"), Nonce: f.Hash("delivery-receiver-random-nonce"), Role: role, ReceiptPublicKey: key}
	d := AdmissionDelivery{Version: PolicyVersionEnrolled, Enrollment: e, Context: c, Binding: ad, RegistryEnrollment: proof}
	if e := d.Validate(); e != nil {
		t.Fatal(e)
	}
	return d
}
func TestAdmissionDeliveryEnrolledModelsBindBothCompleteProofs(t *testing.T) {
	for _, role := range []AdmissionDeliveryRole{AdmissionDeliveryAuthority, AdmissionDeliveryTarget} {
		d := modelEnrolledDelivery(t, role)
		raw, e := d.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := DecodeAdmissionDelivery(raw)
		if e != nil {
			t.Fatal(e)
		}
		again, e := decoded.CanonicalBytes()
		if e != nil || !bytes.Equal(again, raw) {
			t.Fatal("noncanonical packet", e)
		}
		proof, _ := d.RegistryEnrollment.CanonicalBytes()
		retained, _ := decoded.RegistryEnrollment.CanonicalBytes()
		if !bytes.Equal(proof, retained) {
			t.Fatal("registry proof missing")
		}
		seed := byte(14)
		if role == AdmissionDeliveryAuthority {
			seed = 1
		}
		receipt, e := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		ack, e := receipt.CanonicalBytes()
		if e != nil || len(ack) != EnrolledDeliveryReceiptBytes {
			t.Fatal("new receipt framing", e)
		}
		r, e := DecodeAdmissionDeliveryReceipt(ack)
		if e != nil || r.Verify(d) != nil || r.RegistryEnrollmentID != d.Enrollment.RegistryEnrollmentID {
			t.Fatal("receipt omitted registry identity", e)
		}
		other := d
		other.RegistryEnrollment = enrollmentFor(t, d.Context, d.Binding, d.RegistryEnrollment.Registry, 112, 113, 114)
		if e := other.RegistryEnrollment.Verify(d.Context, d.Binding); e != nil {
			t.Fatal("alternate quorum fixture invalid", e)
		}
		if other.Validate() == nil {
			t.Fatal("different sufficient quorum accepted under old enrollment pin")
		}
		other.Enrollment.RegistryEnrollmentID, _ = other.RegistryEnrollment.ID()
		if other.Validate() != nil || r.Verify(other) == nil {
			t.Fatal("new proof reused old receipt")
		}
		r.RegistryEnrollmentID = f.Hash("different-proof")
		if r.Verify(d) == nil {
			t.Fatal("mutated proof receipt accepted")
		}
	}
}
func TestAdmissionDeliveryEnrolledRejectsMissingCorruptAndDowngradedProofs(t *testing.T) {
	original := modelEnrolledDelivery(t, AdmissionDeliveryTarget)
	raw, _ := original.CanonicalBytes()
	for _, name := range []string{"missing", "weak", "corrupt", "descriptor", "wrong-pin", "packet-downgrade", "receiver-downgrade"} {
		t.Run(name, func(t *testing.T) {
			d, e := DecodeAdmissionDelivery(raw)
			if e != nil {
				t.Fatal(e)
			}
			switch name {
			case "missing":
				d.RegistryEnrollment = EnrollmentBinding{}
			case "weak":
				d.RegistryEnrollment = enrollmentFor(t, d.Context, d.Binding, d.RegistryEnrollment.Registry, 111, 112)
			case "corrupt":
				q, _ := wire.DecodeCertificate(d.RegistryEnrollment.Certificate)
				q.Votes[0].Signature[0] ^= 1
				d.RegistryEnrollment.Certificate, _ = q.CanonicalBytes()
			case "descriptor":
				d.RegistryEnrollment.Registry.MaximumOperations++
			case "wrong-pin":
				d.Enrollment.RegistryEnrollmentID = f.Hash("wrong-proof")
			case "packet-downgrade":
				d.Version = Version2
			case "receiver-downgrade":
				d.Enrollment.Version = Version2
			}
			// Re-pin malformed cryptographic proofs to ensure hash checking is not the only gate.
			if name == "weak" || name == "corrupt" || name == "descriptor" {
				d.Enrollment.RegistryEnrollmentID, _ = d.RegistryEnrollment.ID()
			}
			if d.Validate() == nil {
				t.Fatal("invalid proof envelope accepted")
			}
		})
	}
	old := modelAdmissionDelivery(t, AdmissionDeliveryTarget)
	old.RegistryEnrollment = original.RegistryEnrollment
	if old.Validate() == nil {
		t.Fatal("legacy packet silently ignored profile4 proof")
	}
	for _, decode := range []struct {
		raw []byte
		fn  func([]byte) error
	}{
		{raw, func(b []byte) error { _, e := DecodeAdmissionDelivery(b); return e }},
	} {
		for _, bad := range [][]byte{decode.raw[:len(decode.raw)-1], append(append([]byte{}, decode.raw...), 0)} {
			if decode.fn(bad) == nil {
				t.Fatal("malformed packet accepted")
			}
		}
	}
}
func TestAdmissionDeliveryEnrolledStoresKeepOriginalProofAndRequireExplicitOwners(t *testing.T) {
	z := newDeliveryNetworkFixtureProfile(t, true)
	if _, e := CreateAdmissionInbox(filepath.Join(z.x.root, "legacy"), z.x.c, z.x.pin, z.enrollment.BindingID, AdmissionDeliveryTarget, z.x.s, z.enrollment.RecipientPeerID); e == nil {
		t.Fatal("legacy enrollment adopted profile4")
	}
	if _, e := OpenAdmissionInbox(z.path, z.x.c, z.x.pin, z.x.s, z.enrollment, f.Key(14)); e == nil {
		t.Fatal("legacy open adopted profile4")
	}
	i := z.open(t)
	r, e := i.Receive(t.Context(), z.delivery)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := i.Receive(t.Context(), z.delivery); e != nil {
		t.Fatal(e)
	}
	state, e := i.decision.State()
	if e != nil || state.Sequence != 0 {
		t.Fatal("delivery appended source", e)
	}
	received, e := i.Delivery()
	if e != nil {
		t.Fatal(e)
	}
	if e := received.RegistryEnrollment.Verify(z.x.c, received.Binding); e != nil {
		t.Fatal(e)
	}
	_ = i.Close()
	z.noEffect(t)
	if e := CreateEnrolledTarget(z.x.targetPath, z.x.c, z.x.pin, z.x.s, received.Binding, received.RegistryEnrollment); e != nil {
		t.Fatal(e)
	}
	target, e := OpenEnrolledTarget(z.x.targetPath, z.x.c, z.x.pin, z.x.s, received.Binding, received.RegistryEnrollment, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	_ = target.Close()
	i = z.open(t)
	cold, e := i.ReadReceipt()
	if e != nil || cold != r {
		t.Fatal("cold proof receipt changed", e)
	}
}
func TestAdmissionDeliveryEnrolledUnknownWritesNeedExactColdRetry(t *testing.T) {
	for _, stage := range []string{"delivery-before-sync", "delivery-durable", "receipt-before-sync", "receipt-durable"} {
		t.Run(stage, func(t *testing.T) {
			z := newDeliveryNetworkFixtureProfile(t, true)
			i := z.open(t)
			i.s.hook = func(at string) error {
				if at == stage {
					return errors.New("injected delivery persistence failure")
				}
				return nil
			}
			if _, e := i.Receive(t.Context(), z.delivery); e == nil {
				t.Fatal("injected failure missing")
			}
			if e := i.Check(); !errors.Is(e, ErrUncertain) {
				t.Fatal("uncertain inbox remained usable", e)
			}
			_ = i.Close()
			i = z.open(t)
			other := z.delivery
			other.RegistryEnrollment = enrollmentFor(t, other.Context, other.Binding, other.RegistryEnrollment.Registry, 112, 113, 114)
			other.Enrollment.RegistryEnrollmentID, _ = other.RegistryEnrollment.ID()
			if _, e := i.Receive(t.Context(), other); e == nil {
				t.Fatal("different full proof resolved old attempt")
			}
			r, e := i.Receive(t.Context(), z.delivery)
			if e != nil || r.Verify(z.delivery) != nil {
				t.Fatal("exact cold retry failed", e)
			}
			_ = i.Close()
			z.noEffect(t)
		})
	}
}
func TestAdmissionDeliveryEnrolledQUICLostReplyColdRetry(t *testing.T) {
	runDeliveryLostReply(t, newDeliveryNetworkFixtureProfile(t, true))
}
func TestAdmissionDeliveryEnrolledQUICRefusesCrossProtocolAndMalformedFrames(t *testing.T) {
	runDeliveryInvalidTraffic(t, newDeliveryNetworkFixtureProfile(t, true))
}
func TestAdmissionDeliveryEnrolledCanonicalVectors(t *testing.T) {
	d := modelEnrolledDelivery(t, AdmissionDeliveryTarget)
	e, _ := d.Enrollment.ID()
	id, _ := d.ID()
	r, err := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(14))
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := r.ID()
	expected := map[string]string{"receiver": "1b102315d4d9e3753a0b4c3770cd68946d94ee84feb1d4ece0aee1501aff5d2a", "delivery": "fe76e5c49f157d8b1a4de96f02b30ff0100f23f0d9d0a374d15f77c6d3de1d6c", "receipt": "1835aee018ae9a53f0a8b66318cbddd924083671db7d55b5c1bcee7a00d72d89"}
	for name, h := range map[string]types.Hash{"receiver": e, "delivery": id, "receipt": rid} {
		if want, ok := expected[name]; ok {
			if h.String() != want {
				t.Fatal(name, h, want)
			}
		} else {
			t.Log(name, h)
		}
	}
}
func FuzzEnrolledDeliveryPublicPackets(fz *testing.F) {
	d := modelEnrolledDelivery(fz, AdmissionDeliveryTarget)
	raw, _ := d.CanonicalBytes()
	en, _ := d.Enrollment.CanonicalBytes()
	r, _ := (AdmissionDeliveryReceipt{}).Sign(d, f.Key(14))
	ack, _ := r.CanonicalBytes()
	fz.Add(byte(0), raw)
	fz.Add(byte(1), en)
	fz.Add(byte(2), ack)
	fz.Add(byte(0), []byte("OMCVDLV4"))
	fz.Fuzz(func(t *testing.T, kind byte, raw []byte) {
		switch kind % 3 {
		case 0:
			if x, e := DecodeAdmissionDelivery(raw); e == nil {
				b, e := x.CanonicalBytes()
				if e != nil || !bytes.Equal(raw, b) {
					t.Fatal("delivery round trip")
				}
			}
		case 1:
			if x, e := DecodeAdmissionDeliveryEnrollment(raw); e == nil {
				b, e := x.CanonicalBytes()
				if e != nil || !bytes.Equal(raw, b) {
					t.Fatal("receiver round trip")
				}
			}
		case 2:
			if x, e := DecodeAdmissionDeliveryReceipt(raw); e == nil {
				b, e := x.CanonicalBytes()
				if e != nil || !bytes.Equal(raw, b) {
					t.Fatal("receipt round trip")
				}
			}
		}
	})
}

func TestAdmissionDeliveryEnrolledWireRequiresWholeReceipt(t *testing.T) {
	runDeliveryWholeReceipt(t, newDeliveryNetworkFixtureProfile(t, true))
}
func TestAdmissionDeliveryEnrolledLegacyStoreAndServiceAPIsRefuse(t *testing.T) {
	z := newDeliveryNetworkFixtureProfile(t, true)
	path := filepath.Join(z.x.root, "legacy-outbox")
	route := admissionDeliveryTestRoute(t, 15, "40123")
	if e := CreateAdmissionOutbox(path, z.delivery, route); e == nil {
		t.Fatal("legacy outbox accepted profile4")
	}
	if _, e := os.Stat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("legacy refusal created directory", e)
	}
	o := z.outbox(t, filepath.Join(z.x.root, "new-outbox"), route, true)
	if x, e := OpenAdmissionOutbox(o.s.path, z.delivery, route); e == nil {
		_ = x.Close()
		t.Fatal("legacy open adopted profile4")
	}
	if _, e := DeliverAdmission(t.Context(), nil, o, time.Second); e == nil {
		t.Fatal("legacy sender adopted profile4")
	}
	i := z.open(t)
	if s, e := StartAdmissionDelivery(t.Context(), i, f.Key(15), libp2ptransport.DefaultConfig(), time.Second); e == nil {
		_ = s.Close()
		t.Fatal("legacy service adopted profile4")
	}
	_ = i.Close()
	_ = o.Close()
	z.noEffect(t)
}

func TestAdmissionDeliveryEnrolledRejectsClientTransportRegistryKeyReuse(t *testing.T) {
	for _, seed := range []byte{110, 111, 112, 113, 114} {
		t.Run("registry-key-"+types.Hash(f.Public(seed)).String()[:8], func(t *testing.T) {
			c, g := enrolledContext(t)
			c.Plan.ClientTransportPublicKey = f.Public(seed)
			c.Plan.AuditSignature, c.Plan.ServeSignature, c.Plan.AuthoritySignature = [64]byte{}, [64]byte{}, [64]byte{}
			for _, role := range []string{"audit", "serve", "authority"} {
				key := byte(4)
				if role == "authority" {
					key = 1
				}
				var e error
				c.Plan, e = c.Plan.Sign(role, f.Key(key))
				if e != nil {
					t.Fatal(e)
				}
			}
			if e := c.Validate(); e != nil {
				t.Fatal("job fixture must otherwise be valid", e)
			}
			ad := requiredRuntimeBinding(t, c)
			proof := enrollmentFor(t, c, ad, g)
			if e := proof.Verify(c, ad); !errors.Is(e, ErrEnrollmentRequired) {
				t.Fatal("job client reused a registry signing key", e)
			}
		})
	}
}
