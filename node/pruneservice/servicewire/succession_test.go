package servicewire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

const successorFixtureKey = 94
const replacementAuthorityFixtureKey = 95

func successorWireFixture(t testing.TB, original fixture) fixture {
	t.Helper()
	d, q := original.d, original.q
	c := original.c
	replacement, err := (guardwire.Replacement{
		GuardID: fencetest.Hash("guard-identity"), Subject: d.Policy.Service.Service,
		Successor: fencetest.Public(successorFixtureKey), Authority: fencetest.Public(replacementAuthorityFixtureKey),
		RevocationID: fencetest.Hash("revoked"), EvidenceID: fencetest.Hash("retained-accounting"),
		Before: guardwire.Position{Sequence: 1, Head: fencetest.Hash("guard-head")},
	}).Accept(fencetest.Key(successorFixtureKey))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err = replacement.Authorize(fencetest.Key(replacementAuthorityFixtureKey))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := (guardwire.ReplacementReceipt{Request: replacement, Guard: d.Policy.Service.Guard}).Sign(fencetest.Key(92))
	if err != nil {
		t.Fatal(err)
	}
	approval, err := (prunefence.ServiceSuccession{Replacement: receipt}).Sign(d.Policy, d.Binding, fencetest.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	// Fixed synthetic session and independently assembled V2 preimage make
	// stable vectors for both forms of historical response.
	c.Candidate.Succession = &approval
	p, err := d.Policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	successor, err := approval.CanonicalBytes(d.Policy, d.Binding)
	if err != nil {
		t.Fatal(err)
	}
	e := codec.NewEncoder(prunefence.MaximumCandidateBytes)
	e.Fixed([]byte("OMPRFC00"))
	e.U16(2)
	e.BytesField(p)
	for _, h := range []types.Hash{d.Binding.RequestID, d.Binding.AssignmentID, d.Binding.OperationID, d.Binding.InventoryID, d.Binding.ExecutorBindingID, d.Binding.StoragePairID} {
		e.Fixed(h[:])
	}
	e.Fixed(c.Candidate.Session[:])
	e.Fixed(successor)
	hash := types.DomainHash("OMESH/prune-fence/service-session/sign/v2", e.Bytes())
	signer := fencetest.Key(successorFixtureKey)
	copy(c.Candidate.ServiceSignature[:], ed25519.Sign(signer, hash[:]))
	c, err = c.Sign(d, q, signer)
	if err != nil {
		t.Fatal(err)
	}
	claim := claimFor(t, c.Candidate)
	effect := original.r.Effect
	result := resultFor(t, claim, effect)
	settled := settlementFor(t, claim, effect)
	r := Response{DescriptorID: c.DescriptorID, RequestID: c.RequestID, Effect: effect, Result: &result}
	r, err = r.Sign(d, q, signer)
	if err != nil {
		t.Fatal(err)
	}
	s := Response{DescriptorID: c.DescriptorID, RequestID: c.RequestID, Effect: effect, Settlement: &settled}
	s, err = s.Sign(d, q, signer)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{d: d, q: q, c: c, r: r, s: s}
}

func TestSuccessorWireRoundTripAndFixedVectors(t *testing.T) {
	f := successorWireFixture(t, fixtureFor(t))
	if err := f.c.Verify(f.d, f.q); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Response{f.r, f.s} {
		if err := r.Verify(f.d, f.q); err != nil {
			t.Fatal(err)
		}
		id, err := r.ID()
		cursor, cursorErr := r.Position()
		if err != nil || cursorErr != nil || cursor != (Position{Sequence: 2, Head: id}) {
			t.Fatal("incorrect confirmed cursor", err, cursorErr)
		}
	}
	vectors := []struct {
		size int
		id   string
	}{
		{1552, "7ea776794e09840865dd9298ad5f3e3923b468751b8e462a2552abf10b96b170"},
		{3191, "9ccf40208ddcd0d8d2dba3d8e694f3cff62a099b57d65c2cd25c105c12bb3dd2"},
		{4001, "a582ca62992d894e8f0700760f8caff9e9fa5e22b4b0467f36a5281bc1b11162"},
	}
	for i, a := range wireArtifacts(f)[2:] {
		t.Run(a.name, func(t *testing.T) {
			raw, err := a.encode()
			if err != nil || binary.BigEndian.Uint16(raw[8:10]) != 1 {
				t.Fatal("wire version", err)
			}
			decoded, err := a.decode(raw)
			if err != nil || !bytes.Equal(decoded, raw) {
				t.Fatal("successor round trip", err)
			}
			if id, err := a.id(); err != nil || id.String() != vectors[i].id || len(raw) != vectors[i].size {
				t.Errorf("changed successor vector %d %s (%v)", len(raw), id, err)
			}
			for _, version := range []uint16{0, 2} {
				b := bytes.Clone(raw)
				binary.BigEndian.PutUint16(b[8:10], version)
				if _, err = a.decode(b); err == nil {
					t.Fatal("accepted a different outer version", version)
				}
			}
			if _, err = a.decode(raw[:len(raw)-1]); err == nil {
				t.Fatal("accepted truncated successor signature")
			}
		})
	}
}

func TestSuccessorWireRefusesBothCrossSignerDirections(t *testing.T) {
	original := fixtureFor(t)
	current := successorWireFixture(t, original)
	for _, f := range []fixture{original, current} {
		other := fencetest.Key(successorFixtureKey)
		if f.c.Candidate.Succession != nil {
			other = fencetest.Key(90)
		}
		if _, err := f.c.Sign(f.d, f.q, other); err == nil {
			t.Fatal("wrong signer accepted for challenge")
		}
		b, err := f.c.body()
		if err != nil {
			t.Fatal(err)
		}
		f.c.Signature = sign(envelopeLabel(f.c.Candidate, "challenge/sign"), b, other)
		if f.c.Verify(f.d, f.q) == nil {
			t.Fatal("cross-signed challenge verified")
		}
		for _, r := range []Response{f.r, f.s} {
			if _, err := r.Sign(f.d, f.q, other); err == nil {
				t.Fatal("wrong signer accepted for historical proof")
			}
			body, candidate, err := r.body()
			if err != nil {
				t.Fatal(err)
			}
			r.Signature = sign(envelopeLabel(candidate, "response/sign"), body, other)
			if r.Verify(f.d, f.q) == nil {
				t.Fatal("cross-signed historical proof verified")
			}
		}
	}
}

func TestSuccessorWireRejectsTransportRoleReuse(t *testing.T) {
	original := fixtureFor(t)
	f := successorWireFixture(t, original)
	for _, forbidden := range [][32]byte{f.c.Candidate.Session, fencetest.Public(successorFixtureKey), fencetest.Public(replacementAuthorityFixtureKey)} {
		d := f.d
		d.Transport = forbidden
		d, err := d.Sign(fencetest.Key(91))
		if err != nil {
			t.Fatal(err)
		}
		q := f.q
		q.DescriptorID, _ = d.ID()
		q, err = q.Sign(fencetest.Key(1))
		if err != nil {
			t.Fatal(err)
		}
		c := f.c
		c.DescriptorID = q.DescriptorID
		c.RequestID, _ = q.ID()
		c.Before, _ = q.IntentPosition()
		if _, err = c.Sign(d, q, fencetest.Key(successorFixtureKey)); err == nil {
			t.Fatal("signed a successor challenge with a shared transport role")
		}
		r := f.r
		r.DescriptorID, r.RequestID = c.DescriptorID, c.RequestID
		if _, err = r.Sign(d, q, fencetest.Key(successorFixtureKey)); err == nil {
			t.Fatal("signed a successor response with a shared transport role")
		}
	}
}
