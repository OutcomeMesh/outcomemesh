package servicewire

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// This is the public scheduled-Prune effect from the store's fixed v0 fixture.
// Its protected operation is independently enrolled below; no private runtime
// paths, deployment keys, or live storage handles belong in the wire fixture.
//
//go:embed testdata/scheduled_effect.b64
var effectFixture string

type fixture struct {
	d Descriptor
	q Request
	c Challenge
	r Response
	s Response
}

func fixtureFor(t testing.TB) fixture {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(effectFixture))
	if err != nil {
		t.Fatal(err)
	}
	effect, err := workchain.DecodeCanonicalPruneEffect(raw)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := prunefence.ServiceEnrollment{AssignmentID: effect.Operation.AssignmentID,
		ScheduleID: effect.Operation.ScheduleID, StorageID: effect.Operation.StorageID,
		StoragePairID: fencetest.Hash("storage-pair"), Service: fencetest.Public(90),
		Issuer: fencetest.Public(91), Guard: fencetest.Public(92)}
	enrollment, err = enrollment.Sign(fencetest.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	effect.Operation.ServiceEnrollmentID, err = enrollment.ID()
	if err != nil {
		t.Fatal(err)
	}
	op, err := effect.Operation.FenceOperationID()
	if err != nil {
		t.Fatal(err)
	}
	scope := fencetest.Scope()
	d := Descriptor{RootID: fencetest.Hash("root"), ScopeID: fencetest.Hash("scope"),
		ReviewID: fencetest.Hash("review"), ConfigID: fencetest.Hash("config"),
		Policy: prunefence.Policy{Service: &enrollment, Owner: scope.Owner, Controller: scope.Controller,
			Guard: fencetest.Public(80), Threshold: scope.Threshold, Witnesses: scope.Witnesses},
		Binding: prunefence.Binding{AssignmentID: enrollment.AssignmentID, RequestID: fencetest.Hash("prune-request"),
			OperationID: op, InventoryID: fencetest.Hash("inventory"), ExecutorBindingID: fencetest.Hash("executor"), StoragePairID: enrollment.StoragePairID},
		Transport: fencetest.Public(93), OwnerUID: 101, ParticipantUID: 102}
	d, err = d.Sign(fencetest.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	did, _ := d.ID()
	q, err := (Request{DescriptorID: did, Nonce: [32]byte(fencetest.Hash("nonce"))}).Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	qid, _ := q.ID()
	before, _ := q.IntentPosition()
	candidate := signCandidate(t, prunefence.Candidate{Policy: d.Policy, Binding: d.Binding, Session: fencetest.Public(250)})
	c, err := (Challenge{DescriptorID: did, RequestID: qid, Before: before, Candidate: candidate}).Sign(d, q, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	claim := claimFor(t, candidate)
	result := resultFor(t, claim, effect)
	r, err := (Response{DescriptorID: did, RequestID: qid, Effect: effect, Result: &result}).Sign(d, q, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	settlement := settlementFor(t, claim, effect)
	s, err := (Response{DescriptorID: did, RequestID: qid, Effect: effect, Settlement: &settlement}).Sign(d, q, fencetest.Key(90))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{d, q, c, r, s}
}

// Independent preimages make deterministic fixtures without constructing a live
// execution capability. These keys are public test constants only.
func signCandidate(t testing.TB, c prunefence.Candidate) prunefence.Candidate {
	t.Helper()
	p, err := c.Policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	e := codec.NewEncoder(1536)
	e.Fixed([]byte("OMPRFC00"))
	e.U16(1)
	e.BytesField(p)
	for _, h := range []types.Hash{c.Binding.RequestID, c.Binding.AssignmentID, c.Binding.OperationID, c.Binding.InventoryID, c.Binding.ExecutorBindingID, c.Binding.StoragePairID} {
		e.Fixed(h[:])
	}
	e.Fixed(c.Session[:])
	h := types.DomainHash("OMESH/prune-fence/service-session/sign/v0", e.Bytes())
	copy(c.ServiceSignature[:], ed25519.Sign(fencetest.Key(90), h[:]))
	if _, err := c.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	return c
}
func claimFor(t testing.TB, c prunefence.Candidate) prunefence.Claim {
	t.Helper()
	_, command, err := c.Draft()
	if err != nil {
		t.Fatal(err)
	}
	command, err = command.Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	claim := prunefence.Claim{Candidate: c, Certificate: guardedCertificate(t, command)}
	if err := claim.Verify(); err != nil {
		t.Fatal(err)
	}
	return claim
}
func resultFor(t testing.TB, claim prunefence.Claim, effect workchain.CanonicalPruneEffect) prunefence.Result {
	t.Helper()
	c := claim.Candidate
	raw, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	e := c.Policy.Service
	proof := prunefence.ServiceConsumption{Nonce: [32]byte(fencetest.Hash("consume-challenge"))}
	q := guardwire.Request{Kind: guardwire.Gateway, Subject: e.Service,
		Namespace: types.DomainHash("OMESH/prune-fence/service/namespace/v0", e.StorageID[:], e.StoragePairID[:], c.Binding.RequestID[:]),
		Choice:    types.DomainHash("OMESH/prune-fence/service/consume/v0", raw, proof.Nonce[:])}
	digest, err := q.SealDigest()
	if err != nil {
		t.Fatal(err)
	}
	copy(proof.Seal[:], ed25519.Sign(fencetest.Key(92), digest[:]))
	id, err := effect.ID()
	if err != nil {
		t.Fatal(err)
	}
	r := prunefence.Result{Claim: claim, EffectID: id, ServiceConsumption: &proof}
	cid, _ := claim.Certificate.Command.ID()
	h := types.DomainHash("OMESH/prune-fence/result/sign/v1", raw, cid[:], proof.Nonce[:], proof.Seal[:], id[:])
	copy(r.Signature[:], ed25519.Sign(fencetest.Key(250), h[:]))
	if _, err := r.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	return r
}
func settlementFor(t testing.TB, claim prunefence.Claim, effect workchain.CanonicalPruneEffect) prunefence.Settlement {
	t.Helper()
	id, err := effect.ID()
	if err != nil {
		t.Fatal(err)
	}
	p := prunefence.SettlementProposal{Claim: claim, EffectID: id}
	for i, role := range []string{"owner", "controller"} {
		review, err := p.ReviewID(role)
		if err != nil {
			t.Fatal(err)
		}
		p, err = p.Sign(role, review, fencetest.Key(byte(i+1)))
		if err != nil {
			t.Fatal(err)
		}
	}
	_, command, err := p.Draft()
	if err != nil {
		t.Fatal(err)
	}
	command, err = command.Sign(fencetest.Key(2))
	if err != nil {
		t.Fatal(err)
	}
	s := prunefence.Settlement{Proposal: p, Certificate: guardedCertificate(t, command)}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
	return s
}

func guardedCertificate(t testing.TB, command custodyfence.Command) custodyfence.Certificate {
	t.Helper()
	certificate := fencetest.Certificate(command, 70, 71, 72)
	for i := range certificate.Votes {
		v := &certificate.Votes[i]
		h, err := custodyfence.VoteGuardRequest(command, v.Witness).SealDigest()
		if err != nil {
			t.Fatal(err)
		}
		copy(v.GuardSeal[:], ed25519.Sign(fencetest.Key(80), h[:]))
	}
	return certificate
}

func TestWireArtifactsRoundTripAndFixedVectors(t *testing.T) {
	f := fixtureFor(t)
	if err := f.q.Authorize(f.d); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Verify(f.d, f.q); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Response{f.r, f.s} {
		if err := r.Verify(f.d, f.q); err != nil {
			t.Fatal(err)
		}
	}
	artifacts := wireArtifacts(f)
	want := []struct {
		size int
		id   string
	}{
		{970, "f977bba8e6fd67aece1b0124b6faa38d0d0f166bc603fb6a73c7e5b019bed1c4"},
		{206, "6d03850733d1a2348cc0b5d75fbbbd1797e9d17ca99cfb3f906e782f3375ffa5"},
		{1010, "f213305b6108a1ebadeb905647256eba92b66659c3e70fe83f712d45339b3d46"},
		{2649, "f75f784794ebb750d66bac8e04c18fb1a7462dd49de7f0eb78b954ee17007d7d"},
		{3459, "d94c228d21dda0b5388b2aa1e498cd733c5455761b695b6f04349876ca667a26"},
	}
	for i, a := range artifacts {
		t.Run(a.name, func(t *testing.T) {
			b, err := a.encode()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := a.decode(b)
			if err != nil || !bytes.Equal(b, decoded) {
				t.Fatalf("round trip: %v", err)
			}
			id, err := a.id()
			if err != nil {
				t.Fatal(err)
			}
			if len(b) != want[i].size || id.String() != want[i].id {
				t.Fatalf("changed v0 encoding: %s %d %s", a.name, len(b), id)
			}
		})
	}
	initial := Position{}
	intent, _ := f.q.IntentPosition()
	confirmed, _ := f.r.Position()
	if !initial.Valid() || !intent.Valid() || !confirmed.Valid() || intent.Sequence != 1 || confirmed.Sequence != 2 || intent.Head == confirmed.Head {
		t.Fatal("invalid lifecycle positions")
	}
	for _, p := range []Position{{1, types.Hash{}}, {2, types.Hash{}}, {0, intent.Head}, {3, confirmed.Head}} {
		if p.Valid() {
			t.Fatalf("accepted invalid position: %+v", p)
		}
	}
	review, err := f.d.SigningReviewID()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := f.d
	unsigned.Signature = [64]byte{}
	if other, _ := unsigned.SigningReviewID(); other != review {
		t.Fatal("signature altered offline review")
	}
	unsigned.ConfigID = fencetest.Hash("different config")
	if other, _ := unsigned.SigningReviewID(); other == review {
		t.Fatal("configuration substitution retained review ID")
	}
}

type wireArtifact struct {
	name   string
	encode func() ([]byte, error)
	decode func([]byte) ([]byte, error)
	id     func() (types.Hash, error)
}

func wireArtifacts(f fixture) []wireArtifact {
	return []wireArtifact{
		{"descriptor", f.d.CanonicalBytes, func(b []byte) ([]byte, error) {
			v, e := DecodeDescriptor(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, f.d.ID},
		{"request", f.q.CanonicalBytes, func(b []byte) ([]byte, error) {
			v, e := DecodeRequest(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, f.q.ID},
		{"challenge", f.c.CanonicalBytes, func(b []byte) ([]byte, error) {
			v, e := DecodeChallenge(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, f.c.ID},
		{"result-response", f.r.CanonicalBytes, func(b []byte) ([]byte, error) {
			v, e := DecodeResponse(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, f.r.ID},
		{"settlement-response", f.s.CanonicalBytes, func(b []byte) ([]byte, error) {
			v, e := DecodeResponse(b)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		}, f.s.ID},
	}
}

func TestWireStrictCanonicalDecoding(t *testing.T) {
	for _, a := range wireArtifacts(fixtureFor(t)) {
		t.Run(a.name, func(t *testing.T) {
			raw, _ := a.encode()
			for _, n := range []int{0, 1, 8, 9, 10, 42, len(raw) / 2, len(raw) - 65, len(raw) - 1} {
				if _, err := a.decode(raw[:n]); err == nil {
					t.Fatalf("accepted truncation at %d", n)
				}
			}
			for _, off := range []int{0, 8, 9, 10, 42, len(raw) - 1} {
				b := bytes.Clone(raw)
				b[off] ^= 1
				if _, err := a.decode(b); err == nil {
					t.Fatalf("accepted tamper at %d", off)
				}
			}
			if _, err := a.decode(append(bytes.Clone(raw), 0)); err == nil {
				t.Fatal("accepted trailing bytes")
			}
			if _, err := a.decode(make([]byte, MaximumResponseBytes+1)); err == nil {
				t.Fatal("accepted excessive input")
			}
		})
	}
}

func TestDescriptorRejectsRoleAndPlacementSubstitution(t *testing.T) {
	f := fixtureFor(t)
	mutations := map[string]func(*Descriptor){
		"nil service":      func(d *Descriptor) { d.Policy.Service = nil },
		"zero root":        func(d *Descriptor) { d.RootID = types.Hash{} },
		"zero review":      func(d *Descriptor) { d.ReviewID = types.Hash{} },
		"zero scope":       func(d *Descriptor) { d.ScopeID = types.Hash{} },
		"zero config":      func(d *Descriptor) { d.ConfigID = types.Hash{} },
		"root participant": func(d *Descriptor) { d.ParticipantUID = 0 },
		"same uid":         func(d *Descriptor) { d.ParticipantUID = d.OwnerUID },
		"wrong assignment": func(d *Descriptor) { d.Binding.AssignmentID = fencetest.Hash("other") },
		"wrong pair":       func(d *Descriptor) { d.Binding.StoragePairID = fencetest.Hash("other") },
		"empty transport":  func(d *Descriptor) { d.Transport = [32]byte{} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			d := f.d
			mutate(&d)
			if _, err := d.Sign(fencetest.Key(91)); err == nil {
				t.Fatal("signed invalid descriptor")
			}
		})
	}
	roles := append([][32]byte{f.d.Policy.Owner, f.d.Policy.Controller, f.d.Policy.Guard, f.d.Policy.Service.Service, f.d.Policy.Service.Issuer, f.d.Policy.Service.Guard}, f.d.Policy.Witnesses...)
	for _, key := range roles {
		d := f.d
		d.Transport = key
		if _, err := d.Sign(fencetest.Key(91)); err == nil {
			t.Fatal("accepted shared transport role")
		}
	}
	if _, err := f.d.Sign(fencetest.Key(90)); err == nil {
		t.Fatal("service signed issuer descriptor")
	}
	bad := fencetest.Key(91)
	bad[0] ^= 1
	if _, err := f.d.Sign(bad); err == nil {
		t.Fatal("accepted malformed private key")
	}
	d := f.d
	d.OwnerUID = 0
	if _, err := d.Sign(fencetest.Key(91)); err != nil {
		t.Fatalf("owner UID zero is permitted by the wire contract: %v", err)
	}
}

func TestRequestsRejectStaleCursorAndWrongConsumer(t *testing.T) {
	f := fixtureFor(t)
	for _, p := range []Position{{1, fencetest.Hash("intent")}, {2, fencetest.Hash("result")}, {3, fencetest.Hash("unknown")}, {0, fencetest.Hash("nonzero")}} {
		q := f.q
		q.Before = p
		if _, err := q.Sign(fencetest.Key(1)); err == nil {
			t.Fatal("signed noninitial request")
		}
	}
	q := f.q
	q.Nonce = [32]byte{}
	if _, err := q.Sign(fencetest.Key(1)); err == nil {
		t.Fatal("signed empty nonce")
	}
	q, err := f.q.Sign(fencetest.Key(2))
	if err != nil {
		t.Fatal(err)
	}
	if q.Authorize(f.d) == nil {
		t.Fatal("accepted controller as consumer")
	}
	q = f.q
	q.DescriptorID = fencetest.Hash("different descriptor")
	q, err = q.Sign(fencetest.Key(1))
	if err != nil {
		t.Fatal(err)
	}
	if q.Authorize(f.d) == nil {
		t.Fatal("accepted different descriptor")
	}
	if err := f.q.Authorize(f.d); err != nil {
		t.Fatal("exact request remains valid historical input", err)
	}
}

func TestChallengeRequiresFullCandidateAndContext(t *testing.T) {
	f := fixtureFor(t)
	for name, mutate := range map[string]func(*prunefence.Candidate){
		"inventory":  func(c *prunefence.Candidate) { c.Binding.InventoryID = fencetest.Hash("other") },
		"executor":   func(c *prunefence.Candidate) { c.Binding.ExecutorBindingID = fencetest.Hash("other") },
		"operation":  func(c *prunefence.Candidate) { c.Binding.OperationID = fencetest.Hash("other") },
		"request":    func(c *prunefence.Candidate) { c.Binding.RequestID = fencetest.Hash("other") },
		"controller": func(c *prunefence.Candidate) { c.Policy.Controller = fencetest.Public(3) },
		"guard":      func(c *prunefence.Candidate) { c.Policy.Guard = fencetest.Public(81) },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.c
			mutate(&c.Candidate)
			c.Candidate = signCandidate(t, c.Candidate)
			body, err := c.body()
			if err != nil {
				t.Fatal(err)
			}
			c.Signature = sign("challenge/sign", body, fencetest.Key(90))
			if _, err = c.CanonicalBytes(); err != nil {
				t.Fatal(err)
			}
			if c.Verify(f.d, f.q) == nil {
				t.Fatal("accepted substituted candidate")
			}
		})
	}
	c := f.c
	c.RequestID = fencetest.Hash("other")
	c.Before.Head = c.RequestID
	if _, err := c.Sign(f.d, f.q, fencetest.Key(90)); err == nil {
		t.Fatal("signed wrong request")
	}
	if _, err := f.c.Sign(f.d, f.q, fencetest.Key(91)); err == nil {
		t.Fatal("issuer signed service challenge")
	}
	c = f.c
	c.Candidate.ServiceSignature[0] ^= 1
	if _, err := c.CanonicalBytes(); err == nil {
		t.Fatal("accepted missing service attestation")
	}
}

func TestResponseRequiresExactEffectAndOneCompleteProof(t *testing.T) {
	f := fixtureFor(t)
	for _, original := range []Response{f.r, f.s} {
		r := original
		r.Result = nil
		r.Settlement = nil
		if _, err := r.CanonicalBytes(); err == nil {
			t.Fatal("accepted no proof")
		}
		r = original
		r.Result = f.r.Result
		r.Settlement = f.s.Settlement
		if _, err := r.CanonicalBytes(); err == nil {
			t.Fatal("accepted ambiguous proof")
		}
		r = original
		r.Effect.VerifiedAt++
		if _, err := r.CanonicalBytes(); err == nil {
			t.Fatal("accepted different effect")
		}
		r = original
		r.RequestID = fencetest.Hash("other")
		if _, err := r.Sign(f.d, f.q, fencetest.Key(90)); err == nil {
			t.Fatal("signed different wire request")
		}
		if _, err := original.Sign(f.d, f.q, fencetest.Key(91)); err == nil {
			t.Fatal("issuer signed service response")
		}
	}
	mutations := map[string]func(*workchain.CanonicalPruneEffect){
		"enrollment": func(e *workchain.CanonicalPruneEffect) { e.Operation.ServiceEnrollmentID = fencetest.Hash("other") },
		"storage":    func(e *workchain.CanonicalPruneEffect) { e.Operation.StorageID = fencetest.Hash("other") },
		"schedule":   func(e *workchain.CanonicalPruneEffect) { e.Operation.ScheduleID = fencetest.Hash("other") },
		"assignment": func(e *workchain.CanonicalPruneEffect) { e.Operation.AssignmentID = fencetest.Hash("other") },
		"operation":  func(e *workchain.CanonicalPruneEffect) { e.Operation.TicketID = fencetest.Hash("other") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := f.r.Effect
			mutate(&e)
			// The nested proof is honestly signed for the substituted effect. The
			// wire binding must reject it even though all proof signatures verify.
			result := resultFor(t, f.r.Result.Claim, e)
			r := f.r
			r.Effect = e
			r.Result = &result
			if _, err := r.CanonicalBytes(); err == nil {
				t.Fatal("accepted substituted effect with valid result")
			}
			settlement := settlementFor(t, f.r.Result.Claim, e)
			r.Result = nil
			r.Settlement = &settlement
			if _, err := r.CanonicalBytes(); err == nil {
				t.Fatal("accepted substituted effect with valid settlement")
			}
		})
	}
	r := f.r
	c := r.Result.Claim.Candidate
	c.Binding.InventoryID = fencetest.Hash("other")
	c = signCandidate(t, c)
	result := resultFor(t, claimFor(t, c), r.Effect)
	r.Result = &result
	b, err := r.body()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = sign("response/sign", b, fencetest.Key(90))
	if _, err := r.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	if r.Verify(f.d, f.q) == nil {
		t.Fatal("accepted different complete candidate binding")
	}
}

func TestFramingBoundsShortIOAndEOF(t *testing.T) {
	f := fixtureFor(t)
	request, _ := f.q.CanonicalBytes()
	challenge, _ := f.c.CanonicalBytes()
	response, _ := f.s.CanonicalBytes()
	approval, _ := f.r.Result.Claim.Certificate.Command.CanonicalBytes()
	for _, item := range []struct {
		kind uint8
		body []byte
	}{{RequestFrame, request}, {ChallengeFrame, challenge}, {ApprovalFrame, approval}, {ResponseFrame, response}} {
		if frameLimit(item.kind) > MaximumResponseBytes {
			t.Fatal("frame exceeds transport ceiling")
		}
		var b bytes.Buffer
		if err := WriteFrame(shortWriter{&b}, item.kind, item.body); err != nil {
			t.Fatal(err)
		}
		kind, body, err := ReadFrame(shortReader{&b})
		if err != nil || kind != item.kind || !bytes.Equal(body, item.body) {
			t.Fatalf("roundtrip kind %d: %v", item.kind, err)
		}
		if err := RequireEOF(&b); err != nil {
			t.Fatal(err)
		}
		for _, n := range []int{0, frameLimit(item.kind) + 1} {
			var h [5]byte
			h[0] = item.kind
			binary.BigEndian.PutUint32(h[1:], uint32(n))
			if _, _, err := ReadFrame(bytes.NewReader(h[:])); err == nil {
				t.Fatalf("accepted size %d", n)
			}
		}
	}
	if err := WriteFrame(io.Discard, 0, request); err == nil {
		t.Fatal("unknown outgoing kind")
	}
	if _, _, err := ReadFrame(bytes.NewReader([]byte{255, 0, 0, 0, 1, 0})); err == nil {
		t.Fatal("unknown incoming kind")
	}
	if _, _, err := ReadFrame(bytes.NewReader([]byte{RequestFrame, 0, 0, 0, 2, 0})); err == nil {
		t.Fatal("short frame payload")
	}
	if err := WriteFrame(zeroWriter{}, RequestFrame, request); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := RequireEOF(bytes.NewReader([]byte{0})); err == nil {
		t.Fatal("accepted trailing input")
	}
	if err := RequireEOF(noProgressReader{}); err == nil {
		t.Fatal("accepted missing EOF")
	}
}

type shortWriter struct{ io.Writer }

func (w shortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Writer.Write(p)
}

type shortReader struct{ io.Reader }

func (r shortReader) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return r.Reader.Read(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

func FuzzWireCanonical(f *testing.F) {
	artifacts := wireArtifacts(fixtureFor(f))
	for i, a := range artifacts {
		b, err := a.encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(i), b)
	}
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, kind uint8, raw []byte) {
		a := artifacts[int(kind)%len(artifacts)]
		if out, err := a.decode(raw); err == nil && !bytes.Equal(raw, out) {
			t.Fatal("accepted noncanonical artifact")
		}
	})
}
func FuzzWireFrames(f *testing.F) {
	fixture := fixtureFor(f)
	b, _ := fixture.q.CanonicalBytes()
	var frame bytes.Buffer
	if err := WriteFrame(&frame, RequestFrame, b); err != nil {
		f.Fatal(err)
	}
	f.Add(frame.Bytes())
	f.Add([]byte{255, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, raw []byte) {
		reader := bytes.NewReader(raw)
		kind, payload, err := ReadFrame(reader)
		if err != nil {
			return
		}
		if len(payload) == 0 || len(payload) > MaximumResponseBytes {
			t.Fatal("accepted unbounded payload")
		}
		var encoded bytes.Buffer
		if err := WriteFrame(&encoded, kind, payload); err != nil {
			t.Fatal(err)
		}
		consumed := len(raw) - reader.Len()
		if !bytes.Equal(encoded.Bytes(), raw[:consumed]) {
			t.Fatal("accepted noncanonical frame")
		}
	})
}
