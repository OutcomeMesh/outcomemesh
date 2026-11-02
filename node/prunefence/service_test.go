package prunefence_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	p "github.com/outcomemesh/outcomemesh/node/prunefence"
)

type serviceGuard struct {
	mu                         sync.Mutex
	choice                     *guardwire.Request
	seal                       [64]byte
	calls                      int
	revoked, loseReply, replay bool
}

func (g *serviceGuard) Choose(ctx context.Context, q guardwire.Request) ([64]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if ctx.Err() != nil {
		return [64]byte{}, ctx.Err()
	}
	if _, ok := ctx.Deadline(); !ok {
		return [64]byte{}, guardwire.ErrGuard
	}
	if g.replay {
		return g.seal, nil
	}
	if _, err := q.CanonicalBytes(); err != nil || g.revoked {
		return [64]byte{}, guardwire.ErrGuard
	}
	if g.choice != nil && *g.choice != q {
		return [64]byte{}, guardwire.ErrGuard
	}
	g.choice = &q
	h, _ := q.SealDigest()
	copy(g.seal[:], ed25519.Sign(f.Key(92), h[:]))
	if g.loseReply {
		return [64]byte{}, context.DeadlineExceeded
	}
	return g.seal, nil
}
func servicePolicy(t testing.TB) p.Policy {
	t.Helper()
	e, err := (p.ServiceEnrollment{AssignmentID: binding().AssignmentID, ScheduleID: f.Hash("schedule"), StorageID: f.Hash("storage-incarnation"), StoragePairID: binding().StoragePairID, Service: f.Public(90), Issuer: f.Public(91), Guard: f.Public(92)}).Sign(f.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	v := policy()
	v.Service = &e
	return v
}
func servicePermit(t testing.TB, policy p.Policy, guard guardwire.Chooser) (*p.Session, *p.Permit) {
	t.Helper()
	i, err := p.NewServiceIdentity(*policy.Service, f.Key(90), guard)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	s, err := i.NewSession(t.Context(), policy, binding())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	c, err := s.Candidate()
	if err != nil {
		t.Fatal(err)
	}
	permit, _, err := s.Authorize(claim(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return s, permit
}

func TestPruneServiceRequiresEnrollmentAndLiveConsumption(t *testing.T) {
	v := servicePolicy(t)
	if _, err := v.Scope(f.Hash("other assignment"), binding().RequestID); err == nil {
		t.Fatal("service policy moved to another assignment")
	}
	id, _ := v.Service.ID()
	g := new(serviceGuard)
	if _, err := p.NewSession(v, binding()); err == nil {
		t.Fatal("legacy constructor accepted service policy")
	}
	if _, err := p.NewServiceIdentity(*v.Service, f.Key(1), g); err == nil {
		t.Fatal("participant impersonated service")
	}
	s, permit := servicePermit(t, v, g)
	if err := permit.Consume(binding().OperationID, binding().StoragePairID); err == nil {
		t.Fatal("legacy consumption accepted protected session")
	}
	if err := permit.ConsumeProtected(binding().OperationID, binding().StoragePairID, f.Hash("other")); err == nil {
		t.Fatal("wrong enrollment")
	}
	if g.calls != 0 {
		t.Fatal("invalid operation reached guard")
	}
	c, _ := s.Candidate()
	c.Policy.Service.Service = f.Public(250)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if permit.ConsumeProtected(binding().OperationID, binding().StoragePairID, id) == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 || g.calls != 1 {
		t.Fatal("consumption was not singular", accepted.Load(), g.calls)
	}
	r, err := permit.Seal(f.Hash("effect"))
	if err != nil {
		t.Fatal("detached candidate changed session", err)
	}
	raw, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := p.DecodeResult(raw)
	if err != nil || decoded.ServiceConsumption == nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing", "nonce", "seal", "effect", "candidate"} {
		bad, _ := p.DecodeResult(raw)
		switch mode {
		case "missing":
			bad.ServiceConsumption = nil
		case "nonce":
			bad.ServiceConsumption.Nonce[0] ^= 1
		case "seal":
			bad.ServiceConsumption.Seal[0] ^= 1
		case "effect":
			bad.EffectID[0] ^= 1
		case "candidate":
			bad.Claim.Candidate.Binding.InventoryID[0] ^= 1
		}
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("substituted result", mode)
		}
	}
	_, copied := servicePermit(t, v, g)
	if err := copied.ConsumeProtected(binding().OperationID, binding().StoragePairID, id); err == nil {
		t.Fatal("copied service started a second effect")
	}
	g.replay = true
	_, replay := servicePermit(t, v, g)
	if err := replay.ConsumeProtected(binding().OperationID, binding().StoragePairID, id); err == nil {
		t.Fatal("cached seal granted fresh consumption")
	}
}

func TestPruneServiceRejectsLegacyPermitAndMalformedArtifacts(t *testing.T) {
	v := servicePolicy(t)
	id, _ := v.Service.ID()
	s, err := p.NewSession(policy(), binding())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, _ := s.Candidate()
	permit, _, err := s.Authorize(claim(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.ConsumeProtected(binding().OperationID, binding().StoragePairID, id); err == nil {
		t.Fatal("legacy witness permit gained service authority")
	}
	decoders := []func([]byte) error{
		func(b []byte) error { _, e := p.DecodeServiceEnrollment(b); return e },
		func(b []byte) error { _, e := p.DecodePolicy(b); return e },
		func(b []byte) error { _, e := p.DecodeCandidate(b); return e },
		func(b []byte) error { _, e := p.DecodeClaim(b); return e },
		func(b []byte) error { _, e := p.DecodeResult(b); return e },
	}
	for i, raw := range fixedServiceArtifacts(t) {
		if err := decoders[i](raw); err != nil {
			t.Fatal(err)
		}
		bad := bytes.Clone(raw)
		bad[9] = 2
		for _, b := range [][]byte{nil, raw[:9], raw[:len(raw)-1], append(bytes.Clone(raw), 0), bad} {
			if err := decoders[i](b); err == nil {
				t.Fatal("invalid artifact framing", i)
			}
		}
	}
}

func TestPruneServiceGuardFailureSpendsAttempt(t *testing.T) {
	for _, mode := range []string{"revoked", "lost-reply", "closed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			v := servicePolicy(t)
			id, _ := v.Service.ID()
			g := new(serviceGuard)
			i, err := p.NewServiceIdentity(*v.Service, f.Key(90), g)
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s, err := i.NewSession(ctx, v, binding())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, _ := s.Candidate()
			permit, _, err := s.Authorize(claim(t, c))
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "revoked":
				g.revoked = true
			case "lost-reply":
				g.loseReply = true
			case "closed":
				s.Close()
			case "cancelled":
				cancel()
			}
			if err := permit.ConsumeProtected(binding().OperationID, binding().StoragePairID, id); err == nil {
				t.Fatal("failed guard granted effect")
			}
			g.revoked, g.loseReply = false, false
			if err := permit.ConsumeProtected(binding().OperationID, binding().StoragePairID, id); err == nil {
				t.Fatal("failed attempt reused")
			}
			if _, err := permit.Seal(f.Hash("effect")); err == nil {
				t.Fatal("failure manufactured success")
			}
			i.Close()
			if _, err := i.NewSession(t.Context(), v, binding()); err == nil {
				t.Fatal("closed identity reused")
			}
		})
	}
}

// Fixed signing preimages are assembled separately from the model encoder.
func fixedServiceArtifacts(t testing.TB) [][]byte {
	t.Helper()
	v := servicePolicy(t)
	enrollment, _ := v.Service.CanonicalBytes()
	policyBytes, _ := v.CanonicalBytes()
	c := p.Candidate{Policy: v, Binding: binding(), Session: f.Public(250)}
	e := codec.NewEncoder(1024)
	e.Fixed([]byte("OMPRFC00"))
	e.U16(1)
	e.BytesField(policyBytes)
	for _, h := range []types.Hash{c.Binding.RequestID, c.Binding.AssignmentID, c.Binding.OperationID, c.Binding.InventoryID, c.Binding.ExecutorBindingID, c.Binding.StoragePairID, types.Hash(c.Session)} {
		e.Fixed(h[:])
	}
	h := types.DomainHash("OMESH/prune-fence/service-session/sign/v0", e.Bytes())
	copy(c.ServiceSignature[:], ed25519.Sign(f.Key(90), h[:]))
	craw, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	q := p.Claim{Candidate: c, Certificate: claim(t, c)}
	qraw, _ := q.CanonicalBytes()
	proof := p.ServiceConsumption{Nonce: [32]byte(f.Hash("consume-challenge"))}
	req := guardwire.Request{Kind: guardwire.Gateway, Subject: v.Service.Service, Namespace: types.DomainHash("OMESH/prune-fence/service/namespace/v0", v.Service.StorageID[:], v.Service.StoragePairID[:], c.Binding.RequestID[:]), Choice: types.DomainHash("OMESH/prune-fence/service/consume/v0", craw, proof.Nonce[:])}
	digest, _ := req.SealDigest()
	copy(proof.Seal[:], ed25519.Sign(f.Key(92), digest[:]))
	r := p.Result{Claim: q, ServiceConsumption: &proof, EffectID: f.Hash("effect")}
	cid, _ := q.Certificate.Command.ID()
	h = types.DomainHash("OMESH/prune-fence/result/sign/v1", craw, cid[:], proof.Nonce[:], proof.Seal[:], r.EffectID[:])
	copy(r.Signature[:], ed25519.Sign(f.Key(250), h[:]))
	raw, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{enrollment, policyBytes, craw, qraw, raw}
}
func TestPruneServiceCanonicalVectors(t *testing.T) {
	want := []string{"298:5ad417d64932322ef61204be48487e510ca423b466abdabb116d9a2946d86c52", "534:b3b0d61f39a97df633e08bd5edb46d0c2b6ca2c94c6f316ec2eab43a8d56e547", "834:fc879015adc3398a275265b5f91e01483585095b63566be52a70d0ee246218c1", "1484:4eb08c2c04257ee4b0753c4f5a31475b7084b67c8d132eff4d998d65a87e3bc9", "1688:c49418dad072ab4156a1fa6eae1012543b608330f1b33996450e818152e4bd80"}
	for i, raw := range fixedServiceArtifacts(t) {
		got := fmt.Sprintf("%d:%x", len(raw), sha256.Sum256(raw))
		if got != want[i] {
			t.Errorf("vector %d: %s", i, got)
		}
	}
}
func FuzzPruneServiceArtifacts(fuzz *testing.F) {
	for i, raw := range fixedServiceArtifacts(fuzz) {
		fuzz.Add(byte(i), raw)
	}
	fuzz.Fuzz(func(t *testing.T, kind byte, raw []byte) {
		var encoded []byte
		var err error
		switch kind % 5 {
		case 0:
			v, e := p.DecodeServiceEnrollment(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 1:
			v, e := p.DecodePolicy(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 2:
			v, e := p.DecodeCandidate(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 3:
			v, e := p.DecodeClaim(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		case 4:
			v, e := p.DecodeResult(raw)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		}
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("noncanonical service artifact")
		}
	})
}
