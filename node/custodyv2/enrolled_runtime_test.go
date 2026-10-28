package custodyv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func enrolledContext(t testing.TB) (Context, wire.Genesis) {
	t.Helper()
	c := requiredProfileContext(t)
	g := wire.Genesis{Version: wire.Version2, NetworkID: c.Assignment.Base.NetworkID, ChainGenesisID: c.Assignment.Base.GenesisID, ResourceID: f.Hash("externally-provisioned-enrolled-runtime-resource"), Issuer: f.Public(110), Threshold: 3, MaximumOperations: 32, MaximumPending: 8}
	for seed := byte(111); seed <= 114; seed++ {
		g.Witnesses = append(g.Witnesses, f.Public(seed))
	}
	sort.Slice(g.Witnesses, func(i, j int) bool { return bytes.Compare(g.Witnesses[i][:], g.Witnesses[j][:]) < 0 })
	c.Assignment.Policy.Version = PolicyVersionEnrolled
	c.Assignment.Policy.RegistryID, _ = g.ID()
	c.Assignment.Policy.RegistryDescriptorID, _ = g.DescriptorID()
	aid, _ := c.Assignment.ID()
	c.Plan.AssignmentID, c.Plan.Intent.AssignmentID = aid, aid
	c.Plan.AuditSignature, c.Plan.ServeSignature, c.Plan.AuthoritySignature = [64]byte{}, [64]byte{}, [64]byte{}
	for _, role := range []string{"audit", "serve", "authority"} {
		seed := byte(4)
		if role == "authority" {
			seed = 1
		}
		var e error
		c.Plan, e = c.Plan.Sign(role, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c, g
}
func enrollmentFor(t testing.TB, c Context, ad AdmissionBinding, g wire.Genesis, seeds ...byte) EnrollmentBinding {
	t.Helper()
	raw, e := ad.Genesis.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	id, _ := g.ID()
	did, _ := g.DescriptorID()
	s := wire.Selection{Version: wire.Version2, RegistryID: id, DescriptorID: did, Candidate: raw}
	for _, role := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		s, e = s.Sign(role.name, f.Key(role.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	q := wire.Certificate{Version: wire.Version2, Selection: s}
	if len(seeds) == 0 {
		seeds = []byte{111, 112, 113}
	}
	sid, _ := s.ID()
	for _, seed := range seeds {
		v, e := (wire.Vote{Version: wire.Version2, RegistryID: id, DescriptorID: did, SelectionID: sid}).Sign(g, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	raw, e = q.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	b := EnrollmentBinding{Version: PolicyVersionEnrolled, Registry: g, Certificate: raw}
	return b
}

type enrolledFixture struct {
	requiredRuntimeFixture
	enrollment EnrollmentBinding
}

func newEnrolledFixture(t testing.TB) enrolledFixture {
	t.Helper()
	c, g := enrolledContext(t)
	x := fixtureWithContext(t, c)
	ad := requiredRuntimeBinding(t, c)
	return enrolledFixture{requiredRuntimeFixture: requiredRuntimeFixture{fixture: x, binding: ad, targetPath: filepath.Join(x.root, "enrolled-target"), acceptorPath: filepath.Join(x.root, "enrolled-acceptor")}, enrollment: enrollmentFor(t, c, ad, g)}
}
func (x enrolledFixture) open(t testing.TB) *Target {
	t.Helper()
	v, e := OpenEnrolledTarget(x.targetPath, x.c, x.pin, x.s, x.binding, x.enrollment, f.Key(61), f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}
func (x enrolledFixture) create(t testing.TB) *Target {
	t.Helper()
	if e := CreateEnrolledTarget(x.targetPath, x.c, x.pin, x.s, x.binding, x.enrollment); e != nil {
		t.Fatal(e)
	}
	return x.open(t)
}

func TestEnrolledPolicyCommitsAnchorAndRejectsDowngrade(t *testing.T) {
	c, g := enrolledContext(t)
	raw, e := c.Assignment.Policy.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	p, e := DecodePolicy(raw)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := p.ID()
	if id != types.DomainHash("OMESH/custody/v4/witness-policy/id", raw) {
		t.Fatal("wrong profile4 domain")
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.RegistryID = f.Hash("other-anchor") }, func(p *Policy) { p.RegistryDescriptorID = f.Hash("other-descriptor") }, func(p *Policy) {
		p.Version = PolicyVersionAdmission
		p.RegistryID = types.Hash{}
		p.RegistryDescriptorID = types.Hash{}
	}} {
		x := c
		mutate(&x.Assignment.Policy)
		if e := x.Validate(); e == nil {
			t.Fatal("anchor or profilechanged without role signatures")
		}
	}
	old := g
	old.Version = wire.Version1
	rid, _ := old.ID()
	actual, _ := g.ID()
	if rid != actual {
		t.Fatal("registryversion reset resource identity")
	}
	did, _ := old.DescriptorID()
	newDID, _ := g.DescriptorID()
	if did == newDID {
		t.Fatal("different registryformat descriptor conflated")
	}
	legacy := fixtureContext(t).Assignment.Policy
	legacy.RegistryID = rid
	if _, e := legacy.CanonicalBytes(); e == nil {
		t.Fatal("legacyencoding ignored hidden registry anchor")
	}
}
func TestEnrolledRuntimeMandatoryProofAndExactEffect(t *testing.T) {
	x := newEnrolledFixture(t)
	for name, create := range map[string]func(string) error{"raw": func(p string) error { return CreateTarget(p, x.c, x.pin, x.s) }, "required": func(p string) error { return CreateRequiredTarget(p, x.c, x.pin, x.s, x.binding) }, "missing-enrollment": func(p string) error { return createRootBound(p, x.c, x.pin, "target", x.s, &x.binding) }} {
		p := filepath.Join(x.root, name)
		if e := create(p); e == nil {
			t.Fatal("bypassedprofile4", name)
		}
		if _, e := os.Stat(p); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("refusedconstructorwroteowner", name, e)
		}
	}
	target := x.create(t)
	if e := CreateEnrolledAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding, x.enrollment); e != nil {
		t.Fatal(e)
	}
	a, e := OpenEnrolledAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding, x.enrollment, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	eid, _ := x.enrollment.ID()
	target.r.hook = func(stage string) error {
		if stage == "before-effect" {
			raw, e := os.ReadFile(filepath.Join(x.targetPath, "consumed"))
			if e != nil || len(raw) < 106 || string(raw[:8]) != "OMCVUSE4" || !bytes.Equal(raw[74:106], eid[:]) {
				t.Fatal("effectprecededenrollmentconsumption", e)
			}
		}
		return nil
	}
	b := x.bundle(t, target)
	receipt, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt)
	if e != nil {
		t.Fatal(e)
	}
	if e := receipt.Verify(x.c, b); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(x.acceptorPath, "pending"))
	if e != nil || string(raw[:8]) != "OMCVPEN4" || !bytes.Equal(raw[74:106], eid[:]) {
		t.Fatal("acceptancenotboundtoregistry", e)
	}
	for _, r := range []*root{target.r, a.r} {
		s, e := r.decision.State()
		if e != nil || s.Sequence != 1 {
			t.Fatal("wrongsourceeffectcount", s, e)
		}
	}
	_ = target.Close()
	target = x.open(t)
	if _, e := target.Prepare(); !errors.Is(e, ErrConsumed) {
		t.Fatal("coldtargetresetselectedslot", e)
	}
	if _, e := target.ReadResult(); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenRequiredTarget(x.targetPath, x.c, x.pin, x.s, x.binding, f.Key(61), f.Key(14)); e == nil {
		t.Fatal("profile3factoryadoptedprofile4")
	}
}
func TestEnrolledProofRefusalsAreBeforeOwnerCreation(t *testing.T) {
	x := newEnrolledFixture(t)
	goodRaw, _ := x.enrollment.CanonicalBytes()
	for _, name := range []string{"weak", "foreign-candidate", "foreign-genesis", "version-one", "corrupt-signature"} {
		t.Run(name, func(t *testing.T) {
			b, e := DecodeEnrollmentBinding(goodRaw)
			if e != nil {
				t.Fatal(e)
			}
			q, _ := wire.DecodeCertificate(b.Certificate)
			switch name {
			case "weak":
				b = enrollmentFor(t, x.c, x.binding, b.Registry, 111, 112)
			case "foreign-candidate":
				other := x.c
				a := other.Assignment.Base
				other.Assignment.Base, e = workarchive.CreateRemoteCustodyAuthorityAssignment(other.Manifest, other.Initial, other.CustodyPolicy, f.Hash("other selected assignment"), a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
				if e != nil {
					t.Fatal(e)
				}
				aid, _ := other.Assignment.ID()
				other.Plan.AssignmentID, other.Plan.Intent.AssignmentID = aid, aid
				other.Plan.AuditSignature, other.Plan.ServeSignature, other.Plan.AuthoritySignature = [64]byte{}, [64]byte{}, [64]byte{}
				for _, role := range []string{"audit", "serve", "authority"} {
					seed := byte(4)
					if role == "authority" {
						seed = 1
					}
					other.Plan, e = other.Plan.Sign(role, f.Key(seed))
					if e != nil {
						t.Fatal(e)
					}
				}
				ad := requiredRuntimeBinding(t, other)
				b = enrollmentFor(t, other, ad, b.Registry)
				if e := b.Verify(other, ad); e != nil {
					t.Fatal("foreign proof must be valid for other assignment", e)
				}
			case "foreign-genesis":
				b.Registry.ResourceID = f.Hash("self-declared-other-resource")
			case "version-one":
				b.Registry.Version = wire.Version1
			case "corrupt-signature":
				q.Votes[0].Signature[0] ^= 1
				b.Certificate, _ = q.CanonicalBytes()
			}
			p := filepath.Join(x.root, name)
			if e := CreateEnrolledTarget(p, x.c, x.pin, x.s, x.binding, b); e == nil {
				t.Fatal("invalidenrollmentaccepted")
			}
			if _, e := os.Stat(p); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("refusedproofwroteroot", e)
			}
		})
	}
}
func TestEnrolledColdOpenPinsExactQuorumAndMarker(t *testing.T) {
	x := newEnrolledFixture(t)
	target := x.create(t)
	_ = target.Close()
	alternate := enrollmentFor(t, x.c, x.binding, x.enrollment.Registry, 112, 113, 114)
	if e := alternate.Verify(x.c, x.binding); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenEnrolledTarget(x.targetPath, x.c, x.pin, x.s, x.binding, alternate, f.Key(61), f.Key(14)); e == nil {
		t.Fatal("differentvalidQCsubsetreplacedoriginalproof")
	}
	marker := filepath.Join(x.targetPath, "enrollment")
	raw, _ := os.ReadFile(marker)
	raw[len(raw)-1] ^= 1
	if e := os.WriteFile(marker, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenEnrolledTarget(x.targetPath, x.c, x.pin, x.s, x.binding, x.enrollment, f.Key(61), f.Key(14)); e == nil {
		t.Fatal("tamperedretainedproofaccepted")
	}
}
func TestEnrolledConsumptionFailuresNeverResumeWork(t *testing.T) {
	for _, stage := range []string{"consumed-before-sync", "consumed-durable", "result-before-sync", "result-durable"} {
		t.Run(stage, func(t *testing.T) {
			x := newEnrolledFixture(t)
			target := x.create(t)
			candidate, e := target.Prepare()
			if e != nil {
				t.Fatal(e)
			}
			q := f.Certificate(candidate.Claim, 70, 71, 72)
			target.r.hook = func(name string) error {
				if name == stage {
					return errors.New("injected-write-boundary")
				}
				return nil
			}
			if _, e := target.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); e == nil {
				t.Fatal("injectedwritefailurereported success")
			}
			_ = target.Close()
			target = x.open(t)
			if _, e := target.Execute(t.Context(), q, x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrConsumed) {
				t.Fatal("reopenedtargetrepeatedwork", e)
			}
		})
	}
}
func FuzzEnrolledBindingDecoder(fz *testing.F) {
	c, g := enrolledContext(fz)
	ad := requiredRuntimeBinding(fz, c)
	b := enrollmentFor(fz, c, ad, g)
	raw, _ := b.CanonicalBytes()
	fz.Add(raw)
	fz.Add([]byte("OMCVENR4"))
	fz.Add(append(append([]byte{}, raw...), 0))
	fz.Fuzz(func(t *testing.T, raw []byte) {
		if b, e := DecodeEnrollmentBinding(raw); e == nil {
			again, e := b.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, again) {
				t.Fatal("enrollmentroundtrip")
			}
			_ = b.Verify(c, ad)
		}
	})
}

func TestEnrolledAcceptanceFailuresRetainExactPending(t *testing.T) {
	for _, stage := range []string{"pending-before-sync", "source-accepted-before-receipt"} {
		t.Run(stage, func(t *testing.T) {
			x := newEnrolledFixture(t)
			target := x.create(t)
			if e := CreateEnrolledAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding, x.enrollment); e != nil {
				t.Fatal(e)
			}
			a, e := OpenEnrolledAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding, x.enrollment, f.Key(1))
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = a.Close() }()
			b := x.bundle(t, target)
			a.r.hook = func(at string) error {
				if at == stage {
					return errors.New("injected acceptance failure")
				}
				return nil
			}
			if _, e := a.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt); e == nil {
				t.Fatal("missing injected failure")
			}
			raw, e := os.ReadFile(filepath.Join(x.acceptorPath, "pending"))
			eid, _ := x.enrollment.ID()
			if e != nil || len(raw) < 106 || string(raw[:8]) != "OMCVPEN4" || !bytes.Equal(raw[74:106], eid[:]) {
				t.Fatal("pending lacks exact enrollment", e)
			}
			_ = a.Close()
			a, e = OpenEnrolledAcceptor(x.acceptorPath, x.c, x.pin, x.ajournal, x.binding, x.enrollment, f.Key(1))
			if e != nil {
				t.Fatal(e)
			}
			state, e := a.r.decision.State()
			want := uint64(0)
			if stage == "source-accepted-before-receipt" {
				want = 1
			}
			if e != nil || state.Sequence != want {
				t.Fatal("cold open changed source", state, e)
			}
			if _, e := a.Resume(t.Context(), f.Hash("wrong bundle"), x.c.Plan.Challenge.IssuedAt); !errors.Is(e, ErrPending) {
				t.Fatal("foreign resume", e)
			}
			id, _ := b.ID()
			receipt, e := a.Resume(t.Context(), id, x.c.Plan.Challenge.IssuedAt+1)
			if e != nil {
				t.Fatal(e)
			}
			if receipt.AcceptedAt != x.c.Plan.Challenge.IssuedAt {
				t.Fatal("resume refreshed acceptance")
			}
			state, e = a.r.decision.State()
			if e != nil || state.Sequence != 1 {
				t.Fatal("resume repeated original append", state, e)
			}
		})
	}
}

func TestEnrolledCanonicalVectors(t *testing.T) {
	c, g := enrolledContext(t)
	ad := requiredRuntimeBinding(t, c)
	b := enrollmentFor(t, c, ad, g)
	p, _ := c.Assignment.Policy.ID()
	rid, _ := g.ID()
	did, _ := g.DescriptorID()
	aid, _ := c.Assignment.ID()
	bid, _ := b.ID()
	q, e := wire.DecodeCertificate(b.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	sid, _ := q.Selection.ID()
	qid, _ := q.ID()
	expected := map[string]string{
		"policy":      "c5efb3edca3e886e42c7e52bed3eb94906fafa476f67f7d8eda6a62639c59770",
		"registry":    "20899a0fa15b2c1c196bfbba9b442408dd272f8c6156a0fcd6a5ef904ae576a5",
		"descriptor":  "da08d2955b3f81b9dfd905d497206404c4a54e0f8c87e288a6c0d4ecc113dd4f",
		"assignment":  "934ef7b6241953e608c8ef12d78628804f61d028813a610a1446165922789d59",
		"selection":   "7dadcc067f2fccc1e9d13f5e502efc8addebf4732efe99519655d9d21dc1c9fe",
		"certificate": "cc4a04505f15518f5b2f1c4999fd0b7670d8c6d34ec76741c263f780a178feca",
		"enrollment":  "0ba67fd58de7b6b6d3b6c43bcf638340db24cc8214e9dbd04a9c6dbf80ef6d73",
	}
	for name, id := range map[string]types.Hash{"policy": p, "registry": rid, "descriptor": did, "assignment": aid, "selection": sid, "certificate": qid, "enrollment": bid} {
		if want, ok := expected[name]; ok {
			if id.String() != want {
				t.Fatal(name, id, want)
			}
		} else {
			t.Log(name, id)
		}
	}
}
