package custodyregistry

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func registryFixture(t testing.TB) (Genesis, Selection) {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join("..", "custodyv2", "testdata", "public-fixture", "context"))
	if e != nil {
		t.Fatal(e)
	}
	c, e := v2.DecodeContext(raw)
	if e != nil {
		t.Fatal(e)
	}
	c.Assignment.Policy.Version = v2.PolicyVersionAdmission
	aid, e := c.Assignment.ID()
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.AssignmentID = aid
	c.Plan.Intent.AssignmentID = aid
	c.Plan.AuditSignature, c.Plan.ServeSignature, c.Plan.AuthoritySignature = [64]byte{}, [64]byte{}, [64]byte{}
	for _, role := range []string{"audit", "serve", "authority"} {
		key := f.Key(4)
		if role == "authority" {
			key = f.Key(1)
		}
		c.Plan, e = c.Plan.Sign(role, key)
		if e != nil {
			t.Fatal(e)
		}
	}
	initial, e := v2.NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	g := Genesis{Version: Version1, NetworkID: c.Assignment.Base.NetworkID, ChainGenesisID: c.Assignment.Base.GenesisID, ResourceID: f.Hash("independently-provisioned-registry-test-resource"), Issuer: f.Public(110), Threshold: 3, MaximumOperations: 32, MaximumPending: 8}
	for seed := byte(111); seed < 115; seed++ {
		g.Witnesses = append(g.Witnesses, f.Public(seed))
	}
	sort.Slice(g.Witnesses, func(i, j int) bool { return bytes.Compare(g.Witnesses[i][:], g.Witnesses[j][:]) < 0 })
	id, e := g.ID()
	if e != nil {
		t.Fatal(e)
	}
	did, _ := g.DescriptorID()
	return g, registrySign(t, g, Selection{Version: Version1, RegistryID: id, DescriptorID: did, Initial: initial})
}

func registrySign(t testing.TB, g Genesis, s Selection) Selection {
	t.Helper()
	var e error
	for _, role := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		s, e = s.Sign(g, role.name, f.Key(role.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := s.Verify(g); e != nil {
		t.Fatal(e)
	}
	return s
}

func registryCertificate(t testing.TB, g Genesis, s Selection, seeds ...byte) Certificate {
	t.Helper()
	if len(seeds) == 0 {
		seeds = []byte{111, 112, 113}
	}
	q := Certificate{Version: Version1, Selection: s}
	for _, seed := range seeds {
		vote, e := SignVote(g, s, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
		q.Votes = append(q.Votes, vote)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	return q
}

func registryOtherSelection(t testing.TB, g Genesis, s Selection) Selection {
	t.Helper()
	raw, _ := s.CanonicalBytes()
	x, e := DecodeSelection(raw)
	if e != nil {
		t.Fatal(e)
	}
	x.Initial.Assignment.Base.IncarnationID = f.Hash("another-assignment-incarnation-is-not-another-resource")
	x.IssuerSignature, x.AuthoritySignature, x.ControlSignature = [64]byte{}, [64]byte{}, [64]byte{}
	return registrySign(t, g, x)
}

func TestRegistryModelCanonicalRoundTripAndThreeRoleAgreement(t *testing.T) {
	g, s := registryFixture(t)
	q := registryCertificate(t, g, s)
	if e := q.Verify(g); e != nil {
		t.Fatal(e)
	}
	check := func(raw []byte, again []byte, e error) {
		t.Helper()
		if e != nil || !bytes.Equal(raw, again) {
			t.Fatal("canonical round trip changed", e)
		}
	}
	raw, _ := g.CanonicalBytes()
	gg, e := DecodeGenesis(raw)
	if e != nil {
		t.Fatal(e)
	}
	again, e := gg.CanonicalBytes()
	check(raw, again, e)
	raw, _ = s.CanonicalBytes()
	ss, e := DecodeSelection(raw)
	if e != nil || ss.Verify(gg) != nil {
		t.Fatal("selection did not retain all signatures", e)
	}
	again, e = ss.CanonicalBytes()
	check(raw, again, e)
	for _, vote := range q.Votes {
		raw, _ := vote.CanonicalBytes()
		if len(raw) != VoteBytes {
			t.Fatal("vote length", len(raw))
		}
		v, e := DecodeVote(raw)
		if e != nil || v.Verify(g) != nil {
			t.Fatal(e)
		}
		again, e := v.CanonicalBytes()
		check(raw, again, e)
	}
	raw, _ = q.CanonicalBytes()
	qq, e := DecodeCertificate(raw)
	if e != nil || qq.Verify(gg) != nil {
		t.Fatal(e)
	}
	again, e = qq.CanonicalBytes()
	check(raw, again, e)

	for _, role := range []string{"issuer", "authority", "control"} {
		x := s
		_, sig := x.signer(g, role)
		*sig = [64]byte{}
		if e := x.Verify(g); e == nil {
			t.Fatal("missing role consent accepted", role)
		}
		if _, e := x.Sign(g, role, f.Key(90)); e == nil {
			t.Fatal("foreign role seed signed", role)
		}
	}
	x := s
	x.AuthoritySignature = x.ControlSignature
	if x.Verify(g) == nil {
		t.Fatal("cross-role signature accepted")
	}
	x = s
	x.Initial.Assignment.Base.MaximumOperations--
	if x.Verify(g) == nil {
		t.Fatal("budget changed after role consent")
	}
	if _, e := s.Sign(g, "owner", f.Key(110)); e == nil {
		t.Fatal("unrecognized role accepted")
	}
	broken := f.Key(110)
	broken[0] ^= 1
	if _, e := s.Sign(g, "issuer", broken); e == nil {
		t.Fatal("inconsistent private seed/public half accepted")
	}
}

func TestRegistrySemanticAnchorCannotBeRenamedByPolicyOrAssignment(t *testing.T) {
	g, s := registryFixture(t)
	id, _ := g.ID()
	did, _ := g.DescriptorID()
	for _, mutate := range []func(*Genesis){
		func(x *Genesis) { x.MaximumOperations++ },
		func(x *Genesis) { x.MaximumPending++ },
		func(x *Genesis) { x.Issuer = f.Public(109) },
		func(x *Genesis) {
			x.Witnesses[0] = f.Public(108)
			sort.Slice(x.Witnesses, func(i, j int) bool { return bytes.Compare(x.Witnesses[i][:], x.Witnesses[j][:]) < 0 })
		},
	} {
		raw, _ := g.CanonicalBytes()
		x, _ := DecodeGenesis(raw)
		mutate(&x)
		actual, e := x.ID()
		changed, _ := x.DescriptorID()
		if e != nil || actual != id || changed == did || s.Verify(x) == nil {
			t.Fatal("descriptor change replaced or bypassed the original semantic anchor", e)
		}
	}
	x := registryOtherSelection(t, g, s)
	a, _ := x.Initial.Assignment.ID()
	b, _ := s.Initial.Assignment.ID()
	if a == b || x.RegistryID != s.RegistryID || x.DescriptorID != s.DescriptorID {
		t.Fatal("another incarnation should compete for the same immutable anchor")
	}
	// Different externally named resources are deliberately different anchors.
	// Hashing alone does not establish whether they name one physical source.
	other := g
	other.ResourceID = f.Hash("another-externally-provisioned-resource")
	actual, _ := other.ID()
	if actual == id || s.Verify(other) == nil {
		t.Fatal("cross-resource selection accepted")
	}
}

func TestRegistryRejectsForeignNetworksWeakLimitsAndSharedRoles(t *testing.T) {
	g, s := registryFixture(t)
	for name, mutate := range map[string]func(*Genesis){
		"network":              func(x *Genesis) { x.NetworkID++ },
		"chain":                func(x *Genesis) { x.ChainGenesisID = f.Hash("another-network-genesis") },
		"operation-cap":        func(x *Genesis) { x.MaximumOperations = s.Initial.Assignment.Base.MaximumOperations - 1 },
		"pending-cap":          func(x *Genesis) { x.MaximumPending = s.Initial.Assignment.Base.MaximumPending - 1 },
		"issuer-role":          func(x *Genesis) { x.Issuer = s.Initial.Assignment.Base.AuthorityPublicKey },
		"custody-auditor-role": func(x *Genesis) { x.Issuer = s.Initial.CustodyPolicy.TrustedAuditors[0] },
		"witness-role": func(x *Genesis) {
			x.Witnesses[0] = s.Initial.Assignment.Base.RemoteControlPublicKey
			sort.Slice(x.Witnesses, func(i, j int) bool { return bytes.Compare(x.Witnesses[i][:], x.Witnesses[j][:]) < 0 })
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := g.CanonicalBytes()
			x, _ := DecodeGenesis(raw)
			mutate(&x)
			candidate := s
			candidate.RegistryID, _ = x.ID()
			candidate.DescriptorID, _ = x.DescriptorID()
			if candidate.ValidateDraft(x) == nil {
				t.Fatal("invalid registry or proposed enrollment accepted")
			}
		})
	}
	for _, change := range []func(*Genesis){
		func(x *Genesis) { x.Version = 0 }, func(x *Genesis) { x.NetworkID = 0 },
		func(x *Genesis) { x.ChainGenesisID = types.Hash{} }, func(x *Genesis) { x.ResourceID = types.Hash{} },
		func(x *Genesis) { x.Issuer = [32]byte{} }, func(x *Genesis) { x.MaximumOperations = 0 },
		func(x *Genesis) { x.MaximumOperations = 65537 }, func(x *Genesis) { x.MaximumPending = 0 },
		func(x *Genesis) { x.MaximumPending = 65535 }, func(x *Genesis) { x.MaximumOperations = 1; x.MaximumPending = 2 },
		func(x *Genesis) { x.Witnesses = x.Witnesses[:3] }, func(x *Genesis) { x.Threshold = 2 },
		func(x *Genesis) { x.Threshold = 5 }, func(x *Genesis) { x.Witnesses[1] = x.Witnesses[0] },
		func(x *Genesis) { x.Witnesses[0] = x.Issuer }, func(x *Genesis) { x.Witnesses[0] = [32]byte{} },
	} {
		raw, _ := g.CanonicalBytes()
		x, _ := DecodeGenesis(raw)
		change(&x)
		if _, e := x.CanonicalBytes(); e == nil {
			t.Fatal("malformed descriptor encoded")
		}
	}
	x := s
	x.Initial.Assignment.Policy.Version = v2.Version2
	if x.ValidateDraft(g) == nil {
		t.Fatal("legacy raw profile selected")
	}
	x = s
	x.Initial.Initial.Version = 1
	if x.ValidateDraft(g) == nil {
		t.Fatal("renewed receipt selected as an unspent origin")
	}
}

func TestRegistryQuorumIsCompleteUniqueAndDescriptorBound(t *testing.T) {
	g, s := registryFixture(t)
	weak := registryCertificate(t, g, s, 111, 112)
	if weak.Verify(g) == nil {
		t.Fatal("two of four votes formed a quorum")
	}
	q := registryCertificate(t, g, s)
	x := q
	x.Votes = append([]Vote{}, q.Votes...)
	x.Votes[1] = x.Votes[0]
	if x.Verify(g) == nil {
		t.Fatal("duplicate member formed a quorum")
	}
	x = q
	x.Votes = append([]Vote{}, q.Votes...)
	x.Votes[0].Signature[0] ^= 1
	if x.Verify(g) == nil {
		t.Fatal("corrupt witness signature accepted")
	}
	x = q
	x.Selection = registryOtherSelection(t, g, s)
	if x.Verify(g) == nil {
		t.Fatal("votes attached to a different selected assignment")
	}
	v := q.Votes[0]
	if _, e := v.Sign(g, f.Key(99)); e == nil {
		t.Fatal("foreign witness signed")
	}
	v.DescriptorID = f.Hash("another-descriptor-same-semantic-anchor")
	if v.Verify(g) == nil {
		t.Fatal("vote replayed across descriptors")
	}
	v = q.Votes[0]
	v.RegistryID = f.Hash("another-registry")
	if v.Verify(g) == nil {
		t.Fatal("vote replayed across anchors")
	}
	if q.Selection.RegistryID != s.RegistryID {
		t.Fatal("caller-owned quorum mutated")
	}
}

func TestRegistryDecodersRejectTruncatedTrailingAndOversizedArtifacts(t *testing.T) {
	g, s := registryFixture(t)
	q := registryCertificate(t, g, s)
	for name, c := range map[string]struct {
		bytes  []byte
		decode func([]byte) error
		max    int
	}{
		"genesis":     {mustBytes(t, g.CanonicalBytes), func(b []byte) error { _, e := DecodeGenesis(b); return e }, MaximumGenesisBytes},
		"selection":   {mustBytes(t, s.CanonicalBytes), func(b []byte) error { _, e := DecodeSelection(b); return e }, MaximumSelectionBytes},
		"vote":        {mustBytes(t, q.Votes[0].CanonicalBytes), func(b []byte) error { _, e := DecodeVote(b); return e }, VoteBytes},
		"certificate": {mustBytes(t, q.CanonicalBytes), func(b []byte) error { _, e := DecodeCertificate(b); return e }, MaximumCertificateBytes},
	} {
		t.Run(name, func(t *testing.T) {
			for _, n := range []int{0, 7, 9, len(c.bytes) - 1} {
				if c.decode(c.bytes[:n]) == nil {
					t.Fatal("truncated artifact decoded", n)
				}
			}
			bad := append(append([]byte{}, c.bytes...), 0)
			if c.decode(bad) == nil {
				t.Fatal("trailing artifact decoded")
			}
			bad = append([]byte{}, c.bytes...)
			bad[9] ^= 0x40
			if c.decode(bad) == nil {
				t.Fatal("unknown format version decoded")
			}
			if c.decode(make([]byte, c.max+1)) == nil {
				t.Fatal("oversized artifact decoded")
			}
		})
	}
	// An untrusted count is checked against its fixed maximum and remaining
	// bytes before a slice is allocated. It cannot advertise a large history.
	raw := mustBytes(t, g.CanonicalBytes)
	raw[112] = 255
	if _, e := DecodeGenesis(raw); e == nil {
		t.Fatal("oversized witness count decoded")
	}
}

func mustBytes(t testing.TB, f func() ([]byte, error)) []byte {
	t.Helper()
	b, e := f()
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestRegistryGoldenDomains(t *testing.T) {
	g, s := registryFixture(t)
	q := registryCertificate(t, g, s)
	vectors := []struct {
		name string
		id   func() (types.Hash, error)
		want string
	}{
		{"anchor", g.ID, "5275d24c829a276cd6af47ed3514bb9bc00a41dccffe72aa37d13b8538d691c6"},
		{"descriptor", g.DescriptorID, "74aefad4460e8fbff7892c53cd64f2e75488f57dff9d04ba8bc59af874d79dcd"},
		{"selection", s.ID, "c7eff16ceb6d41c922a29e80a3a1808735a8ca426f162e198238c19cbabf4d81"},
		{"vote", q.Votes[0].ID, "8e1f0dd107a11befe626651673976b996e57608dccc79370c15f846201f6699b"},
		{"certificate", q.ID, "cc3b5dea14f84342a0fb2cf9b3ec46adffca1c4c075577814bc3c672f86c00ef"},
	}
	for _, v := range vectors {
		actual, e := v.id()
		if e != nil || actual.String() != v.want {
			t.Fatal(v.name, actual, v.want, e)
		}
	}
}

func FuzzRegistryPublicArtifacts(fz *testing.F) {
	g, s := registryFixture(fz)
	q := registryCertificate(fz, g, s)
	for _, raw := range [][]byte{mustBytes(fz, g.CanonicalBytes), mustBytes(fz, s.CanonicalBytes), mustBytes(fz, q.Votes[0].CanonicalBytes), mustBytes(fz, q.CanonicalBytes), []byte("OMCRGNS1"), []byte("OMCRSEL1"), []byte("OMCRVOT1"), []byte("OMCRGCT1")} {
		fz.Add(raw)
	}
	fz.Fuzz(func(t *testing.T, raw []byte) {
		check := func(b []byte, e error) {
			t.Helper()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("canonical decoder round trip changed", e)
			}
		}
		if x, e := DecodeGenesis(raw); e == nil {
			check(x.CanonicalBytes())
		}
		if x, e := DecodeSelection(raw); e == nil {
			check(x.CanonicalBytes())
			_ = x.Verify(g)
		}
		if x, e := DecodeVote(raw); e == nil {
			check(x.CanonicalBytes())
			_ = x.Verify(g)
		}
		if x, e := DecodeCertificate(raw); e == nil {
			check(x.CanonicalBytes())
			_ = x.Verify(g)
		}
	})
}
