package custodyv2

import (
	"bytes"
	"encoding/hex"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
)

func requiredProfileContext(t testing.TB) Context {
	t.Helper()
	c := fixtureContext(t)
	c.Assignment.Policy.Version = PolicyVersionAdmission
	aid, e := c.Assignment.ID()
	if e != nil {
		t.Fatal(e)
	}
	c.Plan.AssignmentID = aid
	c.Plan.Intent.AssignmentID = aid
	c.Plan.AuditSignature = [64]byte{}
	c.Plan.ServeSignature = [64]byte{}
	c.Plan.AuthoritySignature = [64]byte{}
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
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}

func TestRequiredProfileImmutableSignedMode(t *testing.T) {
	legacy := fixtureContext(t)
	legacyAssignment, _ := legacy.Assignment.ID()
	legacyContext, _ := legacy.ID()
	legacyScope, _ := legacy.Scope()
	legacyScopeID, _ := legacyScope.ID()
	required := requiredProfileContext(t)
	requiredAssignment, _ := required.Assignment.ID()
	requiredContext, _ := required.ID()
	requiredScope, _ := required.Scope()
	requiredScopeID, _ := requiredScope.ID()
	if requiredAssignment == legacyAssignment || requiredContext == legacyContext || requiredScopeID == legacyScopeID {
		t.Fatal("mandatory mode did not change assignment, context or execution scope")
	}
	if required.Assignment.Version != Version2 || required.Plan.Version != Version2 {
		t.Fatal("policy mode changed outer protocol version")
	}
	// Retaining the signed job while stripping admission changes its assignment.
	stripped := required
	stripped.Assignment.Policy.Version = Version2
	if e := stripped.Validate(); e == nil {
		t.Fatal("stripped policy authorized the existing signed job")
	}
	// Even rewriting both unsigned assignment references cannot reuse old role
	// signatures. Every role must explicitly authorize the policy-2 job instead.
	stripped.Plan.AssignmentID = legacyAssignment
	stripped.Plan.Intent.AssignmentID = legacyAssignment
	if e := stripped.Plan.ValidateDraft(stripped.Assignment); e != nil {
		t.Fatal("expected a structurally valid downgraded draft", e)
	}
	if e := stripped.Validate(); e == nil {
		t.Fatal("mandatory role signatures authorized the downgraded job")
	}
	oldIntoRequired := legacy
	oldIntoRequired.Assignment.Policy.Version = PolicyVersionAdmission
	oldIntoRequired.Plan.AssignmentID = requiredAssignment
	oldIntoRequired.Plan.Intent.AssignmentID = requiredAssignment
	if e := oldIntoRequired.Validate(); e == nil {
		t.Fatal("legacy signatures authorized mandatory admission without role consent")
	}
}

func TestRequiredProfilePolicyAndContextRoundTrip(t *testing.T) {
	for _, version := range []uint16{Version2, PolicyVersionAdmission} {
		c := fixtureContext(t)
		if version == PolicyVersionAdmission {
			c = requiredProfileContext(t)
		}
		raw, e := c.Assignment.Policy.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		p, e := DecodePolicy(raw)
		if e != nil {
			t.Fatal(e)
		}
		again, e := p.CanonicalBytes()
		if e != nil || !bytes.Equal(again, raw) || p.Version != version {
			t.Fatal("policy round trip", e)
		}
		domain := "OMESH/custody/v2/witness-policy/id"
		if version == PolicyVersionAdmission {
			domain = "OMESH/custody/v3/witness-policy/id"
		}
		id, e := p.ID()
		if e != nil || id != types.DomainHash(domain, raw) {
			t.Fatal("wrong versioned policy domain", e)
		}
		cb, e := c.CanonicalBytes()
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := DecodeContext(cb)
		if e != nil {
			t.Fatal(e)
		}
		db, e := decoded.CanonicalBytes()
		if e != nil || !bytes.Equal(cb, db) || decoded.Assignment.Policy.Version != version {
			t.Fatal("context round trip", e)
		}
	}
	p := fixtureContext(t).Assignment.Policy
	p.Version = 4
	if _, e := p.CanonicalBytes(); e == nil {
		t.Fatal("unknown policy version accepted")
	}
	p.Version = PolicyVersionAdmission
	raw, _ := p.CanonicalBytes()
	raw[8] = 0
	raw[9] = 4
	if _, e := DecodePolicy(raw); e == nil {
		t.Fatal("unknown wire policy version accepted")
	}
	for _, b := range [][]byte{raw[:9], append(append([]byte{}, raw...), 0)} {
		if _, e := DecodePolicy(b); e == nil {
			t.Fatal("noncanonical policy accepted")
		}
	}
}

func TestRequiredProfileWitnessRoleSeparation(t *testing.T) {
	c := requiredProfileContext(t)
	roles := [][32]byte{c.Assignment.Base.AuthorityPublicKey, c.Assignment.Base.ReplicaPublicKey, c.Assignment.Base.RemoteControlPublicKey, c.Assignment.Base.RemoteTransportPublicKey}
	roles = append(roles, c.Assignment.Base.Auditors...)
	for _, consumer := range c.Assignment.Base.Consumers {
		roles = append(roles, consumer.PublicKey)
	}
	for _, role := range roles {
		a := c.Assignment
		a.Policy.Witnesses = append([][32]byte{}, a.Policy.Witnesses...)
		a.Policy.Witnesses[0] = role
		sort.Slice(a.Policy.Witnesses, func(i, j int) bool { return bytes.Compare(a.Policy.Witnesses[i][:], a.Policy.Witnesses[j][:]) < 0 })
		if _, e := a.CanonicalBytes(); e == nil {
			t.Fatal("mandatory policy reused a participant key as a witness")
		}
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.Threshold = 2 }, func(p *Policy) { p.Witnesses = p.Witnesses[:3] }, func(p *Policy) { p.Witnesses[1] = p.Witnesses[0] }, func(p *Policy) { p.Witnesses[0] = [32]byte{} }} {
		p := c.Assignment.Policy
		p.Witnesses = append([][32]byte{}, p.Witnesses...)
		mutate(&p)
		if _, e := p.CanonicalBytes(); e == nil {
			t.Fatal("weakened mandatory witness policy accepted")
		}
	}
}

func TestRequiredProfileLegacyPolicyVectors(t *testing.T) {
	legacy := fixtureContext(t).Assignment.Policy
	raw, e := legacy.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	id, e := legacy.ID()
	if e != nil {
		t.Fatal(e)
	}
	const legacyBytes = "4f4d4356504f4c3200020304772c8a442b7db06e166cfbc1ccbcbcde6f3eba76a4e98ef3ffc519502237d6efd4eec1869fb1b8a4e817516ad5a931557cb56805c3eb16e8f3a803d647df7869e28a8970753332bd72fef413e6b0b2ef1b4aadda7aa2c141f233712a6876b351ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148"
	if hex.EncodeToString(raw) != legacyBytes || id.String() != "3b82032dfdb11a98d0c102083b85ef16ff5309626df9aa71dc4be8061049d835" {
		t.Fatal("legacy policy bytes or ID changed")
	}
	required := legacy
	required.Version = PolicyVersionAdmission
	b, e := required.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	rid, e := required.ID()
	if e != nil {
		t.Fatal(e)
	}
	if rid.String() != "e0e7343520955af49bb6ecb303c25b8ad85202438d9fbbe4c2cfadfa64daf194" {
		t.Fatal("mandatory policy ID changed", rid)
	}
	if !bytes.Equal(raw[:8], b[:8]) || !bytes.Equal(raw[10:], b[10:]) || bytes.Equal(raw, b) || id == rid {
		t.Fatal("policy version did not preserve the layout with a distinct signed mode")
	}
}

func FuzzRequiredProfilePolicy(fz *testing.F) {
	legacy := fixtureContext(fz).Assignment.Policy
	raw, _ := legacy.CanonicalBytes()
	fz.Add(raw)
	legacy.Version = PolicyVersionAdmission
	raw, _ = legacy.CanonicalBytes()
	fz.Add(raw)
	fz.Fuzz(func(t *testing.T, b []byte) {
		if p, e := DecodePolicy(b); e == nil {
			again, e := p.CanonicalBytes()
			if e != nil || !bytes.Equal(b, again) {
				t.Fatal("policy round trip", e)
			}
			if p.Version != Version2 && p.Version != PolicyVersionAdmission {
				t.Fatal("unknown policy version decoded")
			}
		}
	})
}
