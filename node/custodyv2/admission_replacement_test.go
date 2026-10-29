package custodyv2

import (
	"bytes"
	"crypto/ed25519"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

// This codec fixture deliberately keeps its legacy unguarded admission context:
// decoding mixed proofs must not itself authorize a policy upgrade.
func replacementAdmissionCertificate(t testing.TB) (AdmissionGenesis, AdmissionCertificate) {
	t.Helper()
	c := modelAdmissionContext(t, 4, 2)
	g, e := NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	state, e := NewAdmissionState(g, gid)
	if e != nil {
		t.Fatal(e)
	}
	entry := modelAdmissionEntry(t, g, state, c, AdmissionAdmit, nil)
	cert := modelAdmissionCertificate(t, entry)
	subject := cert.Votes[0].Witness
	q, e := (guard.Replacement{GuardID: f.Hash("guard-id"), Subject: subject, Successor: f.Public(92), Authority: f.Public(91), RevocationID: f.Hash("revocation"), EvidenceID: f.Hash("retained obligations"), Before: guard.Position{Sequence: 1, Head: f.Hash("guard-head")}}).Accept(f.Key(92))
	if e != nil {
		t.Fatal(e)
	}
	q, e = q.Authorize(f.Key(91))
	if e != nil {
		t.Fatal(e)
	}
	r, e := (guard.ReplacementReceipt{Request: q, Guard: f.Public(240)}).Sign(f.Key(240))
	if e != nil {
		t.Fatal(e)
	}
	cert.Votes[0], e = signAdmissionVote(entry, f.Key(92))
	if e != nil {
		t.Fatal(e)
	}
	cert.Votes[0].Replacement = &r
	for i := range cert.Votes {
		q := AdmissionGuardRequest(entry, cert.Votes[i].Witness)
		h, e := q.SealDigest()
		if e != nil {
			t.Fatal(e)
		}
		copy(cert.Votes[i].GuardSeal[:], ed25519.Sign(f.Key(240), h[:]))
	}
	sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
	return g, cert
}
func TestAdmissionReplacementMixedCodecDoesNotUpgradeLegacyPolicy(t *testing.T) {
	g, q := replacementAdmissionCertificate(t)
	raw, e := q.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeAdmissionCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	if got.Verify(g) == nil {
		t.Fatal("legacy genesis accepted replacement guard")
	}
	if types.DomainHash("replacement admission vector", raw).String() != "0db9134ff7ea1828fd7f6dfebd25fb0ca07b18a4ae3ba87783207f5f63b88bb1" {
		t.Fatal("replacement admission wire vector changed")
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
		if _, e = DecodeAdmissionCertificate(bad); e == nil {
			t.Fatal("noncanonical replacement certificate")
		}
	}
}
func FuzzReplacementAdmissionCodecs(fz *testing.F) {
	_, q := replacementAdmissionCertificate(fz)
	raw, e := q.CanonicalBytes()
	if e != nil {
		fz.Fatal(e)
	}
	fz.Add(raw)
	for _, v := range q.Votes {
		raw, e = v.CanonicalBytes()
		if e != nil {
			fz.Fatal(e)
		}
		fz.Add(raw)
	}
	fz.Fuzz(func(t *testing.T, b []byte) {
		if v, e := DecodeAdmissionVote(b); e == nil {
			raw, e := v.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("noncanonical vote")
			}
		}
		if q, e := DecodeAdmissionCertificate(b); e == nil {
			raw, e := q.CanonicalBytes()
			if e != nil || !bytes.Equal(raw, b) {
				t.Fatal("noncanonical certificate")
			}
		}
	})
}
