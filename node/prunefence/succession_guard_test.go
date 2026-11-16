//go:build linux || darwin

package prunefence_test

import (
	"bytes"
	"path/filepath"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyguard"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	p "github.com/outcomemesh/outcomemesh/node/prunefence"
)

func successorPermit(t testing.TB, v p.Policy, succession p.ServiceSuccession, g *custodyguard.Store) *p.Permit {
	t.Helper()
	signer, err := p.NewSuccessorServiceIdentity(*v.Service, f.Key(95), g, succession)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	s, err := signer.NewSession(t.Context(), v, binding())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	c, err := s.Candidate()
	if err != nil || c.Succession == nil || *c.Succession != succession || c.ServiceSigner() != f.Public(95) {
		t.Fatal("successor candidate", err)
	}
	permit, _, err := s.Authorize(claim(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return permit
}

func TestPruneServiceSuccessionOriginalGuardState(t *testing.T) {
	for _, name := range []string{"free", "occupied", "successor revoked"} {
		t.Run(name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(dir, "guard")
			// Leave spare budget so the occupied-slot case fails even if a new
			// signer could otherwise afford another logical slot.
			g, err := custodyguard.Create(root, custodyguard.Config{Subjects: [][32]byte{f.Public(90)}, Limit: 4, Revoker: f.Public(93), Replacer: f.Public(94)})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			guardID := g.Identity()
			v := servicePolicy(t)
			e := *v.Service
			e.Guard = guardID.PublicKey
			e, err = e.Sign(f.Key(91))
			if err != nil {
				t.Fatal(err)
			}
			v.Service = &e
			enrollment, _ := e.ID()
			_, old := servicePermit(t, v, g)
			var oldResult []byte
			if name == "occupied" {
				if err = old.ConsumeProtected(binding().OperationID, binding().StoragePairID, enrollment); err != nil {
					t.Fatal(err)
				}
				res, err := old.Seal(f.Hash("old effect"))
				if err != nil {
					t.Fatal(err)
				}
				oldResult, err = res.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
			}
			revoke := func(subject byte) guardwire.Revocation {
				t.Helper()
				r, err := (guardwire.Revocation{GuardID: guardID.ID(), Subject: f.Public(subject), Authority: f.Public(93), ReasonID: f.Hash("incident")}).Sign(f.Key(93))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = g.Revoke(t.Context(), r); err != nil {
					t.Fatal(err)
				}
				return r
			}
			rid, err := revoke(90).ID()
			if err != nil {
				t.Fatal(err)
			}
			before, err := g.Position()
			if err != nil {
				t.Fatal(err)
			}
			request := replacementRequest(t, guardID.ID(), rid, before, 90, 95)
			receipt, err := g.Replace(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			succ := signSuccession(t, v, receipt)
			if name == "successor revoked" {
				revoke(95)
			}
			pos, err := g.Position()
			if err != nil {
				t.Fatal(err)
			}
			if err = g.Close(); err != nil {
				t.Fatal(err)
			}
			cold, err := custodyguard.Open(root, guardID, pos, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cold.Close()
			again, err := cold.Replace(t.Context(), request)
			if err != nil || again != receipt {
				t.Fatal("lost historical receipt", err)
			}
			if _, err := p.NewSuccessorServiceIdentity(e, f.Key(90), cold, succ); err == nil {
				t.Fatal("wrong signer")
			}
			broken := succ
			broken.IssuerSignature[0] ^= 1
			inert, err := p.NewSuccessorServiceIdentity(e, f.Key(95), cold, broken)
			if err == nil {
				if _, err := inert.NewSession(t.Context(), v, binding()); err == nil {
					t.Fatal("invalid issuer signature obtained session")
				}
				inert.Close()
			}
			_, copiedOld := servicePermit(t, v, cold)
			if err = copiedOld.ConsumeProtected(binding().OperationID, binding().StoragePairID, enrollment); err == nil {
				t.Fatal("copied original key consumed after revocation")
			}
			permit := successorPermit(t, v, succ, cold)
			err = permit.ConsumeProtected(binding().OperationID, binding().StoragePairID, enrollment)
			if name != "free" {
				if err == nil {
					t.Fatal("occupied or revoked successor consumed")
				}
				if _, err = permit.Seal(f.Hash("another result")); err == nil {
					t.Fatal("refusal minted result")
				}
				got, err := cold.Position()
				if err != nil || got != pos {
					t.Fatal("refusal changed guard history", err)
				}
				if oldResult != nil {
					r, err := p.DecodeResult(oldResult)
					if err != nil || r.Claim.Candidate.ServiceSigner() != f.Public(90) {
						t.Fatal("old evidence invalidated", err)
					}
					raw, _ := r.CanonicalBytes()
					if !bytes.Equal(raw, oldResult) {
						t.Fatal("old evidence bytes changed")
					}
				}
				return
			}
			if err != nil {
				t.Fatal("free original slot", err)
			}
			got, err := cold.Position()
			if err != nil || got.Sequence != pos.Sequence+1 {
				t.Fatal("expected one choice", err)
			}
			res, err := permit.Seal(f.Hash("new effect"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := res.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			r, err := p.DecodeResult(raw)
			if err != nil || r.Claim.Candidate.ServiceSigner() != f.Public(95) || *r.Claim.Candidate.Succession != succ {
				t.Fatal("invalid successor result", err)
			}
			duplicate := successorPermit(t, v, succ, cold)
			if err := duplicate.ConsumeProtected(binding().OperationID, binding().StoragePairID, enrollment); err == nil {
				t.Fatal("replacement reused occupied logical slot")
			}
			pos2, err := cold.Position()
			if err != nil || pos2 != got {
				t.Fatal("copied successor changed state", err)
			}
		})
	}
}
