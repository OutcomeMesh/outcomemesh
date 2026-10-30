package custodyv2_test

import (
	"bytes"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func TestGuardedProfile5RetainedCoreVerificationDoesNotGrantAcceptance(t *testing.T) {
	c, protected, bundle, _, _ := artifactFixture(t, true)
	claim := bundle.Chain[0]
	core := protected
	core.Version = v2.Version2
	core.Protection = nil
	if err := core.VerifyRetainedResultCore(c, claim); err != nil {
		t.Fatal(err)
	}
	if core.Verify(c, claim) == nil {
		t.Fatal("bare session core granted protected result acceptance")
	}
	if protected.VerifyRetainedResultCore(c, claim) == nil {
		t.Fatal("protected wrapper accepted as retained bare core")
	}
	if err := protected.Verify(c, claim); err != nil {
		t.Fatal("existing protected result verification changed", err)
	}
	for _, name := range []string{"signature", "scope", "claim", "session", "entry", "quorum", "claim-session"} {
		t.Run(name, func(t *testing.T) {
			bad := core
			q := claim
			switch name {
			case "signature":
				bad.SessionSignature[0] ^= 1
			case "scope":
				bad.ScopeID = f.Hash("other scope")
			case "claim":
				bad.ClaimID = f.Hash("other claim")
			case "session":
				bad.SessionPublicKey = f.Public(249)
			case "entry":
				bad.Entry.Sequence++
				bad.Entry.PreviousEntryID = f.Hash("different predecessor")
			case "quorum":
				q.Votes = nil
			case "claim-session":
				q.Command.EvidenceID = v2.SessionID(f.Public(249))
			}
			if name == "scope" || name == "claim" || name == "entry" {
				var err error
				bad, err = v2.SignResultSession(bad, f.Key(250))
				if err != nil {
					t.Fatal(err)
				}
			}
			if bad.VerifyRetainedResultCore(c, q) == nil {
				t.Fatal("substituted retained core accepted")
			}
		})
	}
	unguarded, r, b, _, _ := artifactFixture(t)
	r.Version = v2.Version2
	r.Protection = nil
	if r.VerifyRetainedResultCore(unguarded, b.Chain[0]) == nil {
		t.Fatal("unguarded context gained recovery")
	}
}

func FuzzGuardedRetainedResultCore(fuzz *testing.F) {
	c, r, b, _, _ := artifactFixture(fuzz, true)
	r.Version = v2.Version2
	r.Protection = nil
	raw, err := r.CanonicalBytes()
	if err != nil {
		fuzz.Fatal(err)
	}
	fuzz.Add(raw)
	fuzz.Add([]byte("OMCVRES2"))
	fuzz.Fuzz(func(t *testing.T, raw []byte) {
		candidate, err := v2.DecodeResult(raw)
		if err != nil {
			return
		}
		encoded, err := candidate.CanonicalBytes()
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal("noncanonical result", err)
		}
		if candidate.VerifyRetainedResultCore(c, b.Chain[0]) != nil {
			return
		}
		if candidate.Verify(c, b.Chain[0]) == nil {
			t.Fatal("core verification bypassed guard effect")
		}
		if candidate.SessionPublicKey != r.SessionPublicKey || candidate.ScopeID != r.ScopeID || candidate.ClaimID != r.ClaimID {
			t.Fatal("retained core escaped original session")
		}
	})
}
