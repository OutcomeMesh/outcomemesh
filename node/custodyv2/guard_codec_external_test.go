package custodyv2_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

// Keep this corpus small: mutating full archive/admission envelopes is expensive
// and supplies very few direct mutations of the new fixed-size proof decoders.
func guardedProofSeeds(fz testing.TB) [][]byte {
	ef, e := (gateway.Effect{Kind: gateway.EffectExecute, DeploymentID: f.Hash("dep"), ScopeID: f.Hash("scope"), AdmissionID: f.Hash("admit"), BindingID: f.Hash("binding"), ArtifactID: f.Hash("artifact"), SourceSequence: 1, SourceHead: f.Hash("head"), CheckedAt: 1}).Sign(f.Key(201))
	if e != nil {
		fz.Fatal(e)
	}
	q, e := ef.GuardRequest()
	if e != nil {
		fz.Fatal(e)
	}
	ef.GuardSeal = guardFixtureSeal(q)
	scope := f.Scope()
	scope.Guard = f.Public(240)
	sid, _ := scope.ID()
	cmd := f.Sign(scope, custodyfence.Position{HeadID: sid}, custodyfence.Claim, types.Hash{}, types.Hash{})
	qc := f.Certificate(cmd, 70, 71, 72)
	vote := qc.Votes[0]
	vote.GuardSeal = guardFixtureSeal(custodyfence.VoteGuardRequest(cmd, vote.Witness))
	av := v2.AdmissionVote{Version: 2, EntryID: f.Hash("entry"), Witness: f.Public(70)}
	enc := codec.NewEncoder(v2.AdmissionVoteBytes)
	enc.Fixed([]byte("OMCVAVT2"))
	enc.U16(2)
	enc.Fixed(av.EntryID[:])
	enc.Fixed(av.Witness[:])
	h := types.DomainHash("OMESH/custody/v2/admission/vote/signature", enc.Bytes())
	copy(av.Signature[:], ed25519.Sign(f.Key(70), h[:]))
	av.GuardSeal = guardFixtureSeal(guard.Request{Kind: guard.Admission, Subject: av.Witness, Namespace: f.Hash("genesis"), Choice: av.EntryID})
	var seeds [][]byte
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{ef, vote, scope, av} {
		raw, e := v.CanonicalBytes()
		if e != nil {
			fz.Fatal(e)
		}
		seeds = append(seeds, raw)
	}
	return seeds
}
func FuzzGuardedProofCodecs(fz *testing.F) {
	for i, raw := range guardedProofSeeds(fz) {
		fz.Add(uint8(i), raw)
	}
	fz.Fuzz(func(t *testing.T, kind uint8, raw []byte) {
		checkGuardedProofRoundTrip(t, kind, raw)
	})
}

func checkGuardedProofRoundTrip(t testing.TB, kind uint8, raw []byte) {
	var v interface{ CanonicalBytes() ([]byte, error) }
	var e error
	switch kind % 4 {
	case 0:
		v, e = gateway.DecodeEffect(raw)
	case 1:
		v, e = custodyfence.DecodeVote(raw)
	case 2:
		v, e = custodyfence.DecodeScope(raw)
	case 3:
		v, e = v2.DecodeAdmissionVote(raw)
	}
	if e != nil {
		return
	}
	again, e := v.CanonicalBytes()
	if e != nil || !bytes.Equal(raw, again) {
		t.Fatal("guarded proof accepted noncanonical bytes")
	}
}

func TestGuardedProofByteMutations(t *testing.T) {
	for kind, raw := range guardedProofSeeds(t) {
		checkGuardedProofRoundTrip(t, uint8(kind), raw)
		for i := range raw {
			for bit := byte(1); bit != 0; bit <<= 1 {
				b := append([]byte(nil), raw...)
				b[i] ^= bit
				checkGuardedProofRoundTrip(t, uint8(kind), b)
			}
		}
		for n := 0; n < len(raw); n++ {
			checkGuardedProofRoundTrip(t, uint8(kind), raw[:n])
		}
		checkGuardedProofRoundTrip(t, uint8(kind), append(append([]byte(nil), raw...), 0))
	}
}

func TestGuardedProofCanonicalVector(t *testing.T) {
	raw := bytes.Join(guardedProofSeeds(t), nil)
	got := types.DomainHash("OMESH/test/guarded-proofs/vector", raw).String()
	const want = "690664e0b9093dc2625c760b6f9fc7eb05fa5473d07a3e9853d3e42504485b4f"
	if got != want {
		t.Fatal(got)
	}
}
