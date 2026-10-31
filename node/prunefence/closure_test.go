package prunefence_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	p "github.com/outcomemesh/outcomemesh/node/prunefence"
)

func closureIntent() p.ClosureIntent {
	return p.ClosureIntent{Policy: policy(), AssignmentID: binding().AssignmentID, RequestID: binding().RequestID}
}
func closure(t testing.TB) p.Closure {
	t.Helper()
	intent := closureIntent()
	_, draft, err := intent.Draft()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := draft.Sign(f.Key(2))
	if err != nil {
		t.Fatal(err)
	}
	return p.Closure{Intent: intent, Certificate: f.Certificate(signed, 70, 71, 72)}
}
func TestPruneFenceClosureCanonicalVectors(t *testing.T) {
	c := closure(t)
	raw, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Assemble the layout independently, without the new codec or Draft method.
	policyRaw, _ := policy().CanonicalBytes()
	expectedIntent := append([]byte("OMPRFI00\x00\x00"), binary.AppendUvarint(nil, uint64(len(policyRaw)))...)
	expectedIntent = append(expectedIntent, policyRaw...)
	expectedIntent = append(expectedIntent, c.Intent.AssignmentID[:]...)
	expectedIntent = append(expectedIntent, c.Intent.RequestID[:]...)
	got, _ := c.Intent.CanonicalBytes()
	if !bytes.Equal(got, expectedIntent) {
		t.Fatal("intent wire layout")
	}
	intentID := types.DomainHash("OMESH/prune-fence/close-intent/id/v0", expectedIntent)
	scope, _ := policy().Scope(binding().AssignmentID, binding().RequestID)
	sid, _ := scope.ID()
	command, err := (custodyfence.Command{Version: 1, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: intentID}).Sign(f.Key(2))
	if err != nil || command != c.Certificate.Command {
		t.Fatal("closure command", err)
	}
	certificate, _ := f.Certificate(command, 70, 71, 72).CanonicalBytes()
	want := append([]byte("OMPRFU00\x00\x00"), binary.AppendUvarint(nil, uint64(len(expectedIntent)))...)
	want = append(want, expectedIntent...)
	want = binary.AppendUvarint(want, uint64(len(certificate)))
	want = append(want, certificate...)
	if !bytes.Equal(raw, want) {
		t.Fatal("certificate wire layout")
	}
	gotID, err := c.ID()
	if err != nil || gotID != types.DomainHash("OMESH/prune-fence/close-certificate/id/v0", want) {
		t.Fatal("closure ID domain", err)
	}
	for _, v := range []struct {
		name string
		raw  []byte
		size int
		sha  string
	}{
		{"intent", expectedIntent, 312, "3714bed37a3149c39d383523631df42bcba24253ac9308f1b54f0a8e799b4ef2"},
		{"closure", raw, 962, "929d52e3d4bb17f3446706cd9a4d197010e086a0f5e18b80201e99981b1b99bf"},
	} {
		digest := fmt.Sprintf("%x", sha256.Sum256(v.raw))
		if len(v.raw) != v.size || digest != v.sha {
			t.Fatalf("%s size=%d sha=%s", v.name, len(v.raw), digest)
		}
	}
}
func TestPruneFenceClosureRejectsSubstitutionAndExecution(t *testing.T) {
	original := closure(t)
	raw, _ := original.CanonicalBytes()
	for _, name := range []string{"assignment", "request", "owner", "controller", "guard", "minority", "duplicate", "command-kind", "position", "evidence", "claim-id", "signature", "owner-signed"} {
		t.Run(name, func(t *testing.T) {
			c, err := p.DecodeClosure(raw)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "assignment":
				c.Intent.AssignmentID = f.Hash("other")
			case "request":
				c.Intent.RequestID = f.Hash("other")
			case "owner":
				c.Intent.Policy.Owner = f.Public(33)
			case "controller":
				c.Intent.Policy.Controller = f.Public(33)
			case "guard":
				c.Intent.Policy.Guard = f.Public(33)
			case "minority":
				c.Certificate.Votes = c.Certificate.Votes[:2]
			case "duplicate":
				c.Certificate.Votes[1] = c.Certificate.Votes[0]
			case "command-kind":
				c.Certificate.Command.Kind = custodyfence.Claim
			case "position":
				c.Certificate.Command.ExpectedSequence = 1
			case "evidence":
				c.Certificate.Command.EvidenceID = f.Hash("other")
			case "claim-id":
				c.Certificate.Command.ClaimID = f.Hash("other")
			case "signature":
				c.Certificate.Command.Signature[0] ^= 1
			case "owner-signed":
				command, err := c.Certificate.Command.Sign(f.Key(1))
				if err != nil {
					t.Fatal(err)
				}
				c.Certificate = f.Certificate(command, 70, 71, 72)
			}
			if c.Verify() == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0), bytes.Repeat([]byte{0}, p.MaximumClosureBytes+1)} {
		if _, err := p.DecodeClosure(bad); err == nil {
			t.Fatal("bad closure accepted")
		}
	}
	overlong := append([]byte(nil), raw[:12]...)
	overlong[11] |= 0x80
	overlong = append(overlong, 0)
	overlong = append(overlong, raw[12:]...)
	if _, err := p.DecodeClosure(overlong); err == nil {
		t.Fatal("noncanonical field length")
	}
	for _, empty := range []bool{false, true} {
		intent := closureIntent()
		if empty {
			intent.AssignmentID = types.Hash{}
		} else {
			intent.RequestID = types.Hash{}
		}
		if _, err := intent.CanonicalBytes(); err == nil {
			t.Fatal("empty closure context")
		}
	}
	if _, err := p.DecodeClaim(raw); err == nil {
		t.Fatal("closure decoded as claim")
	}
	if _, err := p.DecodeResult(raw); err == nil {
		t.Fatal("closure decoded as result")
	}
	s, err := p.NewSession(policy(), binding())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err := s.Authorize(original.Certificate); err == nil {
		t.Fatal("closure authorized deletion")
	}
	// An intent is request-wide: the current candidate session is not an input.
	candidate, _ := s.Candidate()
	claimScope, _, _ := candidate.Draft()
	closedScope, _, _ := original.Intent.Draft()
	a, _ := claimScope.ID()
	b, _ := closedScope.ID()
	if a != b {
		t.Fatal("closure escaped execution slot")
	}
}
func FuzzPruneFenceClosure(fuzz *testing.F) {
	c := closure(fuzz)
	raw, _ := c.CanonicalBytes()
	intent, _ := c.Intent.CanonicalBytes()
	fuzz.Add(false, raw)
	fuzz.Add(true, intent)
	fuzz.Fuzz(func(t *testing.T, isIntent bool, input []byte) {
		var encoded []byte
		var err error
		if isIntent {
			v, e := p.DecodeClosureIntent(input)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		} else {
			v, e := p.DecodeClosure(input)
			if e != nil {
				return
			}
			encoded, err = v.CanonicalBytes()
		}
		if err != nil || !bytes.Equal(input, encoded) {
			t.Fatal("noncanonical closure")
		}
	})
}
