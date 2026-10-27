// Package fencetest contains public deterministic test keys, never deployment keys.
package fencetest

import (
	"bytes"
	"crypto/ed25519"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

func Key(seed byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)) }
func Public(seed byte) (p [32]byte)    { copy(p[:], Key(seed).Public().(ed25519.PublicKey)); return p }
func Hash(label string) types.Hash {
	return types.DomainHash("OMESH/test/witness-network/v0", []byte(label))
}
func Scope() custodyfence.Scope {
	s := custodyfence.Scope{AssignmentID: Hash("assignment"), IntentID: Hash("intent"), PlanID: Hash("plan"), BeginID: Hash("begin"), Owner: Public(1), Controller: Public(2), Threshold: 3}
	for i := byte(70); i < 74; i++ {
		s.Witnesses = append(s.Witnesses, Public(i))
	}
	sort.Slice(s.Witnesses, func(i, j int) bool { return bytes.Compare(s.Witnesses[i][:], s.Witnesses[j][:]) < 0 })
	return s
}
func Sign(s custodyfence.Scope, p custodyfence.Position, kind custodyfence.Kind, claim, evidence types.Hash) custodyfence.Command {
	id, _ := s.ID()
	c := custodyfence.Command{ScopeID: id, ExpectedSequence: p.Sequence, ExpectedHead: p.HeadID, Kind: kind, ClaimID: claim, EvidenceID: evidence}
	seed := byte(1)
	if kind == custodyfence.MarkUnknown || kind == custodyfence.CloseUnclaimed {
		seed = 2
	}
	c, err := c.Sign(Key(seed))
	if err != nil {
		panic(err)
	}
	return c
}

// Certificate independently constructs fixture signatures using the documented
// vote domain. Real network tests obtain their votes from retained witnesses.
func Certificate(c custodyfence.Command, seeds ...byte) custodyfence.Certificate {
	q := custodyfence.Certificate{Command: c}
	id, _ := c.ID()
	for _, seed := range seeds {
		v := custodyfence.Vote{CommandID: id, Witness: Public(seed)}
		e := codec.NewEncoder(custodyfence.VoteBytes)
		e.Fixed([]byte("OMCFVT00"))
		e.U16(0)
		e.Fixed(v.CommandID[:])
		e.Fixed(v.Witness[:])
		h := types.DomainHash("OMESH/custody-fence/vote/signature/v0", e.Bytes())
		copy(v.Signature[:], ed25519.Sign(Key(seed), h[:]))
		q.Votes = append(q.Votes, v)
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	return q
}
