package state

import (
	"bytes"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const MaximumRadixProofBytes = 8 + 2 + 32 + 1 + resource.CanonicalSize + 2 + 256*(2+32+32)

var ErrRadixProof = errors.New("invalid radix state proof")

type RadixStep struct {
	Depth   uint16
	Prefix  types.ResourceID
	Sibling types.Hash
}
type RadixProof struct {
	Version uint16
	Query   types.ResourceID
	Leaf    *resource.Resource
	Steps   []RadixStep
}

// Prove follows the query's branch bits to a terminal leaf. A different terminal
// key proves absence, including divergence inside a compressed prefix.
func (s *Memory) Prove(id types.ResourceID) (RadixProof, error) {
	if s == nil || s.version != CommitmentRadixV1 {
		return RadixProof{}, ErrCommitmentVersion
	}
	p := RadixProof{Version: CommitmentRadixV1, Query: id}
	n := s.radix
	for n != nil && n.depth < 256 {
		step := RadixStep{Depth: n.depth, Prefix: n.prefix}
		if keyBit(id, n.depth) == 0 {
			step.Sibling = n.right.hash
			n = n.left
		} else {
			step.Sibling = n.left.hash
			n = n.right
		}
		p.Steps = append(p.Steps, step)
	}
	if n != nil {
		v, ok := s.Get(n.prefix)
		if !ok {
			return RadixProof{}, ErrRadixProof
		}
		p.Leaf = &v
	}
	return p, nil
}
func (p RadixProof) root() (types.Hash, error) {
	if p.Version != CommitmentRadixV1 || len(p.Steps) > 256 {
		return types.Hash{}, ErrRadixProof
	}
	if p.Leaf == nil {
		if len(p.Steps) != 0 {
			return types.Hash{}, ErrRadixProof
		}
		return radixRoot(nil), nil
	}
	if p.Leaf.Validate() != nil {
		return types.Hash{}, ErrRadixProof
	}
	hash := types.DomainHash(domainRadixLeaf, p.Leaf.CanonicalBytes())
	prefix := p.Leaf.ID
	depth := uint16(256)
	for i := len(p.Steps) - 1; i >= 0; i-- {
		s := p.Steps[i]
		if s.Depth >= depth || s.Prefix != maskPrefix(prefix, s.Depth) || s.Sibling.IsZero() || keyBit(p.Query, s.Depth) != keyBit(prefix, s.Depth) {
			return types.Hash{}, ErrRadixProof
		}
		left, right := hash, s.Sibling
		if keyBit(p.Query, s.Depth) == 1 {
			left, right = right, left
		}
		hash = branchHash(s.Prefix, s.Depth, left, right)
		prefix = s.Prefix
		depth = s.Depth
	}
	return types.DomainHash(domainRadixRoot, hash[:]), nil
}
func VerifyRadixProof(root types.Hash, query types.ResourceID, p RadixProof) (resource.Resource, bool, error) {
	actual, e := p.root()
	if e != nil || root != actual || query != p.Query {
		return resource.Resource{}, false, ErrRadixProof
	}
	if p.Leaf == nil || p.Leaf.ID != query {
		return resource.Resource{}, false, nil
	}
	return *p.Leaf, true, nil
}
func (p RadixProof) CanonicalBytes() ([]byte, error) {
	if _, e := p.root(); e != nil {
		return nil, e
	}
	size := 45 + len(p.Steps)*66
	if p.Leaf != nil {
		size += resource.CanonicalSize
	}
	out := codec.NewEncoder(size)
	out.Fixed([]byte("OMSTRPF1"))
	out.U16(p.Version)
	out.Fixed(p.Query[:])
	if p.Leaf == nil {
		out.U8(0)
	} else {
		out.U8(1)
		out.Fixed(p.Leaf.CanonicalBytes())
	}
	out.U16(uint16(len(p.Steps)))
	for _, s := range p.Steps {
		out.U16(s.Depth)
		out.Fixed(s.Prefix[:])
		out.Fixed(s.Sibling[:])
	}
	return out.Bytes(), nil
}
func DecodeRadixProof(raw []byte) (RadixProof, error) {
	var p RadixProof
	if len(raw) > MaximumRadixProofBytes {
		return p, ErrRadixProof
	}
	d := codec.NewDecoder(raw)
	magic, e := d.Fixed(8)
	if e != nil || string(magic) != "OMSTRPF1" {
		return p, ErrRadixProof
	}
	p.Version, _ = d.U16()
	q, e := d.Fixed(32)
	if e != nil {
		return p, ErrRadixProof
	}
	copy(p.Query[:], q)
	present, e := d.U8()
	if e != nil || present > 1 {
		return p, ErrRadixProof
	}
	if present == 1 {
		v, e := resource.Decode(d)
		if e != nil {
			return p, ErrRadixProof
		}
		p.Leaf = &v
	}
	count, e := d.U16()
	if e != nil || count > 256 || d.Remaining() != int(count)*66 {
		return RadixProof{}, ErrRadixProof
	}
	p.Steps = make([]RadixStep, count)
	for i := range p.Steps {
		s := &p.Steps[i]
		s.Depth, _ = d.U16()
		v, _ := d.Fixed(32)
		copy(s.Prefix[:], v)
		v, _ = d.Fixed(32)
		copy(s.Sibling[:], v)
	}
	again, e := p.CanonicalBytes()
	if e != nil || d.Finish() != nil || !bytes.Equal(raw, again) {
		return RadixProof{}, ErrRadixProof
	}
	return p, nil
}
