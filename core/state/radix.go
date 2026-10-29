package state

import (
	"encoding/binary"
	"math/bits"

	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

// Commitment versions are separate from block/workgraph versions.
const CommitmentV0 uint16 = 0
const CommitmentRadixV1 uint16 = 1
const domainRadixEmpty = "OMESH/state/radix/v1/empty"
const domainRadixLeaf = "OMESH/state/radix/v1/leaf"
const domainRadixBranch = "OMESH/state/radix/v1/branch"
const domainRadixRoot = "OMESH/state/radix/v1/root"

// radixNode is a compressed binary trie. Branch prefixes are masked after
// depth; leaves use the complete resource ID and depth 256. Every branch has
// two children and strictly increasing depths. Shape depends only on keys.
// Path copying hashes at most 256 branches per changed key, independent of N.
type radixNode struct {
	prefix      types.ResourceID
	depth       uint16
	left, right *radixNode
	hash        types.Hash
}

func keyBit(key types.ResourceID, depth uint16) byte { return (key[depth/8] >> uint(7-depth%8)) & 1 }
func sharedBits(a, b types.ResourceID) uint16 {
	for i := range a {
		if diff := a[i] ^ b[i]; diff != 0 {
			return uint16(i*8 + bits.LeadingZeros8(diff))
		}
	}
	return 256
}
func maskPrefix(key types.ResourceID, depth uint16) types.ResourceID {
	if depth == 256 {
		return key
	}
	i := depth / 8
	key[i] &= byte(0xff << uint(8-depth%8))
	for j := int(i) + 1; j < len(key); j++ {
		key[j] = 0
	}
	return key
}
func radixLeaf(v resource.Resource) *radixNode {
	return &radixNode{prefix: v.ID, depth: 256, hash: types.DomainHash(domainRadixLeaf, v.CanonicalBytes())}
}
func branchHash(prefix types.ResourceID, depth uint16, left, right types.Hash) types.Hash {
	var d [2]byte
	binary.BigEndian.PutUint16(d[:], depth)
	return types.DomainHash(domainRadixBranch, d[:], prefix[:], left[:], right[:])
}
func radixBranch(depth uint16, left, right *radixNode) *radixNode {
	prefix := maskPrefix(left.prefix, depth)
	return &radixNode{prefix: prefix, depth: depth, left: left, right: right, hash: branchHash(prefix, depth, left.hash, right.hash)}
}
func radixInsert(n, leaf *radixNode) *radixNode {
	if n == nil {
		return leaf
	}
	common := sharedBits(n.prefix, leaf.prefix)
	if common < n.depth {
		if keyBit(leaf.prefix, common) == 0 {
			return radixBranch(common, leaf, n)
		}
		return radixBranch(common, n, leaf)
	}
	if n.depth == 256 {
		return leaf
	} // caller validates absence before any mutation
	if keyBit(leaf.prefix, n.depth) == 0 {
		return radixBranch(n.depth, radixInsert(n.left, leaf), n.right)
	}
	return radixBranch(n.depth, n.left, radixInsert(n.right, leaf))
}
func radixRemove(n *radixNode, key types.ResourceID) *radixNode {
	if n == nil || sharedBits(n.prefix, key) < n.depth {
		return n
	}
	if n.depth == 256 {
		return nil
	}
	left, right := n.left, n.right
	if keyBit(key, n.depth) == 0 {
		left = radixRemove(left, key)
	} else {
		right = radixRemove(right, key)
	}
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return radixBranch(n.depth, left, right)
}
func radixRoot(n *radixNode) types.Hash {
	h := types.DomainHash(domainRadixEmpty)
	if n != nil {
		h = n.hash
	}
	return types.DomainHash(domainRadixRoot, h[:])
}
func ValidCommitment(version uint16) bool {
	return version == CommitmentV0 || version == CommitmentRadixV1
}
func (state *Memory) CommitmentVersion() uint16 {
	if state == nil {
		return CommitmentV0
	}
	return state.version
}
func EmptyVersion(version uint16) (*Memory, error) {
	if !ValidCommitment(version) {
		return nil, ErrCommitmentVersion
	}
	return &Memory{version: version}, nil
}

// NewVersion is explicit construction, never an in-place chain migration.
func NewVersion(resources []resource.Resource, version uint16) (*Memory, error) {
	result, e := EmptyVersion(version)
	if e != nil {
		return nil, e
	}
	return build(result, resources)
}
