package merkle

import "github.com/outcomemesh/outcomemesh/core/types"

// Root hashes payloads in their supplied order. At every odd tree level the
// final hash is paired with itself.
func Root(payloads [][]byte, emptyDomain, leafDomain, nodeDomain string) types.Hash {
	if len(payloads) == 0 {
		return types.DomainHash(emptyDomain)
	}

	level := make([]types.Hash, len(payloads))
	for index, payload := range payloads {
		level[index] = types.DomainHash(leafDomain, payload)
	}
	for len(level) > 1 {
		next := make([]types.Hash, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			left := level[index]
			right := left
			if index+1 < len(level) {
				right = level[index+1]
			}
			next = append(next, types.DomainHash(nodeDomain, left[:], right[:]))
		}
		level = next
	}
	return level[0]
}
