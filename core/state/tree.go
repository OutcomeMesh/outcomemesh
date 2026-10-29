package state

// indexNode is a persistent AVL index. Updates copy only the search path;
// rotations never modify nodes shared with an earlier state or sibling branch.
type indexNode[V any] struct {
	key          string
	value        V
	left, right  *indexNode[V]
	height, size int
}

func height[V any](n *indexNode[V]) int {
	if n == nil {
		return 0
	}
	return n.height
}
func size[V any](n *indexNode[V]) int {
	if n == nil {
		return 0
	}
	return n.size
}
func node[V any](key string, value V, left, right *indexNode[V]) *indexNode[V] {
	return &indexNode[V]{key: key, value: value, left: left, right: right, height: 1 + max(height(left), height(right)), size: 1 + size(left) + size(right)}
}
func rotateLeft[V any](n *indexNode[V]) *indexNode[V] {
	r := n.right
	return node(r.key, r.value, node(n.key, n.value, n.left, r.left), r.right)
}
func rotateRight[V any](n *indexNode[V]) *indexNode[V] {
	l := n.left
	return node(l.key, l.value, l.left, node(n.key, n.value, l.right, n.right))
}
func balanceNode[V any](n *indexNode[V]) *indexNode[V] {
	if height(n.left)-height(n.right) > 1 {
		if height(n.left.left) < height(n.left.right) {
			n = node(n.key, n.value, rotateLeft(n.left), n.right)
		}
		return rotateRight(n)
	}
	if height(n.right)-height(n.left) > 1 {
		if height(n.right.right) < height(n.right.left) {
			n = node(n.key, n.value, n.left, rotateRight(n.right))
		}
		return rotateLeft(n)
	}
	return n
}
func find[V any](n *indexNode[V], key string) (v V, ok bool) {
	for n != nil {
		if key < n.key {
			n = n.left
		} else if key > n.key {
			n = n.right
		} else {
			return n.value, true
		}
	}
	return
}
func put[V any](n *indexNode[V], key string, value V) *indexNode[V] {
	if n == nil {
		return node(key, value, nil, nil)
	}
	if key < n.key {
		return balanceNode(node(n.key, n.value, put(n.left, key, value), n.right))
	}
	if key > n.key {
		return balanceNode(node(n.key, n.value, n.left, put(n.right, key, value)))
	}
	return node(key, value, n.left, n.right)
}
func remove[V any](n *indexNode[V], key string) *indexNode[V] {
	if n == nil {
		return nil
	}
	if key < n.key {
		return balanceNode(node(n.key, n.value, remove(n.left, key), n.right))
	}
	if key > n.key {
		return balanceNode(node(n.key, n.value, n.left, remove(n.right, key)))
	}
	if n.left == nil {
		return n.right
	}
	if n.right == nil {
		return n.left
	}
	successor := n.right
	for successor.left != nil {
		successor = successor.left
	}
	return balanceNode(node(successor.key, successor.value, n.left, remove(n.right, successor.key)))
}
func walk[V any](n *indexNode[V], visit func(V)) {
	if n == nil {
		return
	}
	walk(n.left, visit)
	visit(n.value)
	walk(n.right, visit)
}
