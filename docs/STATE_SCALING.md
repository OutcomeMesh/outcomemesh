# State costs with the v0 commitment

Memory snapshots use immutable AVL indexes. Updating k resources copies search
paths, rather than the entire resource map: O(k log N), plus owner/asset index
updates. Parent and sibling snapshots share only immutable nodes. Resource values
have no mutable slice fields. Input validation and the prohibition on consuming
and recreating an existing identifier in one diff are unchanged.

Balance reads the cached owner/asset aggregate in O(log A), where A is the number
of accounts with resources. The aggregate uses 128 bits internally so overflow
continues to be reported correctly even after resources are removed. Spendable
balance scans only that owner's asset, because maturity depends on the requested
height. Wallet selection walks the same deterministic resource-ID order within
that account.

The v0 root is unchanged: sorted resource leaves, paired domain-separated hashes,
and duplication of an odd final node. Leaf hashes are cached, iteration needs no
sort, and repeated Root calls on one immutable snapshot share a concurrent cache.
A changed root still costs O(N) internal hashes. Insertions shift leaf ranks in
this commitment; path copying alone cannot make that cost logarithmic.

Mempool admission, selection and revalidation use ApplyTransition, which does not
materialize a root. Consensus block and WorkGraph execution still use Apply and
retain every transaction's original post-state root. Removing those roots or
switching to a sparse/persistent Merkle commitment requires a versioned protocol
proposal, activation rules and new independent verification. No such activation
is part of this change.

On an Apple M3, a representative one-input/one-output diff measured about 2.4 µs
at 1,000 resources and 4.5 µs at 100,000; balance lookup was about 80 ns in both
cases. Changed-root computation still grew from roughly 0.10 ms to 16 ms. These
are local microbenchmarks, not network throughput or a capacity guarantee.

Pebble's v0 canonical-height update now stops at the retained common ancestor.
A straight append writes one height. A reorganization deletes the old divergent
suffix and installs the new suffix in the same synced batch as the tip and active
state. Heights above a shorter winning branch are deleted; the unchanged prefix
is retained. This operation no longer rewrites or implicitly repairs the prefix.
Full history verification remains a separate operation. Snapshot materialization
and diff derivation elsewhere in the storage path still scan state; this is not
a claim that all block storage costs are proportional to the transaction delta.

Physical disk reserves, WAL/LSM amplification, device exhaustion, power loss and
long-retention operations remain launch work. Logical history limits do not bound
filesystem use. Preserve original stores and independently retained pins; a copied
folder does not create an independent current authority.
