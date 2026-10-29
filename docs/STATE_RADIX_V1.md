# Incremental state commitment v1

State commitment v1 is a compressed immutable radix tree. Standalone protocol 2
selects it in genesis and uses genesis, block and receipt version 2. WorkGraph
block version 3 selects it at an explicit activation height. Block versions and
state commitment versions are separate namespaces.

## Activation and compatibility

Create a separate data directory with an explicitly chosen, unused network ID:

```sh
omd init --data ./data/radix-dev --protocol-version 2 --network 3102 \
  --owner <address> --difficulty-bits 12
omd mine --data ./data/radix-dev --count 1
omd verify --data ./data/radix-dev
```

The default stays protocol 0. The original genesis bytes pin the choice on every
open, including read-only access. Header admission, execution contexts and direct
storage commits reject mismatched versions. Reorg and historical snapshots retain
the genesis-selected commitment. Peer handshakes pin the genesis ID; snapshot
collectors take the commitment version from the local chain, never from a remote
manifest or by trying different root algorithms.

Resource and transaction formats, transaction IDs, PoW, issuance and reward
maturity remain unchanged. Choose a different network ID to keep transaction
signatures separate from other chains. Old binaries reject genesis/header version
2. Transport envelopes and chunked snapshot resource encoding keep their existing
version; this does not mean they select the state commitment.

Standalone protocol 2 remains a new-chain option. Existing WorkGraph chains can
use the bounded offline migration and explicit height transition specified in
[WORKGRAPH_RADIX_MIGRATION.md](WORKGRAPH_RADIX_MIGRATION.md). Existing protocol-0
bytes and unscheduled WorkGraph v1 roots remain unchanged. Public network
activation, independently approved checkpoints and archive/custody migration
remain separate requirements.

## Commitment definition

Let `H(domain, parts...)` be SHA-256 of the ASCII domain followed by the exact
concatenated byte strings. Resource IDs are 256-bit keys, traversed most-significant
bit first. A nonempty tree is a compressed binary radix tree with these nodes:

- A leaf stores the full resource ID and commits to all canonical resource bytes:
  `H("OMESH/state/radix/v1/leaf", canonical_resource)`.
- A branch is at the first differing bit `d` of its descendants, with `0 <= d < 256`.
  Both children exist: left has bit 0, right bit 1. Its prefix is a 32-byte ID with
  the first `d` bits retained and every later bit zeroed. Its hash is
  `H("OMESH/state/radix/v1/branch", uint16_be(d), prefix, left_hash, right_hash)`.
- Empty content is `H("OMESH/state/radix/v1/empty")`. The externally committed
  root is always `H("OMESH/state/radix/v1/root", content_hash)`.

Deletion collapses any branch left with one child. Insertion splits at the first
differing key bit. Branch depth strictly increases toward the leaves, whose
internal depth is 256. Tree shape depends only on the key set, never on insertion
order or AVL balancing. Existing resource validation, duplicate-ID rejection and
the prohibition on consuming and recreating one pre-state ID in a diff still apply.

An update copies and hashes only the changed search paths. A key touches at most
256 branches; typical hashed keys have much shorter paths. A nonempty tree has
`2N - 1` nodes. Parent and sibling snapshots share immutable nodes. `Root()` reads
the already committed top hash, so each transaction receipt no longer scans the
whole state in this version. Account/resource lookup indexes remain separate.

This does not remove all state-size costs: initial loading, resource export,
current Pebble snapshot materialization and diff derivation still scan resources.
It is not a claim about end-to-end network throughput. On an Apple M3, a local
one-input/one-output diff including the new root took roughly 6–8 microseconds at
1,000 resources and 14 microseconds at 100,000 resources.

## Membership and absence proofs

The local `state.Prove` API returns a terminal resource and the root-to-leaf path.
An empty tree has no leaf and no steps. Otherwise, follow the query's bit at each
branch until a leaf; a different terminal ID proves absence, including divergence
inside a compressed prefix. Verification binds the exact query and trusted root,
checks increasing branch depths and masked prefixes, then reconstructs hashes
from the terminal leaf upward. The proof grants no finality or trust to its root.

Canonical proof bytes are:

```text
"OMSTRPF1"                 8 bytes
commitment_version         uint16_be, exactly 1
query_id                   32 bytes
leaf_present               uint8, exactly 0 or 1
canonical_resource         184 bytes, only if present
step_count                 uint16_be, at most 256
steps[step_count]           root first, each:
  depth                    uint16_be, 0..255
  masked_prefix            32 bytes
  sibling_hash             32 bytes
```

The maximum is 17,125 bytes. No-leaf proofs require zero steps. Decoding rejects
unknown versions, invalid resources, excessive counts, impossible depths/prefixes,
zero sibling hashes, malformed presence flags, truncation and trailing bytes.
Proofs are exposed as a bounded local API; a new public proof-serving RPC is not
introduced here. Fixed resource, root, proof, genesis and block bytes live in
[`radix-v1.json`](../core/state/testdata/radix-v1.json).

## Security boundary

Separate domains prevent old roots, leaves, internal nodes and empty content from
being interpreted interchangeably. The root is deterministic under the SHA-256
collision-resistance assumption. Compressed shape limits depth even for deliberately
chosen IDs; no probabilistic balance assumption is needed for the 256-branch bound.
An authenticated root and the correct chain version remain prerequisites for proof
verification. Protocol 0 bytes and roots must remain unchanged.
