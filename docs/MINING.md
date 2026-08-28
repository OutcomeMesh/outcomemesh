# Mining design

Status: standalone development implementation; network rules pending

## What a miner does now

For each candidate height, a miner:

1. reads a consistent tip and resource snapshot;
2. chooses an ordered transaction list;
3. executes every transaction against a private candidate state;
4. creates receipts and sums checked native fees;
5. creates one reward resource for `block_subsidy + fees`, locked for 100
   block heights;
6. commits transaction, receipt, and final state roots into the header;
7. increments a 64-bit nonce until the domain-separated SHA-256 block ID is at
   or below the header target;
8. submits the full block for independent replay and atomic commit.

The reward identifier is derived from network, height, parent, and miner. It is
known before nonce search, so the miner does not have to rebuild the state tree
for every hash attempt.

`omd mine` performs this flow on CPU. The PoW search is isolated behind a small
hash/target boundary so later worker processes, GPUs, FPGAs, pools, or a changed
PoW engine do not enter transaction execution or storage code.

## Fork weight

Each valid target contributes:

```text
floor(2^256 / (target + 1))
```

The store persists every competing block, its cumulative work, and its
create/delete resource delta. More cumulative work wins; an equal-work tie uses
the lexicographically smaller tip ID. A winning side branch atomically switches
the canonical height index, materialized active state, and tip while preserving
the losing branch for later descendants. Reconstructed branches are checked
against every committed intermediate state root. Blocks and deltas are not yet
pruned. A persisted local logical-history budget atomically stops new commits
at its limit, but checkpoints, pruning, and a physical filesystem reserve remain
public-network gates.

## Why rewards are ordinary resources

Mining rewards use the same native `Resource` representation as transferred
funds. There is no hidden account balance or separate coinbase database. The
reward's consensus-committed `spend_after` is `reward height + 100`; execution
rejects an early spend and the wallet excludes immature rewards from selection.
This keeps conservation auditing, state roots, wallets, and maturity on one
state model.

## Inactive WorkGraph mining path

The anchor chain remains conventional and independently verifiable. The
implemented but inactive version-1 loop publishes weaker proof-of-work shares
into one bounded per-candidate DAG. Accepted shares can provide:

- proportional accounting for small miners without trusting a pool operator;
- transaction-inclusion commitments before the next anchor block;
- eligibility input for a short-lived preconfirmation committee;
- measurable work that can be paid only once after an anchor and maturity
  window.

Weak shares never make an invalid transaction valid and never outweigh anchor
proof of work. Useful computation, solving, proving, and archival storage remain
separate paid markets; pretending arbitrary computation is Sybil-resistant PoW
would weaken objective verification.

The isolated version-1 prototype additionally precommits each height's target
from the parent timestamp using lagged ASERT. The current miner's timestamp can
no longer make its own target easier, and bounded timestamp differences between
otherwise identical WorkSeals do not discard the whole share DAG. This rule is
not active in version-0 mining.

For each version-1 candidate the miner now:

1. executes transactions, applies the predecessor WorkGraph payout, advances
   the delayed-fee queue, and fixes one payload root;
2. takes up to four accepted local pool tips and constructs one WorkSeal;
3. searches that seal against the 512-times-easier weak threshold;
4. if the Work ID misses the hard target, stores the detached weak share,
   announces its ID, and rebuilds the next seal on the updated tips;
5. if the same Work ID meets the hard target, bypasses ordinary share admission,
   reconstructs the exact parent closure, and finalizes it as the anchor block.

The winner therefore uses the exact nonce and preimage already tested as weak
work, and cannot also appear in its own paid share list. If the 8,192-share or
3 MiB pool limit is reached, further weak results are discarded while hard
search continues on the last accepted tips. The mining loop is cancelable and
safe against concurrent remote-share admission. A deterministic integration
fixture produced 228 weak shares and then a valid replayable anchor from this
single loop.

Gossip is inventory-first: up to 1,024 sorted IDs are announced, at most 256
missing bodies are requested at once, and every response is tied to one exact
network/height/parent/target/payload context. An isolated version-1 stream now
negotiates that context and its frame/count limits. The libp2p adapter can expose
it under an explicit opt-in protocol handler and passes a real two-host QUIC
relay. The isolated block router now enforces the activation-height version
boundary across multiple possible v0 bases. Ordinary CLI/session routing remains
version 0, while explicit `work-enable`, `work-mine`, and versioned QUIC commands
exercise the transition on a marked development directory. The v1 CLI miner now
uses the unified miner and bounded pool: every weak share and the hard anchor
come from the same evolving nonce space, and the anchor commits the canonical
share closure. The opt-in QUIC server now admits authenticated inbound share
inventories into a parent-scoped round that is discarded on parent change.
The ordinary `work-mine` remains local-only. The separate `work-mine-quic`
experiment publishes to as many as eight explicit peers. Each peer accumulates
its own locally admitted, not-yet-announced IDs, sorts at the relay boundary,
and lets negotiation shorten the prefix. The mining callback only enqueues IDs;
independent workers perform all network I/O. Exact progress accounting removes
successful prefixes and retains the rest. A worker attempts relay after 128 new
IDs or, by default, after eight seconds with any partial batch. The timer is
bounded to 8 seconds..1 minute at the CLI: disabling it would systematically
leave low-hash miners below the batch threshold during short rounds. A failed
attempt retains the suffix for the next batch or timer tick. Transport/context
failure cannot invalidate hard mining; attempts have bounded deadlines and
every queue is capped by the 8,192-share round. The command also admits
reciprocal shares into its live pool. A first successful remote admission is
queued to every explicit peer except its authenticated source. Duplicate pool
admission never triggers a second fanout, which terminates gossip loops without
a separate unbounded seen-set. A bounded pre-attach buffer closes the small
window between round creation and publisher startup. Output reports unique
`gossip_shares` and resulting `gossip_copies`. Bounded activation-aware
discovery is opt-in; public activation remains disabled. A winning local anchor queues one coalesced
chain-notify-v1 prompt per peer without delaying the next mining round. Each
peer becomes the initiator of normal header-first verification; the responder
serves the canonical path pinned at handshake, and only a successfully selected
new hard-work tip invalidates the receiver's round and cancels stale hashing.

An optional `--auto-peers N` startup path fills part or all of the same eight
slots from the signed local peerbook. Before selection it contacts explicit
bootstrap peers and eligible existing records over activation-bound chain-v1,
fetches at most 64 signed advertisements per session, and atomically persists
successful batches. Version-1 records sign both activation height and capability
bits. The selector requires the exact local activation height and a WorkGraph
claim, then applies a fresh local ASN table, bounded attempts/per-ASN, self and
explicit-peer exclusion, and persisted score/latency/backoff ranking. `Probe`
still performs live identity, protocol, and exact mining-context negotiation
without announcing inventory. Signed claims therefore reduce wasted dials but
never replace capability proof. At least one live explicit or unexpired signed
bootstrap remains necessary when a local book has no usable records.

After selection, the miner repeats the bounded refresh every 30 minutes through
the selected peers without changing the active relay set mid-round. Selected
bootstrap peers remain the first tier; each tier is ordered by a local-identity and
epoch keyed hash so successive passes do not spend a small attempt budget on a
fixed peer-ID prefix. This rotation improves coverage but is not Sybil proof.

The peer probe's stable context intentionally excludes each miner's candidate
timestamp, but share admission still applies the winner-relative 120-second
window. The manager rolls the candidate after 60 seconds without changing the
stable context: it cancels/drains the old objective search, revalidates the same
DAG pool under the later timestamp, and starts a new payload generation. Both
the local and cooperative commands schedule the deadline from candidate age,
not merely command start time. The cooperative path reseeds retained inventory
into deduplicated per-peer queues, so pending work is not abandoned at handoff.

## Gates before public mining

- external PoW review and hash-rate simulations;
- production calibration of fee delay, share gossip queues, and miner strategy;
- adversarial discovery/eclipse soaks across diverse operators and networks;
- longer real-QUIC rollover soaks with clock skew and rapid parent churn;
- extended filesystem-fault storage soaks and longer multi-node QUIC churn.
