# OutcomeMesh

OutcomeMesh is an outcome-native, proof-of-work ledger. Users authorize bounded
state outcomes instead of opaque execution paths. The protocol is being built as
an independent Go codebase: no EVM, Solidity, Bitcoin Core, Cosmos SDK, or
Substrate dependency.

The project is pre-alpha. Nothing in this repository is ready to secure real
value.

## Design principles

- Users sign constraints over the final state diff.
- Assets are typed resources with explicit owners and versions.
- Consensus data has one canonical binary encoding.
- Consensus execution is deterministic and independent of local storage.
- Proof of work remains the Sybil-resistance mechanism.
- Useful work, solving, proving, and archival storage are separate markets.
- Fast committee confirmations never replace proof-of-work fork choice.
- Cryptographic primitives are reused from reviewed implementations; protocol
  semantics are implemented here.

## What runs today

Milestones 0–4 are complete under the repository's written exit gates. The
deterministic kernel, signed ledger, standalone PoW chain, and bounded QUIC
peer-to-peer devnet all run today. Milestone 5 WorkGraph research and
implementation is now in progress; its consensus-pure DAG/accounting kernel and
an isolated version-1 block-transition prototype run only through explicit
experimental `work-*` commands and are not activated by default.

The repository also contains the first standalone-ledger slice:

- canonical genesis, block, receipt, and Merkle formats;
- SHA-256 development proof of work, integer ASERT, and cumulative-work fork
  choice;
- median-time-past, bounded future timestamps, and mature subsidy-plus-fee
  reward resources;
- atomic Pebble commits checked against an in-memory reference store;
- persistent competing branches and atomic higher-work reorganizations;
- restart-safe chain replay;
- key generation, balance lookup, constrained transfer, mining, and verification
  commands in `omd`.

Canonical block/delta pruning now exists only as a disabled-by-default
experimental API. A multi-attestor anchor binds a content-addressed archive to
the exact selected WorkGraph ancestry, and each configured replica must fully
replay its own copy before issuing a short-lived signed custody receipt. At
prune time every distinct replica directory is replayed again and the resulting
availability bundle is fsynced before one Pebble batch replaces the strict
prefix with canonical headers and a full-state retained floor. Reopen verifies
the header chain, target, cumulative work, timestamps, ancestry commitment, and
floor state before applying later deltas. This is trusted operational custody,
not a data-availability proof or consensus finality. After a floor advance,
`ComposeDirectory` can stream the exact prior archive together with only the
still-executable suffix into a new self-contained archive, without restoring the
old WorkChain database; it rechecks both floor identity and selected ancestry
before publication. Archive format v1 removes the terminal anchor from chunk
identity and freezes predecessor chunk boundaries, so every old content ID is
stable and only suffix chunks are new in the cross-generation object set. Each
directory remains complete and independently restorable. A bounded local
object store can import only a fully replayed archive, negotiate sorted missing
IDs in manifest-bound batches, and materialize a complete archive only after a
second full replay; a replica that already has the prior generation therefore
fetches only new suffix chunks. A separate opt-in libp2p QUIC-v1 protocol now
requires an exact server pin and a canonical allowlist of authenticated client
identities, with independent concurrent and fixed-window limits. It is not
trusted by consensus. A second isolated QUIC-v1 custody protocol lets a trusted
auditor issue a short-lived signed random challenge whose sampled chunk IDs are
derived deterministically from the nonce, manifest, and current receipt. The
replica returns the exact validated chunks, a signed digest proof, and a linked
version-1 receipt with the requested renewal deadline committed by the
challenge. Legacy full-replay version-0 receipts remain valid. The custody
protocol is exposed through one-shot replica and auditor `omd` commands with
separate transport/evidence keys and immutable restart records. Journal mode
adds a replay-verified renewal chain, an interval gate for external timers,
local recovery of unfinished outputs, and segment rotation that preserves all
evidence. Local byte/path growth limits include temporary files and retain
read/retry access to committed evidence when a cap is lowered. They are not a
physical disk quota. Paired checkpoints bind the journal and auditor artifacts,
including pending challenges, for cold-copy verification against an independently
retained ID. A managed local-backup command now copies both trees under their
locks and publishes a completion checkpoint only after fsync and full replay.
Incomplete targets are preserved, never overwritten or treated as ready. See
[the custody runbook](docs/CUSTODY.md) for retention rules and remaining
backup/reconciliation gates. Separate
archive-object serve/fetch commands replay the source before import, resume into
an append-only destination store, and publish only a complete replayed archive.
Together with unaudited PoW parameters, the raw-seed CLI wallet, and provisional
peer routing policy, this keeps the system a local development chain rather
than a public testnet.

## Build and run

Go 1.26.7 is the pinned toolchain. With it available as `go`:

```sh
make test-all
make test-process
make test-work-rollover-soak
make test-economic-review
make build
```

`test-process` runs three real v0 QUIC server restart/sync/replay cycles, a
separate three-node v0→v1 WorkGraph enable/mine/fanout/restart cycle with one
incompatible authenticated peer, a two-observer authenticated controlled-tie
artifact delivery/restart recovery, a long-lived campaign observer killed after
durable ACK but before coordinator confirmation, an expired zero-delivery slot
followed by a convergent published slot, a kill after exactly one durable
sibling that must remain fail-closed, a two-slot version-2 campaign that restarts
one of two observers on its pinned endpoint and finishes with a healthy
multi-observer audit, a coordinator killed with one of two ACKs durably
journaled and resumed with delivery only to the missing observer, four real
filesystem permission failures bracketing coordinator rename and observer link
durability, explicit recovery of an exact post-link ACK without false chain
advance, and kills the
WorkGraph Pebble process on
both sides of commit, replay-checkpoint rotation, stale-fork pruning, and the
canonical retained-floor transition
durability boundaries. It also kills WorkGraph archive restore immediately
before directory publication and immediately after rename, requiring either no
destination or a fully reopenable and extendable database. The suite also kills
custody-record publication on both sides of its atomic link,
then runs two real `omd` custody processes, restarts the replica, and requires
the exact first proof and renewed receipt to be replayed. It also imports,
transfers, materializes, fully replays, locally recovers, and repeats an archive
object fetch after restarting the pinned source. Custody journal process tests
cover body/slot/segment crash boundaries, lost-response redelivery, two cycles
with replica restart, and local restoration of completed artifacts. Raise the
v0 QUIC soak length with, for example,
`OUTCOMEMESH_SOAK_CYCLES=25 make test-process` (hard cap: 100 cycles).
The completed campaign case also runs the read-only coordinator/observer audit
and proves that it does not rewrite the campaign journal.
`test-work-rollover-soak` runs 256 timestamp generations across four in-memory
WorkGraph nodes with a 60-second clock spread, node churn, deterministic stream
loss, full DAG convergence, and final anchor closure. Override the bounded
8..1,000 generation count with `WORKROLLOVERCYCLES=1000`.
`test-economic-review` reruns the deterministic PoW cases and the frozen
WorkGraph selfish-mining/private-fee activation corpus. `make economic-review`
emits all 847 strategy/fee points plus their canonical SHA-256 digest as JSON;
this is an external-review input, not an audit result.

Create a wallet, initialize a local chain to that wallet, mine, transfer, and
replay-verify it:

```sh
./bin/omd keygen --out alice.key
./bin/omd init --data ./data/dev --owner <address-printed-by-keygen> \
  --max-history-bytes 68719476736
./bin/omd mine --data ./data/dev --count 3
./bin/omd balance --data ./data/dev --address <alice-address>
./bin/omd transfer --data ./data/dev --key alice.key --to <recipient-address> --amount 100 --fee 1
./bin/omd verify --data ./data/dev
```

Run an authenticated development peer and synchronize another node that has the
same genesis:

```sh
./bin/omd serve --data ./data/node-a --key node-a.key --listen 127.0.0.1:9844
./bin/omd sync --data ./data/node-b --key node-b.key \
  --peer 127.0.0.1:9844 --peer-id <peer-id-printed-by-serve>
./bin/omd peers --data ./data/node-b --key node-b.key \
  --peer 127.0.0.1:9844 --peer-id <peer-id-printed-by-serve>
./bin/omd snapshot-check --data ./data/node-b --key node-b.key \
  --peer 127.0.0.1:9844 --peer-id <peer-id-printed-by-serve>
```

Run the QUIC-v1 adapter (the printed multiaddress includes the libp2p routing
ID; `--peer-id` remains the stable OutcomeMesh 32-byte ID):

```sh
./bin/omd serve-quic --data ./data/node-a --key node-a.key \
  --listen /ip4/127.0.0.1/udp/9844/quic-v1
./bin/omd sync-quic --data ./data/node-b --key node-b.key \
  --peer <multiaddress-printed-by-serve-quic> --peer-id <outcomemesh-peer-id>
./bin/omd peers-quic --data ./data/node-b --key node-b.key \
  --peer <multiaddress-printed-by-serve-quic> --peer-id <outcomemesh-peer-id>
./bin/omd auto-sync-quic --data ./data/node-b --key node-b.key --limit 8 \
  --asn-map ./current-cidr-asn.csv --max-per-asn 2
./bin/omd auto-sync-quic --data ./data/node-b --key node-b.key --limit 8 \
  --asn-map ./current-cidr-asn.csv --max-per-asn 2 --watch-interval 30s
```

The ASN file is operator-supplied local policy (`CIDR,ASN`, one mapping per
line); [docs/asn-map.example](docs/asn-map.example) is only a private-use
development fixture. The node does not bundle or silently download a production
routing dataset. Omitting `--watch-interval` keeps auto-sync one-shot.

The WorkGraph path is experimental and remains off for every ordinary command.
Enable it only on an initialized development directory after checking its exact
genesis ID (the default 12-bit development target supports the required exact
512:1 share threshold):

```sh
./bin/omd work-enable --data ./data/work-a --activation-height 2 \
  --confirm-genesis <genesis-id> --max-trees 64 \
  --max-history-bytes 68719476736
./bin/omd work-mine --data ./data/work-a --count 5
./bin/omd work-status --data ./data/work-a
./bin/omd work-balance --data ./data/work-a
./bin/omd work-verify --data ./data/work-a
./bin/omd work-serve-quic --data ./data/work-a --key node-a.key \
  --listen /ip4/127.0.0.1/udp/9845/quic-v1
./bin/omd work-sync-quic --data ./data/work-b --key node-b.key \
  --peer <multiaddress> --peer-id <outcomemesh-peer-id>
./bin/omd work-mine-quic --data ./data/work-b --key node-b.key \
  --peer <multiaddress> --peer-id <outcomemesh-peer-id> \
  --peer <second-multiaddress> --peer-id <second-outcomemesh-peer-id> \
  --count 1 --relay-every 128 --relay-interval 8s

# Or refresh, rank, and fill a bounded peer set from signed activation records.
./bin/omd work-mine-quic --data ./data/work-b --key node-b.key \
  --auto-peers 4 --auto-attempts 16 --asn-map ./current-cidr-asn.csv \
  --max-per-asn 1 --count 1
```

`work-enable` writes an immutable, fsynced profile binding network, genesis,
activation height, fee delay, tree cap, and forest-wide history budget. Once
that marker exists, ordinary v0 status/balance/verify/mining and networking
commands refuse the directory; only explicit `work-*` commands can open its
mixed chain. `work-mine` currently builds empty development payloads, but its
v1 loop mines weak shares and the hard anchor in one nonce space, commits the
bounded canonical share DAG, and reports both share counts. `work-mine-quic`
adds authenticated, best-effort publication to as many as eight explicit peers
while also accepting reciprocal shares, forwarding each first admission, and
serving chain-v1. Repeat `--peer`; either omit every `--peer-id` or supply one
matching pin after each peer. A forwarded share is never echoed directly to its
authenticated source, and the round pool prevents a duplicate from triggering
another fanout. Every peer has its own full-round bounded queue and worker,
while mining and admission callbacks perform no network I/O. A slow,
incompatible, or unreachable peer therefore cannot stop hard-PoW search or a
healthy peer's relay. Each worker sends when either 128 new shares accumulate or
the eight-second partial-batch timer fires; the time bound prevents a low-hash
miner's shares from remaining private for an entire round. Activation-aware
peer exchange and ASN-ranked routing are available only on this opt-in path.
When this miner wins,
coalesced background chain-notify-v1 prompts make the configured peers initiate
the existing trustless header-first pull; these are not trusted block pushes.
`--auto-peers` first refreshes the local book from explicit and eligible signed
bootstraps over activation-bound chain-v1. Version-1 records sign their exact
activation height and claimed capabilities; refreshed batches are validated
atomically and persisted. The selector then ranks them by reputation/latency,
applies the required operator-supplied ASN table, and performs an inventory-free
WorkGraph/exact-context capability probe. Claims never replace the live probe,
and the command fails unless the requested compatible count is reached. A
long-lived miner repeats the bounded refresh every 30 minutes through its
selected peers. Candidate order is keyed by the local identity and refresh
epoch, so a small attempt budget does not retry one fixed peer-ID prefix forever.
Transactions on the experimental path, migration tooling, and public activation
also remain gated.

`balance` reports total, spendable at the next height, and maturity-locked
amounts separately.

`init` persists the node's logical immutable-history budget (64 GiB by
default). `status` reports both current logical history bytes and the limit. A
full budget makes new block commits fail atomically while status, snapshots,
and replay verification remain available. Pebble WAL/LSM amplification and
filesystem free-space reserves are separate operator concerns.

Key files contain a raw 32-byte Ed25519 seed and are created with mode `0600`.
The CLI wallet is for development only.

## Repository map

- `core/`: deterministic consensus objects and pure execution;
- `core/chainblock/`, `core/workgraph/`, `core/workblock/`: strict cross-version
  block/header unions plus the inactive WorkGraph kernel and isolated version-1
  activation/codec/replay prototype;
- `storage/`: atomic persistent and in-memory ledger stores;
- `node/chain/`: optimistic mining, validation, and commit coordination;
- `node/activation/`: inactive strict v0/v1 boundary, cumulative-work fork
  choice, and catalog-free Pebble recovery across multiple activation bases;
- `node/chainsession/`: inactive negotiated, header-first cross-version sync
  through the activation router;
- `node/workpool/`, `node/workminer/`, `node/workround/`, `node/worksession/`:
  bounded WorkGraph gossip state, unified weak-share/hard-anchor mining,
  parent-scoped round lifecycle, and explicitly negotiated inventory-first
  relay;
- `node/workchain/`: inactive fork-aware v1 coordinator with atomic Pebble
  delta/checkpoint rotation, stale-fork pruning, opt-in canonical retained
  floors, logical history budget, restart, and reorg verification;
- `node/workarchive/`: strict content-addressed history export/replay/restore,
  multi-attestor anchors, expiring and challenge-renewed replica-custody
  receipts, and the policy gate for disabled-by-default canonical-prefix
  pruning;
- `node/mempool/`, `node/wire/`, `node/syncer/`, `node/session/`: bounded peer
  admission and transport-independent fork synchronization;
- `node/discovery/`, `node/peers/`: signed peer advertisements, bounded
  anti-replay/reputation storage, rate limits, decaying scoring, and bans;
- `node/calibration/`: crash-safe first-admission collection, signed hourly
  public-testnet telemetry chains, clustering policy, bounded manifest
  persistence, and ER-5 evidence aggregation;
- `node/snapshot/`: bounded chunk export and state-root verification without
  unsafe canonical-state import;
- `node/tieproducer/`, `node/tieexchange/`: deterministic role-labelled sibling
  production, portable pair validation/replay, and bounded authenticated
  observer delivery with durable acknowledgement recovery;
- `node/transport/`: mutually authenticated TLS/TCP fallback and bounded
  go-libp2p QUIC-v1 adapter, including distinct opt-in WorkGraph-v1 and
  activation-aware chain-v1 streams;
- `wallet/`: deterministic resource selection and guarded transaction building;
- `cmd/omd/`: standalone development CLI;
- `cmd/omreview/`: deterministic economic activation-report generator;
- `cmd/omcalibrate/`: integer-only public-testnet ER-5 evidence evaluator;
- `docs/`: protocol, architecture, security model, vectors, and gated roadmap.

See [docs/PLAN.md](docs/PLAN.md), [docs/STATUS.md](docs/STATUS.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/MINING.md](docs/MINING.md),
[docs/WORKGRAPH.md](docs/WORKGRAPH.md), [docs/SIMULATIONS.md](docs/SIMULATIONS.md),
[docs/ACTIVATION_REVIEW.md](docs/ACTIVATION_REVIEW.md),
[docs/TESTNET_TELEMETRY.md](docs/TESTNET_TELEMETRY.md),
[docs/P2P.md](docs/P2P.md), and [docs/SECURITY.md](docs/SECURITY.md).
