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
an isolated version-1 block-transition prototype exist but are not activated.

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

The unpruned block/delta history, unaudited PoW parameters, raw-seed CLI wallet,
and provisional peer routing policy make this a local development chain, not a
public testnet.

## Build and run

Go 1.26.7 is the pinned toolchain. With it available as `go`:

```sh
make test-all
make test-process
make build
```

`test-process` runs three real QUIC server restart/sync/replay cycles and kills
the WorkGraph Pebble process on both sides of its durable batch boundary. Raise
the opt-in QUIC soak length with, for example,
`OUTCOMEMESH_SOAK_CYCLES=25 make test-process` (hard cap: 100 cycles).

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
- `node/activation/`: inactive strict v0/v1 boundary and cumulative-work fork
  choice across multiple activation bases;
- `node/workpool/`, `node/workminer/`, `node/worksession/`: inactive bounded
  WorkGraph gossip state, unified weak-share/hard-anchor mining, and explicitly
  negotiated inventory-first relay;
- `node/workchain/`: inactive fork-aware v1 coordinator with atomic Pebble
  delta/checkpoint rotation, stale-fork pruning, logical history budget,
  restart, and reorg verification;
- `node/mempool/`, `node/wire/`, `node/syncer/`, `node/session/`: bounded peer
  admission and transport-independent fork synchronization;
- `node/discovery/`, `node/peers/`: signed peer advertisements, bounded
  anti-replay/reputation storage, rate limits, decaying scoring, and bans;
- `node/snapshot/`: bounded chunk export and state-root verification without
  unsafe canonical-state import;
- `node/transport/`: mutually authenticated TLS/TCP fallback and bounded
  go-libp2p QUIC-v1 adapter, including an opt-in isolated WorkGraph-v1 stream;
- `wallet/`: deterministic resource selection and guarded transaction building;
- `cmd/omd/`: standalone development CLI;
- `docs/`: protocol, architecture, security model, vectors, and gated roadmap.

See [docs/PLAN.md](docs/PLAN.md), [docs/STATUS.md](docs/STATUS.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/MINING.md](docs/MINING.md),
[docs/WORKGRAPH.md](docs/WORKGRAPH.md), [docs/SIMULATIONS.md](docs/SIMULATIONS.md),
[docs/P2P.md](docs/P2P.md), and [docs/SECURITY.md](docs/SECURITY.md).
