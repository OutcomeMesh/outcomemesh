# OutcomeMesh Core

OutcomeMesh is a proof-of-work network built around explicit changes to owned
resources. A transaction names the resources it consumes, the resources it
creates and the conditions that must hold for execution. Nodes verify the same
canonical data and derive the same state independently.

This repository contains the Go implementation of the protocol, node, mining
software and operator CLI.

**Status: pre-alpha.** Current builds are for development networks. Mainnet has
not been activated, and the software is not ready to secure assets of real
value. Estimated readiness for the planned production launch is **44/100**.
The [readiness assessment](docs/PRODUCTION_READINESS.md) records the remaining
launch requirements; the score is an engineering estimate.

## Protocol

Resources have an identity, owner, asset, amount and version. A signed transaction
consumes specific resource versions and declares its outputs. GuardVM evaluates
bounded conditions during deterministic execution. Ownership authorizes changes
to a holder's resources; it does not grant control over network rules or set a
universal exchange rate. The current transaction format uses a single signer.

WorkGraph records work as a graph of shares attached to a hard proof-of-work
anchor. Fork choice uses cumulative hard work. Once WorkGraph is active, an
exact-work tie preserves the incumbent branch. Rewards for an anchor and its
included shares enter state in the following block. Collected fees pass through
a delayed queue maintained separately for each branch.

The state commitment has two formats. The original format remains available for
existing chains. The radix format updates the affected tree paths and reads the
cached root without rehashing every resource. WorkGraph adopts this format only
at an explicitly configured height.

| Block version | Chain mode | State commitment |
| --- | --- | --- |
| 0 | Standalone ledger | Original commitment |
| 1 | WorkGraph | Original commitment |
| 2 | Standalone ledger with protocol-2 genesis | Radix commitment v1 |
| 3 | WorkGraph at or above its radix activation height | Radix commitment v1 |

Protocol rules and byte encodings are specified in [PROTOCOL.md](docs/PROTOCOL.md).
The [WorkGraph specification](docs/WORKGRAPH.md) covers mining and accounting.

## Implementation

| Component | Current scope |
| --- | --- |
| Execution | Signed transactions, typed resources, bounded GuardVM and deterministic receipts |
| Consensus | Proof of work, integer difficulty adjustment, fork choice and delayed WorkGraph accounting |
| State | Immutable resource and account indexes, versioned commitments and local radix proofs |
| Storage | Atomic persistent commits, retained forks, historical replay and replay checkpoints |
| Networking | Authenticated peer connections, QUIC transport, bounded relay and chain synchronization |
| Wallet | Key generation, encrypted wallet files, balance lookup and constrained transfers |
| Archive custody | Experimental archive verification, retained-result recovery and protected operator workflows |
| Operations | CLI, activation profiles, offline migration and release packaging |

Archive custody remains a separate operational subsystem. Its protections depend
on the configured owners, witnesses, services and deployment boundaries. The
archive formats support a scheduled WorkGraph v3 chain. Local custody owners
can migrate active Audit/Serve tickets while preserving original receipt history.
New Audit/Serve admissions and reviewed completion preserve that same accounting.
Scheduled pruning verifies the live storage quorum and complete archives before
removing old history, with retained effects for recovery. Its CLI covers plan
preparation, separate signatures, admission, execution and per-replica completion.
Original obligations and spent operation IDs remain in their existing journals.
[Original Prune outcomes](docs/PRUNE_MIGRATED_OUTCOMES.md) can be resolved after
migration using their retained results or an explicit cancellation before start.
Remote execution still
requires its own schedule integration. The [custody migration guide](docs/CUSTODY_RADIX_SCHEDULE.md)
describes the supported path and its limits.

## Build

Use Go **1.27.3**. The repository pins this version for development and official
binary builds.

```sh
git clone https://github.com/OutcomeMesh/outcomemesh.git
cd outcomemesh
make build
./bin/omd version --json
```

Official binary targets are Linux and macOS on amd64 and arm64. Packaging,
checksums and provenance are described in [RELEASES.md](docs/RELEASES.md).

## Run a local chain

Create a private passphrase file containing 12 to 1024 bytes with permissions
`0600`. Keep it outside the repository and node data directory. The wallet uses
the exact file contents, including any final newline.

```sh
./bin/omd keygen --out alice.key --passphrase-file /private/location/alice.pass
./bin/omd init --data ./data/dev --owner <address-printed-by-keygen>
./bin/omd mine --data ./data/dev --count 3
./bin/omd balance --data ./data/dev --address <alice-address>
./bin/omd verify --data ./data/dev
```

To create a separate standalone chain with radix state, pass
`--protocol-version 2 --network <unused-network-id>` to `init`. Existing genesis
files cannot be changed to select another protocol version.

For a transfer, use an owned spendable resource balance and the recipient's
address:

```sh
./bin/omd transfer --data ./data/dev --key alice.key \
  --passphrase-file /private/location/alice.pass \
  --to <recipient-address> --amount 100 --fee 1
```

See [WALLET_KEYSTORE.md](docs/WALLET_KEYSTORE.md) for encryption, backups and
conversion of older key files. Daemon identities are separate from wallet keys.
Peer setup and routing policy are documented in [P2P.md](docs/P2P.md).

## Enable WorkGraph

WorkGraph uses explicit `work-*` commands. On a fresh development directory,
choose activation heights above the retained legacy history and confirm the
exact genesis ID printed by `init` or `status`:

```sh
./bin/omd init --data ./data/work --network 3103 --owner <alice-address>
./bin/omd work-enable --data ./data/work --activation-height 2 \
  --radix-height 5 --confirm-genesis <genesis-id>
./bin/omd work-mine --data ./data/work --count 6
./bin/omd work-status --data ./data/work
./bin/omd work-verify --data ./data/work
```

This example starts with protocol-0 genesis, activates WorkGraph v1 at height 2
and switches to v3 at height 5. Omit `--radix-height` to retain WorkGraph v1. With
a protocol-2 genesis, the radix height must equal the WorkGraph activation height.
All peers must agree on the same genesis and activation schedule.

An existing WorkGraph directory uses `work-migrate-radix`. Stop the node, review
the proposed migration and run it with the returned review ID. The command
replays retained history into a fresh directory and preserves the source.
Follow [the migration procedure](docs/WORKGRAPH_RADIX_MIGRATION.md) before moving
an existing chain. Archive successors and protected stores have a separate
[reviewed migration procedure](docs/RADIX_ARCHIVE_STORAGE_MIGRATION.md), which
retains original obligations and position journals. Publishing a local profile
does not activate a public network.

## Repository layout

| Path | Purpose |
| --- | --- |
| `core/` | Consensus types, encodings, state transitions, commitments and mining rules |
| `node/` | Peer services, WorkGraph coordination, archives and custody operations |
| `storage/` | Persistent ledger and reference storage |
| `wallet/` | Wallet keys, signing and transaction construction |
| `cmd/` | Node and supporting command-line programs |
| `sim/` | Protocol and economic models |
| `scripts/` | Build, release and operator tooling |
| `docs/` | Specifications, operating procedures and development records |

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Development plan](docs/PLAN.md) and [implementation status](docs/STATUS.md)
- [Production readiness](docs/PRODUCTION_READINESS.md)
- [Mining](docs/MINING.md) and [ownership and exchange](docs/OWNERSHIP_AND_EXCHANGE.md)
- [Radix state commitment](docs/STATE_RADIX_V1.md) and [WorkGraph migration](docs/WORKGRAPH_RADIX_MIGRATION.md)
- [Custody operator CLI](docs/CUSTODY_OPERATOR_CLI.md) and [guard deployment](docs/CUSTODY_GUARD_DEPLOYMENT.md)
- [Security model](docs/SECURITY.md) and [vulnerability reporting](SECURITY.md)

## Contributing and license

Read [Contributing to OutcomeMesh Core](CONTRIBUTING.md) before proposing a change.
Protocol changes require an explicit compatibility decision and updates to the
specification. Report security issues through the private channel in
[SECURITY.md](SECURITY.md).

OutcomeMesh Core is distributed under the [MIT License](LICENSE).
