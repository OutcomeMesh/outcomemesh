# OutcomeMesh

OutcomeMesh is an outcome-native, proof-of-work ledger. Users authorize bounded
state outcomes instead of opaque execution paths. The protocol is being built as
an independent Go codebase: no EVM, Solidity, Bitcoin Core, Cosmos SDK, or
Substrate dependency.

The project is pre-alpha. Nothing in this repository is ready to secure real
value.

Estimated readiness for the full planned production launch: **about 44/100**.
This is a weighted engineering assessment, not a security guarantee or a count
of completed tasks. See [the baseline and remaining launch gates](docs/PRODUCTION_READINESS.md).

## Design principles

- Users sign constraints over the final state diff.
- Holders choose terms for their own transfers; agreed trade prices do not set
  a universal exchange rate. See [ownership and exchange](docs/OWNERSHIP_AND_EXCHANGE.md)
  for the current single-signer limits and future settlement requirements.
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
Incomplete targets are preserved, never overwritten or treated as ready.
An append-only backup-pin journal now selects the latest explicitly pinned
bundle and checks that each update preserves the earlier evidence. Operators
must place and protect that journal in an independent failure domain; it is not
a deployed remote pin service or a freshness guarantee. Read-only outage
reconciliation compares pinned auditor/replica backups, distinguishes stale
responses from current proof-age bounds, and reports conflicts without importing
records, changing a baseline, or authorizing a restart. A separate reviewed-ID
handoff command packages one exact historical response and verifies it against
both source bundles. Explicit application can now reconstruct a separate auditor
history, with a transfer-linked header that forbids live use. It does not alter
the original journals, refresh proof age, or fence an old participant. See
[the custody runbook](docs/CUSTODY.md) for retention rules and remaining
backup/reconciliation gates. Separate
archive-object serve/fetch commands replay the source before import, resume into
an append-only destination store, and publish only a complete replayed archive.
Together with unaudited PoW parameters, the raw-seed CLI wallet, and provisional
peer routing policy, this keeps the system a local development chain rather
than a public testnet.

Three explicit command-only prune transport commands can now serve an existing
pinned executor/coordinator or deliver a retained admission/completion outbox.
They require independently prepared and pinned inputs; they do not sign commands,
initialize journals or execute pruning. Six separate
[offline preparation commands](docs/PRUNE_PREPARATION.md) now provide explicit
new-root bootstrap, reviewed consumer/authority signing and typed outbox
preparation. Two additional explicit offline commands sign secondary operations
against the unchanged primary request and both pinned assignments. Review is
the default; neither preparation nor delivery authorizes
a live prune. See the
[prune command runbook](docs/PRUNE_COMMANDS.md) for flags, shutdown, recovery and
the remaining live-authorization gates.
[Reviewed local maintenance](docs/PRUNE_MAINTENANCE.md) can now park command
transport without unlocking journals through an opt-in macOS/Linux stdin pipe.
A separate offline command reviews existing owners or cancels before start using
an exact review ID. Separate offline recovery review/action modes can settle one
already retained intent, with no new execution or automatic next step.
Neither path executes pruning or supplies live authorization.

A separate opt-in [local archive-prune library adapter](docs/PRUNE_ACCEPTANCE.md)
now replays all selected replicas and holds each assignment's original permission
guard through deletion and confirmed result. It requires exact policy and storage
pair pins. The original mode accepts only initial receipts; a separately pinned
mode verifies complete renewal prefixes under the same current authority guards.
Bounded lineage retention, reviewed extraction
from existing journals, inventory-bound execution history and explicit local
secondary admission/completion are implemented. Source extraction requires exact
independently pinned journal checkpoints and leaves their histories unchanged.
The offline `work-prune-lineage-extract` command provides source review, exact
reviewed publication and independent retained-file verification; see the
[preparation runbook](docs/PRUNE_PREPARATION.md).
An explicit owned secondary service/CLI can receive one selected secondary's signed
commands over the existing QUIC protocols under independently pinned inventory
and peer identities. Select `admit`, `complete` or `both`; stop and drain admission
before a separate offline effect, then reopen completion without primary owners.
No mode executes pruning or automatically resumes retained work.
A separate [owned archive-effect library runtime](docs/PRUNE_EFFECT_RUNTIME.md)
opens the pinned executor, every original coordinator and position-pinned
WorkChain after command owners close. It keeps them through explicit local review,
exact reviewed execution and Close; it neither resumes Started work nor completes
tickets. The explicit `work-prune-archive-effect` CLI defaults to review and
offers a supervised control mode on macOS/Linux with dedicated stdin/stdout
pipes. It requires a reported same-session review before execution and keeps
every owner until close; existing command services must drain/close beforehand.
Activation history is opened as an existing read-only source, never initialized.
An opt-in [managed Serve library](docs/CUSTODY_SERVE_ACCEPTANCE.md) binds one
already admitted challenge to its original coordinator and existing journal.
Its guard spans signing, exact cached/recovered delivery, EOF and stream cleanup;
successful delivery does not complete the authority ticket. The separate
[managed Audit and server runtime](docs/CUSTODY_MANAGED_RUNTIME.md) retains an
unsigned intent before challenge signing, guards accepted results and exact
recovery, and provides a local pair using one original coordinator. The owned
`work-archive-custody-managed-serve-quic` CLI defaults to review and explicitly
serves under dedicated control pipes, draining handlers before owner release.
The [operator commands](docs/CUSTODY_OPERATOR_CLI.md) now prepare unsigned
intents, supervise reviewed Audit preparation/recovery/network exchanges and
run both local participants through one owned paired QUIC runtime. Review
tokens are consumed and checked again under the original guard; each paired
exchange drains both hosts and callbacks before owner release. The separate
[ticket workflow](docs/CUSTODY_TICKET_WORKFLOW.md) prepares exact-position
consumer commands and authority co-signatures, captures the committed current
journal result, and explicitly applies Audit/Serve admissions and completions.
Uncertain attempts require a separately reviewed resume. In-place transfer and
physical/cross-host enforcement remain open.

The opt-in [remote acceptance procedure](docs/REMOTE_ACCEPTANCE.md) now has
[recorded two-VPS evidence](docs/evidence/remote-acceptance-20261027.json): five
custody scenarios cover real QUIC, partitions around the replica commit, exact
recovery, loss/delay and expired-proof refusal. A separate devnet run checks
restart, divergent branches and full replay after reorganization. Each custody
participant retains a different local assignment and original owner; this does
not establish distributed current authority for one assignment.

The separate [remote authority foundation](docs/REMOTE_AUTHORITY_FOUNDATION.md)
adds an opt-in version-1 assignment whose original owner retains an unresolved
remote execution across restart. A record-only worker journal seals delayed
starts permanently, while drain never implies successful custody or completion.
The opt-in [managed remote protocol](docs/REMOTE_CUSTODY_EXECUTION.md) now adds
confirmed-owner Start, an independently pinned data exchange, irreversible
handler drain and a typed terminal checked against the original accepted A
journal. Drain and the two ticket completions remain explicit separate actions.
The [remote operator/server commands](docs/REMOTE_CUSTODY_OPERATOR.md) now provide
default non-executing review, supervised owned control and retained sealed/terminal
artifacts. Separate [V1 offline preparation commands](docs/REMOTE_CUSTODY_OFFLINE.md)
create assignments, authority/worker roots and plans, and review/sign/co-sign
admissions, Begin proposals and successful completions. The [position-zero CLI
workflow](docs/REMOTE_CUSTODY_BOOTSTRAP.md) now also creates local source journals,
applies initial admissions and prepares their exact challenge under original
guards. The [V1 WAN campaign](docs/REMOTE_CUSTODY_WAN.md) now covers eleven
controlled scenarios on two hosts, including 32 cycles on one assignment and
the original source journals. Unknown/expired/unseen outcomes retain their
ordinary tickets. Negative-disposition closure, independently enforced key/root copy
fencing and the wider production gates remain open.

The [negative observation workflow](docs/REMOTE_CUSTODY_NEGATIVE.md) now records
signed Unseen/unknown/unaccepted-result evidence against the original A source,
including export and historical verification of B's complete retained entry.
Capture keeps both ordinary tickets pending. An explicit, separately signed
administrative Audit completion can now close that observation while the
original Serve obligation remains pending, blocking retirement. The experimental
[independent witness foundation](docs/CUSTODY_FENCE.md) adds durable quorum vote
locks and unknown-outcome rules. An experimental
[witness network and CLI](docs/CUSTODY_WITNESS_NETWORK.md) now serves those journals,
assembles quorum certificates and binds complete historical custody results.
The separate experimental [custody V2 job path](docs/CUSTODY_V2.md) now mandates
assignment witness policy, a signed derived job, live-session claim consumption
at the actual target, and a full result quorum before original-source acceptance.
Its CLI supports preparation through exact crash recovery. [Typed Serve](docs/CUSTODY_V2_SERVE.md),
[shared admission](docs/CUSTODY_V2_ADMISSION.md) and the signed
[required profile](docs/CUSTODY_V2_REQUIRED.md) bind accounting to original owners.
[Retained proof delivery](docs/CUSTODY_V2_DELIVERY.md) provides authenticated
inbox/outbox distribution and explicit recovery before separate owner creation.
The [resource registry foundation](docs/CUSTODY_REGISTRY.md) separately records
one jointly signed assignment selection under an independently pinned anchor;
its format-1 certificates remain selection-only. The fresh
[registry-bound profile](docs/CUSTODY_V2_ENROLLED.md) requires a format-2 selection
and complete admission proof at profile-4 owners and their effect boundaries;
it cannot promote an existing selection or migrate a legacy owner.
[Enrolled proof delivery](docs/CUSTODY_V2_ENROLLED_DELIVERY.md) transports both
complete proofs with durable acknowledgement and explicit owner handoff.
The [disabled legacy review CLI](docs/CUSTODY_CUTOVER_REVIEW.md) now verifies
complete retired V1 histories, observes original A/B sources and retains a signed
transition proposal without refunding spent allowance. It enables no source or
spending import by itself. The separate [imported accounting path](docs/CUSTODY_IMPORTED_ACCOUNTING.md)
now carries spending/source/retention into selected profile-5 admission witnesses,
with one shared registry choice across native and imported successors. The
[sealed source handoff](docs/CUSTODY_SOURCE_HANDOFF.md) retains the selected
successor in original A/B journals and closes their legacy access. Protected
old-grant exclusion against root/VM copies and independent deployment remain
gated. The experimental
[isolated source gateway](docs/CUSTODY_GATEWAY.md) performs original-source
inspection and chunk reads with a fresh private key, separate Linux participant
UID, exact request positions and permanent revocation. Imported job execution
now runs through the [explicit protected Plan5 adapter](docs/CUSTODY_PROFILE5_EXECUTION.md),
with real archive proofs, source continuation and protected A/B closure; raw
constructors stay blocked. Root/whole-service-VM protection and independent
deployment remain gated. The [joint two-host V2
fault campaign](docs/CUSTODY_V2_WAN.md) covers lost replies, process kills,
quorum outages and expired results, with public signed evidence and original
source checks.
The optional
[local placement profile](docs/REMOTE_CUSTODY_PLACEMENT.md) checks independently
pinned original roots, permanent locks and operator key files across restart.
It detects ordinary copies/replacements; independent raw-key/VM-copy fencing
still requires a protected issuer and mandatory protocol validation.

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
with replica restart, and local restoration of completed artifacts. Backup-pin
tests kill the process before and after pin publication and exercise CLI
selection of a newer backup containing an uncommitted signed request. Raise the
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
- `node/custodyfence/`: experimental independently pinned witness quorum and
  durable proposal locks and versioned session commitments;
- `node/custodyv2/`: experimental witness-mandatory jobs, target/acceptor owners,
  bounded QUIC and typed source receipts; production deployment remains gated;
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

## Contributing and license

See [Contributing to OutcomeMesh Core](CONTRIBUTING.md) for development,
review and security reporting. Project-owned code is available under the
[MIT License](LICENSE). Dependencies and separately licensed material retain
their own copyright and license terms.
