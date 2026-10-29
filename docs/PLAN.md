# OutcomeMesh implementation plan

Status: active
Protocol maturity: research / pre-alpha
Implementation language: Go 1.27.3
Initial build mode: pure Go, `CGO_ENABLED=0`

## Execution rules

This plan is intentionally gate-driven. A later milestone may be researched in
parallel, but it must not be integrated into the protocol until every exit gate
of the preceding milestone is satisfied.

Every consensus-affecting change must include:

1. a written rule in `docs/PROTOCOL.md`;
2. canonical encoding test vectors;
3. positive and negative unit tests;
4. a fuzz target for any new decoder or interpreter surface;
5. an explicit compatibility decision;
6. a security note when an invariant or trust assumption changes.

No milestone is complete because the code merely compiles. Completion requires
the stated safety properties and reproducible tests.

Progress reports end with an approximate production-readiness score out of 100,
using `PRODUCTION_READINESS.md`. The denominator is this full launch plan, not
the current slice. Small completed tasks do not automatically increase the score;
an estimate never overrides an unpassed exit gate.

## WorkGraph state commitment slice (2026-10-29)

Implemented: explicit block v3 activation, radix receipts, persistent fork and
checkpoint reconstruction, schedule negotiation and reviewed offline migration
of complete unbound histories. See [the transition specification and operating
procedure](WORKGRAPH_RADIX_MIGRATION.md). Existing v0/v1 commitments remain valid
under their original rules.

Remaining work, in order:

1. Complete schedule-bound custody receipt, admission and retention continuity
   before enabling new canonical pruning on migrated protected stores. Manifest
   v2, statement/checkpoint v1, same-prefix archive migration and an in-place
   original-position-journal transition are implemented; see
   [archive and protected-storage migration](RADIX_ARCHIVE_STORAGE_MIGRATION.md).
   Existing effects, floors and custody evidence are retained. Managed custody
   owners do not yet switch their active binding to the new schedule.
2. Define the independently approved network activation policy and transition
   checkpoint; local operator profiles alone do not authorize public activation.
3. Extend migration beyond the initial bounded history, with resumable streaming
   and durable progress that cannot publish partial state.
4. Reduce persistent diff derivation and snapshot materialization costs, then
   establish operational resource limits for the full node.

This slice does not close M5 or any mainnet launch gate.

## Active custody V2 integration slice (2026-10-27)

The separate experimental V2 path now mandates assignment witness policy,
derived signed job scope, volatile-session claim consumption at the real target,
typed result quorum and original-source acceptance with explicit crash recovery.
See [CUSTODY_V2.md](CUSTODY_V2.md) for rules and remaining trust boundaries.

Next required work remains ordered:

1. The controlled [joint two-host V2 matrix](CUSTODY_V2_WAN.md) now covers
   reply cuts, process failures, cold persistent copies and witness outages.
   Next deploy independently operated/protected domains, retain original witness
   pins outside participant backups and extend adversarial acceptance there.
2. The [typed V2 Serve disposition](CUSTODY_V2_SERVE.md) now covers fulfilled
   work and original-quorum no-claim cancellation, with original-owner A/B
   application, explicit recovery and retained archive deadlines. Unknown or
   B-only expired results remain held. The adapter cannot clear existing V1
   Serve tickets. A dedicated typed Serve RPC is not part of that CLI slice.
3. The [assignment-wide admission coordinator](CUSTODY_V2_ADMISSION.md) now
   shares two-unit lifetime/pending accounting across job Plans, with typed
   witness quorums, permanent deduplication and full Serve A/B closure evidence.
   The [signed required profile](CUSTODY_V2_REQUIRED.md) now binds a complete
   Admit prefix to original Target/Acceptor owners, rejects raw-owner bypass,
   consumes binding/admission IDs before current archive-object reads and retains
   exact acceptance/Serve/accounting recovery. Legacy policy 2 is unchanged;
   this does not activate or migrate it. [Durable proof delivery](CUSTODY_V2_DELIVERY.md)
   now retains exact inbox/outbox intents, authenticated recipient acknowledgements
   and explicit cold recovery without creating execution owners. Next complete
   protected enrollment and activation/cutover registry rules. The
   [one-choice registry foundation](CUSTODY_REGISTRY.md) now fixes one experimental
   profile-3 candidate under a stable externally provisioned resource anchor,
   with a separate descriptor pin, three-role agreement and permanent quorum
   selection. It grants no activation or profile upgrade; physical anchor
   uniqueness and the version/accounting bridge remain required. The
   [new enrolled profile](CUSTODY_V2_ENROLLED.md) now mandates the full registry-2
   selection and admission proofs at profile-4 owner creation/open and effect
   consumption. Registry-1 histories cannot be promoted or reset; protected
   issuance and old-grant exclusion remain required. The separate
   [profile-4 proof delivery](CUSTODY_V2_ENROLLED_DELIVERY.md) now retains both
   complete proofs with exact retry and explicit owner handoff. Joint WAN
   fault acceptance accompanies that path; protected independent deployment
   remains required. The explicit imported adapter is described below. [Legacy cutover
   rules](CUSTODY_V2_MIGRATION.md) now have a separate
   [disabled review CLI](CUSTODY_CUTOVER_REVIEW.md): complete retired histories,
   original-source observations, no-refund arithmetic and signed durable
   preparation. The [imported accounting stage](CUSTODY_IMPORTED_ACCOUNTING.md)
   now derives a policy-5 successor, carries spent/source/retention into original
   admission witnesses and shares the existing registry-2 slot across native and
   imported choices. The sealed original-source handoff now closes legacy access under original
   A/B guards. The [isolated source gateway](CUSTODY_GATEWAY.md) now owns a
   fresh key and original storage under a separate Linux UID, with exact signed
   per-action positions, durable replies and irreversible issuer revocation.
   The [protected Plan5 adapter](CUSTODY_PROFILE5_EXECUTION.md) now performs real
   archive execution, retained source continuation, protected A acceptance and
   Serve/admission closure inside explicitly configured service owners. It binds
   both service identities and original enrollment to each job, retains the
   inherited spending/source/retention and rejects bare old role proofs. Raw
   profile-5 constructors and accounting-only Plan2 execution still refuse.
   The [joint profile-5 WAN campaign](CUSTODY_PROFILE5_WAN.md) now covers actual
   A/B execution, packet partitions, process death, exact recovery and original
   admission closure across two hosts. Lost sessions remain held. The [independent guard adapter](CUSTODY_INDEPENDENT_GUARD.md)
   now makes external one-choice seals mandatory in explicitly guarded deployments,
   including full original admission prefixes and service/Serve results. Separately
   authorized permanent per-subject revocation now reserves durable journal space,
   returns exact signed receipts and survives lost replies/process death through
   reviewed CLI recovery. Previously signed proofs remain historical; unknown work
   stays held. [One-generation key replacement](CUSTODY_KEY_REPLACEMENT.md) now
   preserves logical subjects, original witness/service histories, spent/pending
   accounting and unknown outcomes through reviewed successor enrollment and
   activation. New service descriptors pin guarded outer responses from creation.
   The [two-host deployment](CUSTODY_GUARD_DEPLOYMENT.md) separates UIDs and uses
   authenticated tunnels, but shares administrative control. [Retained-result
   consent](CUSTODY_RETAINED_ACCEPTANCE.md) now closes delayed verifiable results
   through original Serve/admission accounting. Outcomes without a complete
   result remain held. [Evidence recovery](CUSTODY_EVIDENCE_RECOVERY.md) now returns
   original completed result, acceptance and Serve receipts through the protected
   service, including after closure, without changing execution obligations.
   Next deploy outside all participant backup/control domains
   with independent operators and protected monotone/key storage, finish unknown-outcome settlement and
   further key generations without resetting prior obligations,
   extend physical-failure and long-retention acceptance
   and obtain independent review. No consensus/mainnet activation follows.
4. Specify safe progress for split votes and its quorum/rollback assumptions;
   never reset a retained slot to recover availability.
5. Establish protected execution/key deployment, activation/migration rules and
   independent review before connecting these experimental jobs to mainnet.
6. Complete the existing M5–M10 audit, economics, calibration and sustained
   adversarial public-testnet exit gates. No software slice waives those gates.

The [state/index work](STATE_SCALING.md) preserves v0 commitments while reducing
diff, balance and canonical-height costs. [Encrypted wallet keys](WALLET_KEYSTORE.md)
provide explicit seed migration. [Protocol 2](STATE_RADIX_V1.md) now selects an incremental commitment for explicit
new standalone chains. Existing-chain migration, WorkGraph integration, physical
storage operations and a reviewed user wallet remain launch work.

## Product thesis

The initial product is a native ledger where a user signs both a resource
transition and a bounded GuardVM program. The transaction is accepted only when
the actual post-state satisfies that program.

The long-term product is an agent-native settlement network with:

- open proof-of-work participation;
- protocol-accounted weak work shares;
- capability-limited accounts;
- encrypted outcome batches;
- permissionless solver competition;
- stateless verification;
- optional succinct execution proofs;
- paid archival storage.

The protocol must demonstrate value as a safe execution kernel before a public
token or mainnet launch is considered.

## Milestone 0: specification foundation

### Deliverables

- Architecture boundaries and dependency policy.
- Consensus and execution invariants.
- Versioned transaction and resource formats.
- Threat model and failure taxonomy.
- Repository layout and reproducible developer commands.

### Exit gates

- All consensus objects have an owner, version, and canonical representation.
- The state transition can be described without referencing a database, network,
  goroutine schedule, or wall clock.
- Deferred features are explicitly excluded from protocol version 0.

## Milestone 1: deterministic kernel

### Scope

Protocol version 0 supports a single-signer resource transfer with explicit
inputs, outputs, fee, expiry height, and a GuardVM program.

### Deliverables

- Fixed-size consensus primitives.
- Checked amount arithmetic.
- Canonical encoder and strict decoder.
- Resource and transaction validation.
- Ed25519 authorization.
- Bounded, loop-free GuardVM.
- Reference in-memory state.
- Atomic state transition and deterministic reference state root.
- Golden vectors, unit tests, and fuzz targets.

### Safety invariants

- A resource is consumed at most once.
- A transaction cannot create value.
- Every input is authorized.
- Failed execution changes no state.
- The state root is independent of insertion order.
- A GuardVM failure rejects the entire transaction.
- Unknown versions and opcodes fail closed.

### Exit gates

- `go test ./...` passes with the race detector.
- Fuzz smoke tests cover codec, transaction decode, and GuardVM decode/execute.
- Reordering map insertion produces the same state root.
- Random invalid transitions never mutate the pre-state.
- Test vectors are stable across repeated runs.

## Milestone 2: signed ledger and blocks

### Deliverables

- Genesis document and genesis state root.
- Block body and header formats.
- Transaction Merkle root and receipt root.
- Block execution over a state snapshot.
- Atomic block commit and crash recovery.
- Chain database schema using Pebble.
- Reference storage implementation for differential testing.

### Exit gates

- Killing the node at every write boundary recovers either the old or new block,
  never a partial state.
- Replaying the same chain from genesis produces identical roots.
- Pebble and reference storage produce identical results.

## Milestone 3: single-node proof of work

### Deliverables

- Replaceable PoW engine interface.
- SHA-256 development PoW.
- Header difficulty target validation.
- ASERT-style difficulty adjustment specification and implementation.
- Cumulative-work fork choice.
- Coinbase/resource issuance rules.
- Standalone node, miner, wallet, and CLI binaries.

### Exit gates

- A clean machine can create genesis, mine, transfer, restart, and resync.
- Invalid difficulty, timestamp, issuance, or state roots are rejected.
- Fork-choice simulations cover timestamp manipulation and variable hash rate.

## Milestone 4: peer-to-peer devnet

### Deliverables

- go-libp2p QUIC-v1 transport with authenticated peer identity. QUIC uses its
  native TLS 1.3 security; Noise is reserved for non-QUIC libp2p transports.
- Peer discovery, peer scoring, and connection limits.
- Transaction, block, header, and state synchronization protocols.
- Bounded mempool with deterministic admission rules.
- Snapshot sync with root verification.
- Four-to-seven-node local devnet harness.

### Exit gates

- Nodes converge after partitions, duplication, delay, and message reordering.
- Invalid peers cannot cause unbounded memory, CPU, disk, or goroutine growth.
- A new node syncs without trusting a snapshot provider.

## Milestone 5: WorkGraph and native share accounting

### Deliverables

- Weak Work Share format and difficulty.
- Recent-share DAG validation.
- Anchor commitment to accepted shares.
- Reward maturity and proportional payout calculation.
- Orphan, withholding, and selfish-mining simulator.
- Inclusion commitments carried by work shares.
- Bounded explicit multi-peer relay with independent backpressure and verified
  anchor synchronization.
- Count-or-time share flushing with a deterministic small-miner reward corpus.
- A versioned multi-attestor archive anchor bound to the exact selected
  WorkChain ancestry, followed separately by a content-addressed restorable
  export, expiring independently keyed replica-custody receipts, and an atomic
  canonical retained-floor transition. Successive generations must be
  composable from the exact retained predecessor archive plus the executable
  suffix, without restoring pruned chain payloads. Published chunk boundaries
  and IDs must remain stable across those generations so a content-addressed
  replica transfers only missing suffix objects through bounded, canonical,
  manifest-bound requests and batches over identity-pinned, allowlisted,
  independently rate-limited transport sessions, then fully replays the
  materialized archive before publication. Fresh retention must be renewable
  only through a signed, freshness-bounded random-sample challenge whose
  deterministic manifest sample, returned-byte proof, predecessor receipt, and
  requested term are linked into a versioned receipt over a separate pinned,
  allowlisted, rate-limited transport scope. Repeated custody cycles must derive
  their state from an immutable policy-bound evidence journal, commit each
  response before delivery, recover interrupted publication, and serialize
  append/replay/segment rotation across processes. Timer-driven invocations must
  retry the exact unfinished challenge and preserve completed evidence during
  segmentation. Local disk growth must account for bodies, slots, temporary
  links, orphan evidence, and rotation directories before publication, preserve
  replay and committed retries after a limit reduction, and bound replay's path
  inventory. Evidence-retention policy and long-outage reconciliation remain
  separate gates. An anchor alone must never authorize deletion or override
  hard-work fork choice; canonical pruning is
  explicit local finalization and remains disabled by default.

  Custody storage follow-through:

  - [x] Journal byte/path admission limits, crash-completion reserve, usage
    reporting, and reduced-limit recovery tests.
  - [x] Define non-deleting evidence retention and cold-backup/independent-pin
    requirements, including the separate auditor artifact directory. Add paired
    canonical checkpoints, exact-copy verification without repair, whole-cycle
    auditor locking, and a pending-record restore drill. No automatic deletion.
  - [x] Managed local backup publication under the source locks: independent
    file copies, fsync and full replay before the final checkpoint marker,
    no-replace destinations, exact completed retries, preserved incomplete
    attempts, process-kill tests, and a pending-cycle restore drill.
  - [x] Local tooling for independently stored backup pins: bounded append-only
    pin history, explicit compare-and-append, exact committed retries, full
    verification of both bundles, and preservation of previously pinned chain,
    orphan bodies, pending files, and auditor artifacts. Add latest-pin CLI
    verification, concurrent-update and process-kill tests. No deletion or
    automatic fallback to an older backup.
  - [ ] Deploy and maintain the independent pin failure/access-control domain,
    cross-host cutover review, scheduled backup/pin operations, and deployment-
    scale restore drills. Local bundle and pin tooling do not establish physical
    independence, external freshness, or safe participant cutover.
  - [ ] Explicit long-outage reconciliation/rebaseline without silently replacing
    an expired challenge or discarding the previous evidence chain.
    - [x] Read-only comparison of independently pinned auditor/replica backups:
      exact common prefix, pending intent/response matching, retained-evidence
      blockers, and historical validity separated from proof/receipt freshness.
    - [x] Prepare, explicitly select by ID, export, and verify a bounded
      historical-response handoff package. Require the exact pinned common
      prefix, one replica-committed next entry, and matching auditor intent.
      Preserve source trees and incomplete attempts; test concurrent exports,
      tampering, and process kills before/after publication. This is offline
      packaging, not journal import or participant fencing.
    - [x] Apply one reviewed historical entry to a separate, no-replace auditor
      reconstruction. Write a transfer-linked historical-only header before
      copying journal payloads; reject live open, append, rotation, and journal
      serving. Verify the exact source-plus-entry/artifact delta, preserve
      incomplete attempts, and test pre/post-commit crashes and live CLI refusal.
    - [x] Linked, short-lived rebaseline proposals following a fresh full archive
      replay and verification of the pinned historical reconstruction. Bind the
      previous receipt, new replica/location, and disjoint new auditor policy;
      sign only in a proposal-specific domain. Require independent review inputs,
      recheck expiry after replay, and preserve immutable proposal files. No live
      receipt, challenge, journal writer, or activation is created.
    - [x] Managed local participant retirement: hold the permanent journal lock
      across the whole auditor cycle and replica response, including cached
      replies; verify both exact pinned inventories before retiring either root.
      Publish proposal-linked no-replace tombstones, preserve every old byte,
      and complete a crashed pair only from its original durable intent. Keep
      retired evidence replayable/backuppable but reject live open, stale handles,
      signing scopes, append, rotation and cached serving. Cover concurrent calls,
      expiry/rollback, partial-state drift, process kills and actual CLI restarts.
    - [ ] Cross-host authority/acceptance enforcement and active rebaseline:
      local tombstones cover only the named roots and upgraded journal-backed
      participants. They do not revoke copied keys, rolled-back roots, legacy
      unjournaled services, or another host's acceptance policy. Establish an
      independently authoritative retirement decision at every acceptance path,
      then one crash-safe activation linked to the reviewed proposal. Test stale
      and partitioned/restarted remote participants before allowing any cutover.
      - [x] Final deletion-time authorization boundary: live wall-clock samples
        after replica replay/publication and inside WorkChain's prepared batch;
        fail closed on expiry, insufficient remaining term, cancellation, and
        backwards time. Preserve immutable availability evidence on failed
        attempts. This does not distribute or enforce remote revocations.
      - [ ] Implement the current-authority and drain protocol described in
        `CUSTODY_AUTHORITY.md`; cover every listed live acceptance path without
        changing historical verification into a freshness claim.
        - [x] Bounded reference admission/drain kernel: independently pinned
          assignment, separated control/evidence keys, signed compare-and-append
          entries, explicit operation tickets, immutable stop intent and terminal
          retirement only after every consumer closes its pending work. Preserve
          completed IDs and drain capacity; require exact pinned replay. Cover
          role/shape/binding rejection, concurrent admission, canonical vectors,
          codec fuzzing and an independent small state-machine model.
        - [x] Local durable authority history: serialize validation/publication/
          apply under a lifetime process lock, sync immutable entries before
          returning results, and replay against independent exact pins. Recover
          only the prior pin or one exact uncertain attempt; retain pending work,
          reject altered/partial history and poison failed writers. Cover 45
          process-kill boundaries. Never bootstrap an empty authority on missing
          history. Independent pin/intent deployment and physical power-loss
          campaigns remain external gates; results are not live permissions.
        - [x] Local retained authority positions and append intents: persist the exact
          attempted entry before issuing it, advance independent pins only after
          a verified durable result, and recover ambiguous outcomes without
          inferring the expected head from the authority root. Keep at most one
          pending intent, never repair confirmed missing history, and require
          explicit resume after non-submitting open. Cover cancellation, root
          aliases, malformed pins, concurrency and 129 coordinator process kills.
          Independent failure/access-control deployment and a managed runtime
          service remain separate; local results are not consumer permissions.
        - [ ] Current-authority transport and durable consumer operations: no
          stale-snapshot fallback, no duplicate effect on retry/restart, and no
          completion before the final effect has drained. Enforce at every
          audit/serve/prune acceptance path and test real partitions.
          - [x] Atomic local prune effect: retain the exact assignment/ticket/
            requested floor, final authorization time and original result in the
            same synchronous WorkChain batch as deletion. Keep completed results
            across later maintenance; exact retries only return evidence, and
            conflicting ticket reuse fails. Bound retained results, account for
            their bytes, reject inconsistent recovery and poison uncertain
            canonical commits. Cover concurrent retries and four process-death
            boundaries. This trusted primitive is not live authority enforcement.
          - [x] Bounded one-assignment local prune executor: retain the exact
            request before admission, bind its ID into the signed operation,
            and hold the private coordinator's pending-ticket guard through
            durable start, concrete WorkChain pruning and durable result. Never
            rerun a retained start; resolve only a matching existing chain effect.
            Keep unknown outcomes pending, require separate signed completion,
            and cover 26 process-death boundaries plus local stop/result races.
            This is a trusted library, not live archive-policy enforcement or
            protection against journal/database rollback.
          - [x] Optional independently retained local consumer-stage journal:
            write each exact transition intent before the executor record, then
            confirm its durable publication. Bind two new disjoint roots, refuse
            raw reopening or fresh-pin attachment, and retain both lifetime locks.
            Open only the exact confirmed prefix or one known unconfirmed next
            transition; never reconstruct confirmed missing history. Require
            explicit resume without chain execution or completion. Cover 71
            process-kill boundaries and keep unresolved starts pending. Independent
            physical/access-control deployment and shared rollback remain external.
          - [x] Opt-in logical storage-incarnation binding: initialize a new
            database under an independently selected ID; require that pin on
            reopen, retain it in a versioned request before admission and in the
            atomic result. Reject another incarnation before start and preserve
            strict no-effect ambiguity. Keep old formats unchanged and bound
            requests behind independent stage pins. Cover copied-old-image
            recovery, malformed/downgraded metadata and 77 new process boundaries.
            This is not physical identity, copy fencing or rollback detection.
          - [x] Optional independently retained WorkChain database positions:
            create two new disjoint roots, bind their identity and retain both
            lifetime locks. Publish an exact intent before every logical batch,
            store a fresh position in that same batch, then independently confirm
            before success. Cover block commits, fork pruning, replay checkpoints
            and canonical pruning; keep the final authorization after intent I/O.
            Reopen only an exact confirmed position or its one pending successor.
            Explicit recovery may confirm an already present batch, never execute
            missing work or clear an unresolved intent. Reject database-only
            rollback and unexplained extensions. Cover 79 process-kill boundaries;
            copied pairs/shared rollback and physical deployment remain external.
          - [ ] Physical chain-storage identity and protected pin deployment,
            safe no-effect disposition, current-authority admission/
            completion transport, and live audit/serve/prune runtime adapters
            (including all required replica assignments, not just one guard).
            Do not infer a safe retry from absence in a replaced/rolled-back
            database, or sign completion from a generic callback return alone.
            - [x] Pinned local cancellation before any retained start: persist an
              irreversible terminal branch under the executor and pending-ticket
              guard, independently confirm it, and return a request/ticket/pair-
              bound cancellation record. Never inspect database absence, cancel
              a retained or uncertain start, complete authority automatically or
              reuse a cancelled operation. Test cancellation/execution races,
              21 publication-fault boundaries, 14 resume errors and 42 process
              kills. This does not resolve Started outcomes, fence copied
              executors or supply completion transport.
            - [x] Explicit local outcome-bound completion: accept an externally
              consumer-signed, authority-co-signed Complete only for the pinned
              executor's independently confirmed effect or pre-start cancellation.
              Hold executor/coordinator guards through the retained authority
              intent, decision and confirmation; exact retry resumes only that
              entry or reads its historical decision. Reject unknown Started
              work, wrong evidence and stale heads without signing or refreshing
              them. Cover 42 publication faults and 70 process kills, including
              interrupted retries. This is a local adapter, not authority
              transport, copy fencing or enforcement at all acceptance paths.
            - [x] Opt-in completion-only QUIC delivery to the original colocated
              executor/coordinator: pin both transport peers, accept one bounded
              externally co-signed Complete plus EOF, and reply only after exact
              terminal validation and independent authority confirmation. Bind
              replies to a fresh exchange nonce and entry ID; lost replies never
              imply non-commit. Isolate rate/concurrency budgets, reject trailing
              requests and exercise 12 server-process kill/restart boundaries.
              This does not remotely admit/execute work, add durable client
              intent, install daemon handlers or fence remote/copied consumers.
            - [x] One-command completion client outbox: retain the exact co-signed
              entry and both transport identity pins before any send, require an
              independently retained intent ID on reopen, and persist a checked
              channel acknowledgement before client success. Open is non-sending;
              explicit retries retain the same command and use a fresh exchange.
              Cover lost replies, seven local publication faults, 41 client-process
              kills and exact recovery. No signing, head refresh, automatic
              failover, cross-host execution or portable/current-authority proof.
            - [x] Opt-in admission-only QUIC to the original colocated pinned
              executor/coordinator: validate an externally co-signed prune Admit
              against the retained request before writing, then hold both owners
              through authority confirmation and executor-binding confirmation
              before replying. Resume only the exact authority/admission attempt;
              never resume a start/result/cancellation or choose a new head.
              Keep fixed frames, fresh nonces, peer pins and independent budgets.
              Cover 42 initial publication faults, 14 interrupted executor resumes,
              45 server-process kills, lost replies and Stop/cancellation races.
              Historical ACKs cannot bypass Execute's live pending-ticket guard.
              This neither remotely executes nor installs live acceptance paths.
            - [ ] Admission client intent/receipt durability and explicit runtime
              ownership: retain the exact signed command and endpoint pins before
              sending, recover without signing/refreshed heads or implicit sends,
              and never treat a retained admission ACK as a live execution grant.
              - [x] Separate one-command AdmissionOutbox: retain the exact prune
                Admit and both transport pins before any send; persist a checked,
                domain-separated ACK before success. Open only validates and
                re-syncs existing evidence. Explicit retries use the original
                command and fresh wire nonces, including after Stop/Complete/
                Retire. Cover receipt failures, wrong request/head, sequence
                bounds, lost replies, concurrency and 41 client-process kills.
                Request bytes remain separately prepared on the server; no
                request creation, signing, execution or current-authority grant.
              - [ ] Connect managed runtime owners to the two outboxes and
                colocated admission/completion handlers, with explicit roots,
                identity/key ownership, recovery and shutdown. Keep every
                actual effect under live authority and all-assignment checks.
                - [x] Command-only runtime ownership: open four existing pinned
                  roots without listening or resuming; explicitly start the
                  original colocated Admit/Complete service. Keep transport keys
                  separate from control/evidence keys; expose no raw writer or
                  effect API. Close listener, drain handlers, then release roots.
                  Stop on storage uncertainty without automatic recovery.
                  Add typed one-shot client runners around existing outboxes;
                  check pinned identity, retain receipt before success, close
                  transport before releasing the journal and return cached ACKs
                  without a socket. Cover shutdown/startup races and 16 separate
                  server-process crashes across five lifecycle phases.
                - [ ] Expose explicit operator commands and connect the actual
                  audit/serve/prune lifecycle, including live all-assignment
                  enforcement, storage pins and reviewed ownership handoff.
                  - [x] Command-only operator entry points: explicitly serve
                    Admit/Complete from four existing pinned roots and deliver
                    either typed retained outbox once. Require independent IDs
                    and transport seed paths, reject repeated flags, keep
                    shutdown ordered and stdout failure historically unresolved.
                    Return retained storage/shutdown errors; handle broken stdout
                    through cleanup. Cover real CLI SIGTERM/kill/restart, SIGPIPE
                    and exact historical retry. Publish the scoped operator runbook.
                  - [x] Explicit offline bootstrap for two new authority roots
                    under pins-first ownership, and an independently pinned
                    executor pair. Default placement review is non-mutating;
                    verify only reopens exact retained state. Preserve partial
                    initialization and never attach fresh pins to old work.
                  - [x] Reviewed prune Admit/Complete signing: consumer review
                    and signature followed by independent authority review and
                    co-signature, using existing signature domains. Pin request,
                    original admission and terminal bytes; publish immutable
                    outputs. Never infer a current head or durable terminal state.
                  - [x] Offline preparation of both typed outboxes from exact
                    co-signed entries and independent endpoint/intent pins.
                    Default review writes nothing; create only initializes a new
                    root; verify reports historical receipts without sending.
                    Exercise all six commands in a separate-process pipeline
                    and preserve roots/artifacts after broken stdout.
                  - [ ] Reviewed ownership handoff and actual audit/serve/prune
                    wiring with live archive policy,
                    all-required-assignment guards and protected storage pins.
                    - [x] One-way in-process maintenance capability: stop and
                      drain the command transport without releasing any of the
                      four root locks. Bind a local cancellation review ID to
                      confirmed authority/executor positions, storage/binding
                      IDs and terminal history. Compare it under the same
                      guards held through CancelBeforeStart; never resume an
                      attempt or expose Execute/raw owners. Cover lifecycle
                      races, confirmation barriers and four process-kill points.
                    - [x] Local operator integration and lifetime supervision:
                      opt-in macOS/Linux stdin control parks the same service
                      without unlocking, compares exact review IDs, and handles
                      EOF, SIGTERM, input/output and retained storage errors.
                      Adopt inherited pipe descriptors into interruptible I/O
                      before opening owners. Add standalone non-listening
                      review/cancel and export canonical cancellation bytes for
                      the existing independently reviewed Complete pipeline.
                      Test stale/partial input, short output, pending pins,
                      nine lifecycle process exits, SIGPIPE and public-CLI-only
                      preparation through completion. No Execute or auto-resume.
                    - [x] Explicit reviewed operator recovery of one retained
                      transition: separate confirmed/observed-prefix digest and
                      independently chosen action under the original owner guards.
                      Limit authority recovery to exact-request Admit or confirmed-
                      terminal Complete; limit executor recovery to its exact
                      pending record. No Execute, binding-gap fill or next-step
                      inference. Reject unrelated/two-layer pending state. Provide
                      offline recovery-review/recover; leave live stdin unchanged.
                      Cover six actions at both retained states, sticky failure,
                      stale review, lost output, Close drain and 18 process kills.
                    - [ ] Actual audit/serve/prune acceptance with
                      live policy, all-required-assignment and protected-storage
                      checks. Native Windows live stdin control remains absent;
                      offline maintenance is the supported boundary there.
                      - [x] Opt-in colocated archive-prune library acceptance:
                        pin exact checkpoint/trust/timing policy, selected replica
                        assignments and both executor/storage pair IDs. Lock every
                        original coordinator in immutable assignment-ID order
                        through replica replay, exact evidence, final live-time
                        storage check and independently confirmed executor result.
                        Require initial receipt coverage and position-pinned DB;
                        reject missing/relabelled owners and overlapping placement.
                        No new execution from retained starts, automatic completion
                        or cached result relabelled as live acceptance. Cover
                        secondary-stop barriers, cancellation and six process kills;
                        keep journal/command/effect encodings unchanged.
                      - [x] Complete renewal-prefix verification for colocated
                        pruning: separate lineage policy pin, exact initial
                        assignment/custody policy, canonical entries from sequence
                        one and exact selected terminal receipt. Bound aggregate
                        evidence before copying; retain all authority guards through
                        historical verification, live archive replay and result.
                        Reject gaps, substitutions and stale mode pins; preserve
                        unknown starts and cover seven process-kill boundaries.
                        This is not a latest-head proof or journal activation.
                      - [x] Bounded, externally pin-checked prepared inventory:
                        retain exact initial/lineage mode, full policy/checkpoint,
                        storage pairs, original request, selected receipt bundle
                        and one co-signed admission per assignment. Canonical
                        codec, immutable publication, exact retries, bounded load,
                        fixed vector and five process-kill boundaries. Verify
                        historical request-time consistency and all secondary
                        bindings; do not infer live admission or execution from
                        the package. Keep lineage bodies and runtime ownership
                        outside this preparation-only format.
                      - [x] Colocated prepared-archive execution and retained
                        start binding: require the exact package/tickets/receipts,
                        keep all guards through archive/lineage replay and package
                        re-sync, and bind its ID in version-1 Started records in
                        both executor journals before effects. Refuse pre-existing
                        results and preserve binding through exact pending recovery.
                        Provide read-only local inspection without relabelling old
                        starts/results, pending state or unknown work as success.
                        Cover both modes, one-root downgrade and 19 process kills.
                        This is not a remote certificate or copy-fencing mechanism.
                      - [x] Bounded historical lineage-body preparation and
                        immutable retention: exact inventory/policy/evidence pins,
                        complete verified prefixes in pinned assignment order,
                        streaming file I/O and aggregate pre-allocation limits.
                        Preserve original canonical bodies, reject replacement,
                        permit exact retries and read-only re-verification. Cover
                        mixed/empty prefixes, frozen vector, fuzz smoke and five
                        publication process kills. This does not export a live
                        journal, grant authority or bind the file ID into Started.
                      - [x] Explicit colocated secondary admission from retained
                        inventory: submit one exact co-signed candidate against the
                        original primary request ID. Require confirmed executor
                        admission and live primary permission before the first
                        secondary intent; retain all three guards through exact
                        package sync, intent, decision and confirmation. Reconcile
                        only exact retained attempts/history after primary drain;
                        never infer execution or completion. Cover both modes,
                        concurrent retries, 21 publication faults and 13 process
                        kills. No format, signing, transport or CLI changes.
                      - [x] Explicit colocated secondary completion from the
                        independently confirmed primary outcome: match the exact
                        packaged and actually admitted secondary operation, then
                        retain both guards through package sync and completion
                        intent/decision/confirmation. Success requires the original
                        inventory-bound start/result; pre-start cancellation uses
                        its original request/ticket/executor binding. Support exact
                        retained recovery and historical retry after retirement,
                        preserve unknown starts and require separate executor
                        recovery. Cover both outcomes/modes, concurrent retries,
                        42 publication faults and 26 process-kill scenarios.
                        No automatic completion, new terminal format or
                        remote certificate; operator signing and delivery are
                        covered by the following substeps.
                      - [x] Explicit offline secondary signing and co-signing:
                        independently pin original primary and selected secondary
                        assignments, keep the primary request bytes/ID unchanged,
                        and require distinct replicas with the same archive scope
                        and allowed consumer. For completion, pin both admissions,
                        validate terminal evidence against the primary ticket and
                        position against the secondary history. Reuse reviewed
                        signature domains and immutable publication; prepare typed
                        outboxes without claiming live admission or terminal state.
                        No inventory/signature cycle or new format; secondary
                        delivery/server ownership is covered by the following
                        network/service substeps.
                      - [x] Explicit fixed-secondary network sessions: reuse
                        Admit/Complete framing with pinned inventory, policy,
                        target and transport identities. Require exact request
                        plus EOF before the concrete guarded adapter; acknowledge
                        only independently confirmed target decisions. Re-read
                        content pins per request, preserve exact pending recovery
                        and original client outboxes after lost replies. Separate
                        transport keys from all selected roles and archive trust
                        keys; keep default primary sessions unchanged. One target
                        per host and caller-owned owner/host lifetime; no new CLI,
                        multiplexing, execution endpoint or automatic recovery.
                        Cover real QUIC/outbox flows in both modes/outcomes,
                        role/pin/EOF rejection, lost replies and 18 process kills.
                      - [x] Owned fixed-secondary command service and explicit CLI:
                        derive the original executor and selected target from the
                        pinned inventory, require disjoint existing owner roots,
                        and select admit/complete/both without automatic recovery.
                        Reuse the runtime admission gate and handler drain before
                        releasing owners; expose no maintenance or effect API.
                        Completion-only opens no primary owner. Stop/drain before
                        separate offline effects, then reopen for exact outbox
                        delivery. Cover startup cleanup, shutdown ownership,
                        context cancellation, uncertainty and real CLI restarts.
                      - [x] Reviewed live-journal evidence extraction: require
                        explicit source checkpoints and pinned inventory scope,
                        retain source ownership while reading exact canonical
                        prefixes, reject changed/incomplete sources and bound
                        the aggregate before copying. Preserve detached historical
                        bytes without creating or repairing journals. Keep source
                        review pins separate from the unchanged evidence file ID.
                        Cover rotated/losing bodies, alias rejection, cancellation,
                        source ownership and reuse in the existing guarded effect.
                        Extraction does not imply current Audit permission or a
                        unique head; operator tooling is covered below.
                      - [x] Operator extraction review/publication/verification:
                        read bounded source metadata and existing canonical
                        files under external inventory/checkpoint pins, require
                        an exact reviewed scope before extraction, and reuse the
                        immutable evidence publisher and loader. Display the
                        canonical reviewed scope and bind source/output paths in
                        the local review ID. Verify retained bytes with sources
                        offline; preserve exact retries and stdout failures.
                        No automatic checkpoint capture, source repair,
                        signing or execution.
                      - [ ] Supervised multi-owner effect/runtime handoff with
                        every required original owner retained through explicit
                        review and guarded execution. Integrate managed audit/serve
                        paths; test remote partitions and physical/copy fencing
                        before activation. Library acceptance alone does not close
                        this parent gate.
                        - [x] Explicit owned prepared-archive effect service:
                          open the original pinned executor, every selected
                          coordinator in assignment-ID order and position-pinned
                          WorkChain without recovery. Keep these owners from
                          local review through exact guarded execution and Close;
                          bind paths, content pins, execution configuration and
                          confirmed positions in the comparison ID. Recheck under
                          all original guards before replay and final live-time
                          authorization. Cover initial/lineage modes, stale scope,
                          uncertainty, concurrent calls and real process death.
                          This is a separate colocated library lifetime, not
                          a command-service transfer or managed Audit/Serve.
                        - [x] Explicit operator CLI with non-executing review
                          by default and opt-in supervised control pipes. Load
                          exact bounded root mappings and existing read-only
                          activation history without initialization. Require a
                          successfully reported same-session review before
                          Execute; cancel on EOF, channel failure or signal and
                          retain owners until the effect drains. Export canonical
                          terminal bytes without completing tickets. Cover actual
                          command-service drain/close, effect and command reopen,
                          lost stdout, killed processes and blocked pipe writes.
                        - [x] Opt-in journal-backed managed Serve library:
                          pin the exact admitted challenge and authenticated
                          peer, open only the existing active journal, and retain
                          the original coordinator guard through fresh, cached
                          and recovered response delivery, EOF, actual stream
                          close and cancellation drain. Cover stop/complete,
                          stale authority, real QUIC and five process-death
                          checkpoints without implicitly completing a ticket.
                        - [x] Managed Audit library from an unsigned, externally
                          pinned durable intent through deterministic challenge
                          publication, verified response acceptance and exact
                          prior+1 recovery. Hold the original Audit guard through
                          actual stream cleanup, journal commit and artifact
                          publication; reject uncertain/completed authority,
                          stale/foreign heads and missing evidence. Cover five
                          real process-death checkpoints without completing tickets.
                        - [x] Explicit local Audit/Serve pair under one original
                          coordinator guard. Check both exact pending tickets,
                          challenge, separate transport identities and disjoint
                          participant roots before application I/O; concurrently
                          run private participants and drain both on any failure.
                          Cover fresh/cache/reopen/Stopping, blocked Close and
                          pinned real QUIC without recursive owner acquisition.
                        - [x] Owned Serve host and operator CLI: default review
                          releases owners before output; opt-in serving uses
                          dedicated interruptible control pipes. Open existing
                          objects/journal/authority only, bind both seed identities
                          to external pins and drain handlers before owner Close.
                          Cover native process restart/kill, EOF/SIGTERM, broken
                          readiness and malformed control without auto-completion.
                        - [x] Unsigned intent operator review/publish/verify:
                          require fixed predecessor/times/samples and an existing
                          separate nonce file. Publish only against the reviewed
                          content ID, without new randomness, signing or admission;
                          preserve exact retry and lost-output evidence.
                        - [x] Owned Audit runtime and operator CLI: review is
                          non-executing and closes owners before output. Explicit
                          supervised control requires a fully reported same-session
                          scope before prepare, recover or pinned network Audit.
                          Compare current owner/journal positions under the
                          original guard immediately before effects, consume the
                          token, and drain actions/hosts before owner release.
                        - [x] Owned local paired QUIC runtime and operator CLI:
                          retain one original coordinator, both private sessions
                          and existing evidence/objects. Each reviewed exchange
                          owns two pinned hosts, stops callback admission and
                          drains accepted callbacks, streams and cancellation
                          before releasing the owner. Recheck the local comparison
                          under the joint guard before signing/application I/O.
                          Cover stale review, blocked Close, native process kill,
                          EOF/signals and lost stdout without implicit completion.
                        - [x] Reviewed Audit/Serve signing/co-signing and local
                          application of exact-position Admit/Complete commands.
                          Capture a canonical terminal envelope from the selected
                          original pending ticket and committed current journal
                          head. Hold original coordinator and source decision
                          through publication or append plus confirmation; never
                          resume implicitly. Test the complete process workflow
                          from position zero, lost output, independent completions
                          and exact retry after the other ticket closes.
                        - [x] Two-host acceptance with separate fresh local
                          Audit/Serve assignments, pinned identical binaries and
                          original owners created independently at destination.
                          Exercise real QUIC exchange, pre-request packet loss,
                          a deterministic post-replica-commit partition/kill,
                          unchanged response recovery, bounded loss/delay and
                          expired-proof refusal. Verify ordinary devnet restart,
                          independent fork mining and full replay after reorg.
                          Retain sanitized source/artifact/state evidence; this
                          adds no independent audit or physical-control credit.
                        - [x] Opt-in version-1 authority state with an intrinsic
                          RemoteBegin/RemoteDrained hold. Persist the exact Serve
                          ticket and plan across original-owner restart; freeze
                          every other new transition until the exact drain, then
                          permanently prohibit generic live Serve reuse. Preserve
                          version-0 bytes and reject V1 in legacy signing/delivery.
                        - [x] Record-only remote worker journal with immutable
                          plan/Begin pins, irreversible Sealing and permanent
                          unseen/started tombstones. Require explicit exact
                          confirmation recovery; supply no execution or signer.
                          Cover original-owner and worker process deaths, delayed
                          Start refusal and no implicit proof/ticket completion.
                        - [x] Owned opt-in V1 remote execution library: separate
                          bounded authenticated control protocol and Audit data
                          channel; confirmed original-A Begin before Start; one
                          same-runtime fresh attempt; restart permits only an
                          exact committed cache. Persist Sealing before stopping
                          admission and draining callbacks; sign only afterward.
                          Bind successful typed terminal/completion to the SAME
                          result already accepted in the original A journal.
                          Preserve explicit Begin/Drain/Complete pending recovery
                          and independent ticket completion without proof refresh.
                        - [x] Existing-root V1 operator/server CLI with default
                          non-executing review, consumed same-session comparisons,
                          original-owner rechecks and native dedicated control
                          pipes. Retain normalized sealed metadata and publish a
                          typed terminal under original source guards; recover
                          confirmed Drain metadata after lost output without
                          execution, signing or implicit authority resume.
                          Test real CLI processes, EOF and broken output.
                        - [x] Distinct V1 offline assignment/plan publication,
                          reviewed Admit/Begin/Complete signatures and explicit
                          fresh authority/worker bootstrap with no implicit
                          recovery. Compare canonical bytes, preserve V0-only
                          workflows, recover exact immutable signatures without
                          seeds, and use CLI signatures in the real-QUIC
                          successful-completion test.
                        - [x] Explicit fresh A/B source journals and A artifacts,
                          original-A guarded V1 admission application and
                          pre-Begin challenge preparation. Require independently
                          confirmed pending Audit, preserve exact intent nonce/
                          times, reject partial/existing root reinitialization,
                          active remote holds and replaced source/lock identities.
                          Run the entire position-zero CLI lifecycle through
                          native processes and real QUIC, lose the first admission
                          reply, recover the same entry and close both tickets
                          independently at confirmed position six. Retain V0
                          rejection/behavior and explicit pending Resume.
                        - [x] Controlled same-assignment V1 WAN operator
                          acceptance on two Linux hosts: frozen native binaries,
                          explicit CLI bootstrap, partitions/loss/delay, A/B
                          process deaths before and after result acceptance,
                          lost sealed reply and metadata-only reconciliation.
                          Reject expired/unseen/unknown success and retain both
                          ordinary tickets. Reject delayed Start over an
                          authenticated live route after every seal. Reuse one
                          assignment and original source journals/locks through
                          32 sequential cycles, closing both tickets independently;
                          validate retained reports before publishing a sanitized
                          index. See REMOTE_CUSTODY_WAN.md.
                        - [x] Separately versioned authority-signed negative
                          observations with exact original-A predecessor binding.
                          Distinguish Unseen, unknown after Start, unverified B
                          commitment and verified-but-unaccepted B entry. Retain
                          both tickets; never import/refresh proof or allow a
                          successful terminal. Add owned capture/review, exact
                          output recovery and read-only sealed B entry export.
                          Preserve positive vectors and reject stale absence
                          observations after original source advance. See
                          REMOTE_CUSTODY_NEGATIVE.md; capture does not complete.
                        - [x] Opt-in local placement enrollment and runtime
                          checks for original roots/locks, anchor directory and
                          role seed files. Check independent pins before CLI
                          seed loading and during owned A/B actions/responses.
                          Refuse ordinary copies, substitutions and changed
                          private permissions across process restart. Require
                          explicit reviewed enrollment; no automatic rebind or
                          implicit recovery. See REMOTE_CUSTODY_PLACEMENT.md.
                          This is not raw-key, full-VM or distributed copy fencing.
                        - [x] Explicit negative Audit-only administrative Complete
                          with independent consumer/authority signatures, original
                          source/Drain guards, exact retry and explicit pending
                          Resume. Keep the original Serve ticket pending in all
                          four branches, including Unseen; prohibit retirement
                          across that obligation. Preserve positive evidence and
                          reject proof refresh/new execution. See
                          REMOTE_CUSTODY_NEGATIVE.md.
                        - [x] Experimental independent witness protocol and
                          durable non-equivocation journal: externally pinned
                          scope, >2/3 signatures, one claim/result commitment,
                          retained unknown obligation, fsync before vote release,
                          strict replay/recovery and process-death tests. See
                          CUSTODY_FENCE.md. This is a separate foundation;
                          mandatory assignment/transport/effect acceptance and
                          independent service deployment remain open below.
                        - [x] Experimental authenticated witness transport and
                          five-command operator workflow: read-only seed-free
                          review, explicit bootstrap/serve/recovery, exact-pinned
                          requests, nonce-bound observations, quorum assembly,
                          bounded frames/EOF/ACL/resources and complete cleanup.
                          Run native CLI lost-output/SIGKILL/cold-recovery tests
                          and four logical witnesses over two Linux hosts with
                          insufficient/duplicate quorum refusal, original-root
                          reuse and retained unknown/result obligations. This is
                          not four independently protected failure domains.
                        - [x] Separately pinned typed historical custody-result
                          bundle: replay mandatory claim/[unknown]/result
                          certificates, bind their evidence to the complete exact
                          custody entry, reject legacy/digest/role substitutions
                          and preserve original proof time. Add fixed signature
                          vectors, fuzzing and CLI review/publication/verification.
                          Current original-source acceptance, effect consumption
                          and Serve completion remain open; see
                          CUSTODY_WITNESS_NETWORK.md.
                        - [ ] Single-assignment cross-host current-authority
                          enforcement and independently enforced physical/copy
                          fencing. Separate local assignments over real WAN do
                          not establish distributed current authority. The V1
                          managed operator path now has controlled WAN evidence;
                          this does not fence copied roots or independent use of
                          A's trusted control key. Remaining work: unknown/unseen
                          Serve disposition (REMOTE_CUSTODY_NEGATIVE_PLAN.md),
                          mandatory versioned witness assignment/transport/effect/
                          proof validation and independent witness deployment
                          (CUSTODY_FENCE.md);
                          independently protected keys/roots and copy fencing.
                          In-place owner transfer is not added by the explicit
                          stop/close/reopen operator workflow.
  - [ ] Filesystem-full, inode-exhaustion, power-loss, and long-running retention
    campaigns before deployment claims.
  - [x] Isolate the 2026-09-07 custody sibling-rejection deadline race: force the
    rejecting replica to close before the auditor's final challenge Write returns.
    Preserve ErrCustodySession alongside deadline-setup errors, as already done
    for read/write errors; do not continue I/O or treat closed-pipe as success.
    Cover fresh/durably recovered responses and unchanged retained evidence.
  - [x] Isolate the 2026-09-07 custody response-close race: force a verified
    auditor close before the replica's last successful Write returns. Reuse the
    final frame's already installed deadline instead of resetting it on a closed
    pipe; still require actual EOF and retain timeout/non-EOF rejection. Cover
    fresh and recovered journal responses with deterministic failing-before-fix
    regressions and repeated race-enabled runs. No completion message or evidence
    format changes, timeout extension or generic closed-pipe acceptance.
  - [x] Isolate the intermittent 2026-09-07 process failure in the campaign
    coordinator's post-rename journal case. Reproduce the visible-but-not-yet-
    acknowledged StagePair window with a deterministic writer checkpoint, and
    require a killed/drained old writer plus recovered AwaitingPublication
    startup before permission faults target ConfirmPublication. Preserve exact
    recovered phases, no premature delivery/advance and normal recovery checks.
  - [x] Isolate the intermittent 2026-09-07 process failure in the campaign
    observer's post-link confirmation case. A reproduced failure's peer logs
    show observer exit before connection: the fixture wrote a watched final
    publication marker directly, exposing its empty create/write interval.
    Preserve strict malformed-file rejection. Use the explicit, pin-checked
    external publisher with checkpoint-first staged/synced no-replace links;
    cover reader visibility, all ten file boundaries, exact retries and conflicts.
    The deterministic direct-write reproducer and 15 process repetitions under
    concurrent store crash-test load distinguish this cause from confirmation
    loss. External review, directory ownership and physical storage remain
    separate deployment obligations.
  - [x] Isolate the 2026-09-06 tie-pair/campaign early-close race with a
    failing-before-fix process regression, add bounded EOF-based host/slot
    retirement, and distinguish nested transport timeouts from signed-slot
    expiry without changing pending-delivery safety rules.
  - [x] Close the between-slot observer readiness gap found by the 2026-09-06
    process gate: keep one authenticated handler installed, bound readiness
    waiting, and retire the old binding before stream close. A delayed second-
    slot regression fails before the fix and completes without reconnect after
    it; request budgets, signed slot times, and role ordering are unchanged.
- Admission-deduplicated multi-hop forwarding across the explicit peer graph.
- Reputation/latency/ASN-ranked peerbook selection with an inventory-free,
  exact-context WorkGraph capability probe.
- Same-parent timestamp generations with retire/drain semantics, atomic DAG
  revalidation, concurrent-admission linearization, and gossip handoff.
- Activation-bound peer exchange with signed height/capability records,
  atomic refresh, persistent sequence renewal, and live WorkGraph confirmation.
- Epoch-keyed bootstrap rotation and periodic long-lived miner refresh with
  serialized crash-safe peerbook persistence.
- Adversarial bootstrap failover: a mixed exact/foreign-activation response is
  rejected atomically without preventing the next independent bootstrap.
- Canonical Work-ID ordering after coverage-ranked parent selection and a
  parameterized four-node rollover/churn/loss convergence soak.
- Versioned PoW/economic activation-review packet with a deterministic result
  digest, fine standard/bounded-trail selfish-mining and private-fee grids, and
  precommitted external pass/fail gates. A global-ID selective-publication
  counterexample rejects deterministic v1 equal-work displacement; version 1
  persists the local arrival incumbent and switches only for strictly more
  cumulative hard work.
- Integer-only stochastic PoW paths for both target rules with canonical
  observation digests and timestamp/hash-rate regression corpora.
- Versioned public-testnet calibration evidence with integer-only one-sided 99%
  upper bounds, family-wise mining-cluster selection correction, a 30-day
  window gate, signed gapless hourly manifests, trusted deployment/policy
  bindings, published rollback checkpoints, a crash-safe first-admission hard-
  anchor collector, canonical tie plans precommitting miner and first-delivery
  roles, one signed raw receipt per planned slot with conservative failure
  accounting, a fail-closed dual-manifest evidence bundle, a crash-safe post-
  commit receipt writer, an isolated-pool two-miner producer with a one-slot
  persistent-router CLI harness plus wait/crash/restart process coverage, and a
  transport-neutral pair artifact with observer-side deterministic mining
  replay, a canonical digest, and version-2 plans sharing one campaign ID across
  up to 64 observer keys. A separately rate-limited authenticated QUIC pair
  protocol now pins both transport identities and published IDs, returns a
  durable signed-receipt acknowledgement, confirms its delivery, and recovers
  lost acknowledgements without duplicate admission. The ER-5 handoff now
  requires every version-2 observer chain, counts a campaign slot only once,
  and downgrades any valid block/selection disagreement to conservative
  `NoPair` without majority voting. The report commits the plan version, so the
  legacy single-view path cannot certify a version-2 plan. Coordinator-signed
  per-slot pair checkpoints now give the external publication channel a compact
  immutable binding, and a checksum-protected crash-safe campaign journal
  persists pair, publication, every observer acknowledgement, and advance
  boundaries. A resumable timed coordinator driver now writes immutable
  artifacts, waits for the separate publication gate, contacts all missing
  observers concurrently, and advances its local chain only after every ack.
  A long-lived observer receiver now validates numbered externally published
  checkpoints for the whole plan, records coordinator confirmation separately
  from signed receipt persistence, recovers the ACK/confirmation crash window,
  advances after completely empty `NoPair` slots, and stops on any partial pair.
  Coordinator publication waits are bounded by the signed slot; before any
  delivery it waits through the common receipt grace and journals the exact
  skipped sequence, while every state after publication is permanently
  non-skippable. A real coordinator/observer process regression proves an
  expired zero-delivery slot followed by a completed pair retains one parent
  and convergent tips. A second injected process crash after only the first
  sibling commit proves partial state survives and permanently stops the
  campaign; pre-commit and ambiguous post-commit write failures for skip and
  confirmation journals are idempotently recoverable.
  A read-only operator audit now reconciles coordinator state, immutable
  artifacts/publications, canonical observer receipt chains, confirmation
  markers, and cross-observer selected tips. It distinguishes healthy,
  retryable ACK/closure lag, and permanently blocked divergence without
  creating, advancing, or migrating any journal.
  A two-observer, two-slot version-2 process campaign now restarts one observer
  between slots at its stable pinned endpoint. A stale reused QUIC session is
  explicitly disconnected and retried once with a fresh authenticated
  handshake; both independent receipt chains, role order, selected tips, and a
  read-only healthy audit converge afterward.
  A separate exact-boundary process run blocks one observer before request
  decoding, waits for the other ACK to enter the fsynced journal, and kills the
  coordinator. Restart exposes `acknowledged=1`, delivers only to the missing
  observer, delays local advance until that ACK, and ends in a healthy audit.
  The pair stream is now version 2 and ends with an observer acknowledgement
  emitted only after its confirmation marker and directory fsync. Real
  coordinator/observer processes exercise pre-commit and ambiguous post-commit
  filesystem failures on both journals; no case advances the coordinator tip.
  An offline recovery command accepts only the audit's exact
  `unrecorded_observer_ack` proof, journals that tail without admitting blocks,
  and lets the ordinary coordinator resume from `AwaitingAdvance`.

### Exit gates

- No share can be paid more than once.
- Reward calculation is deterministic and bounded.
- Honest small miners receive approximately proportional rewards in simulation.
- Share bandwidth remains within the published node budget.
- Long rounds preserve valid same-parent work across timestamp generations.
- Formal analysis documents the remaining fairness assumptions.
- Independent reviewers can reproduce the frozen corpus without trusting a
  generated summary; internal reproduction is not labeled as an audit.

## Milestone 6: committee preconfirmations

### Deliverables

- Committee eligibility and selection from mature PoW shares.
- Pure deterministic BFT state machine.
- Ed25519 multi-signature certificates with signer bitmap.
- Microblocks and preconfirmation receipts.
- Locked earned rewards as equivocation collateral.
- Evidence inclusion and slashing of immature rewards.
- PoW fallback when the committee stalls.

### Exit gates

- Committee signatures never override PoW fork choice.
- Safety holds below the documented Byzantine threshold.
- Liveness returns after committee rotation.
- Conflicting signatures create independently verifiable evidence.
- The protocol clearly distinguishes preconfirmation from PoW confirmation.

## Milestone 7: application and solver layer

### Deliverables

- Deterministic Wasm execution through wazero.
- Minimal host API with no WASI, clock, network, filesystem, floats, or threads.
- Declared read/write sets and parallel execution of disjoint transactions.
- Intent score functions and permissionless solver bids.
- Batch auction and deterministic winner selection.
- Capability accounts, session keys, spending limits, and recovery policies.
- Go/TinyGo SDK and contract examples.

### Exit gates

- Execution results are identical across supported operating systems and CPUs.
- Parallel and sequential execution produce identical ordered state diffs.
- A malicious solver cannot violate a signed outcome constraint.
- A compromised session key cannot exceed its capability.

## Milestone 8: privacy, data availability, and proving

### Deliverables

- Encrypted envelope and commit/decrypt/solve batch phases.
- Well-formedness and fee-reservation proof for encrypted envelopes.
- Plaintext escape path if decryption stalls.
- Erasure-coded batch data and availability sampling.
- Archive assignments, challenges, and storage rewards.
- Versioned execution-proof interface.
- Initial gnark or external zkVM proving adapter.

### Exit gates

- Encryption failure cannot halt plaintext transactions.
- Unavailable data cannot become an accepted anchor state.
- A proof system can be replaced through an explicit protocol upgrade.
- Full execution remains a safe fallback until proof-only validation is audited.

## Milestone 9: adversarial public testnet

### Deliverables

- Reproducible releases and signed binaries.
- Public explorer, faucet, wallet, and SDK documentation.
- Continuous network chaos testing.
- Independent implementation or independent consensus verifier.
- External audits for codec, GuardVM, state transition, PoW, and networking.
- Public bug bounty and incident response process.

### Exit gates

- At least six months without an unresolved consensus split.
- Successful recovery from intentionally induced partitions and database faults.
- No unaudited cryptographic construction in a consensus-critical path.
- Resource and bandwidth requirements match published limits.

## Milestone 10: mainnet readiness

Mainnet is a separate decision, not an automatic next step.

Required evidence:

- demonstrated user demand for outcome-safe execution;
- stable mining participation across independent operators;
- a credible security budget and issuance simulation;
- multiple wallet and node operators;
- completed external audits with resolved critical findings;
- documented upgrade and emergency response procedures;
- legal review for distribution, mining, and public interfaces.

## Explicitly deferred

The following do not belong in the first vertical slice:

- a public token sale;
- bridges;
- private balances;
- BLS aggregation;
- custom post-quantum cryptography;
- proof-only state validation;
- mobile mining;
- an unbounded general-purpose contract API;
- on-chain token voting over protocol rules.
