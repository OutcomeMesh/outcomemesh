# Owned prepared-archive effect runtime

Status: opt-in colocated library and operator CLI, not an activated network service.
The broader M5 operator/acceptance gate remains open in [PLAN.md](PLAN.md).

`OpenPruneArchiveEffectService` owns one already prepared archive-prune operation.
It opens the original protected executor pair, **every** original coordinator pair
selected by the independently pinned inventory, and one position-pinned WorkChain.
It exposes `Review`, `Execute` and `Close`; no raw owners or generic callbacks are
available to callers. Existing command services must stop, drain and close before
this separate owner opens their roots. This is not an in-place transfer from the
one-assignment command service or a remote execution endpoint. The explicit CLI
below uses this same ownership lifetime.

## Inputs and ownership

`PruneArchiveEffectServiceConfig` requires explicit existing paths and external
pins. It never initializes, repairs, resumes or replaces a missing root.

- Inventory file, independently retained inventory ID and mode-specific policy ID.
- Original executor and executor-pin roots.
- Exactly one original authority/pin pair per inventory assignment, labelled by
  its original assignment ID. Tickets and assignments come from the verified
  inventory, not caller substitutions or discovery.
- Existing position-pinned WorkChain and its independent position journal. The
  inventory selects the storage incarnation and storage-pair IDs; pending or
  mismatched database positions block opening without confirmation or recovery.
- One existing replica archive directory per selected assignment. Its selected
  receipt is derived from the inventory.
- A dedicated existing availability-artifact parent and explicit output filename.
- For lineage mode only, the retained lineage-evidence file and its independent
  content ID. Initial mode rejects both lineage inputs.
- Exact activation base, WorkGraph parameters, local storage policy and archive
  replay limits. Mutable configuration slices and base state are detached.

All owner roots, replica directories and dedicated artifact parents must be
pairwise disjoint. Placement is validated before acquiring lifetime locks.
Coordinator pairs open in immutable assignment-ID order, with pins before writers;
WorkChain opens last. Partial opening releases acquired owners in reverse order.
Canonical paths and logical IDs do not establish physical independence or fence
copied keys, copied owner pairs, rolled-back hosts or privileged filesystem edits.
Keep inputs immutable and their independent pins protected for the whole lifetime.

## Explicit review and execution

1. Stop, drain and close all preceding command owners. Independently review the
   inventory and the retained lineage evidence, when required. Select the exact
   original roots and activation configuration; do not derive expected pins from
   an untrusted artifact or queried authority head.
2. Open the effect service. Opening listens nowhere and advances no journal.
3. Call `Review(ctx)`, inspect its detached fields and compute `review.ID()`. It
   verifies retained inputs and captures confirmed executor, authority and storage
   positions under the executor and all original coordinator guards. It does not
   replay replica archives, publish availability or certify live receipt freshness.
4. Explicitly supply that exact independently reviewed ID to `Execute(ctx, id)`.
   The service rechecks it inside the same original guards held through concrete
   archive replay, final authorization, retained start, effect and result.
5. Close the service before any subsequent owner opens these roots. Complete
   tickets only through the separate reviewed signing/delivery pipeline, using
   independently confirmed terminal evidence.

The scope comparison domain is `OMESH/custody-prune/archive-effect/scope/v0`.
It binds canonical input/output and owner paths, content pins, assignment-labelled
roots, the complete activation configuration, storage policy and replay limits.
The review domain is `OMESH/custody-prune/archive-effect/review/v0`. It additionally
binds the inventory mode, request/storage/pair IDs, confirmed executor position,
storage commit position and each original authority's position, phase and ticket.
These local comparison IDs are neither signatures nor portable permissions.
Reopening the same exact unchanged scope can reproduce a review; changed retained
positions require a new explicit review. Receipts must still pass final live-time
authorization regardless of whether the comparison ID matches.

Lineage mode reloads and fully checks the retained historical prefixes on every
Review and Execute. Both comparisons recheck the file's content ID. Immediately
before start, the retained lineage file and its parent are re-synced and checked
again, along with the inventory fence, before the existing final authorization.
A cached detached lineage cannot replace a lost file. Started records continue to
bind the inventory ID; the separate lineage-evidence ID remains a review/input pin
and is not silently added to existing journal or effect formats.

## Failure, concurrency and restart

The private lifecycle mutex serializes Review, Execute and Close. Close waits for
an accepted synchronous effect, including result publication, before releasing any
owner. Concurrent Execute calls cannot apply the same operation twice. Cancelling
a context does not itself close the service: the caller must still call Close.

Review requires an independently confirmed Admitted executor and every exact
original ticket still pending. Pending transitions, completed/cancelled work and
unknown Started outcomes are not execution candidates. No review or open repairs
a binding gap, resumes an intent, signs a command, completes a ticket or infers
non-execution from an absent result. Sticky uncertain/closed-owner failures block
further work until Close and explicit reopening/recovery through existing tools.

A process interruption after Started may leave an unknown outcome. Preserve the
executor, all authority roots, independent pins, inventory, lineage evidence and
database pair. Reopen alone does not resolve that outcome. Existing separate
recovery may confirm only an already present exact atomic effect; absence is not
permission to rerun. A lost return value likewise does not imply non-commit.

## Compatibility and evidence

### Operator command

`omd work-prune-archive-effect` defaults to `--mode review`. It opens existing
owners, computes a detached local review, **closes every owner**, and only then
prints the header and readable scope. No output failure can keep those owners
behind a blocked one-shot report. Review remains available without live control
support, including on Windows.

The opt-in `--mode control` requires dedicated native stdin and stdout pipes on
macOS/Linux. Both inherited endpoints are adopted into interruptible nonblocking
I/O before long-lived effect owners open. Native terminals, regular files and
sockets are rejected for control. This transfers the entire dedicated endpoints;
do not attach another reader/writer to them. The command creates no listener.

Every invocation requires these explicit inputs:

```text
omd work-prune-archive-effect --mode review
  --inventory /operator/inventory/prepared.ompi
  --inventory-id <independently-retained-inventory-id>
  --policy-id <independently-retained-mode-policy-id>
  --data /operator/activation-source
  --roots /operator/metadata/roots.json
  --executor /operator/executor --executor-pins /operator/executor-pins
  --chain /operator/chain --chain-pins /operator/chain-pins
  --availability-out /operator/availability/verified.omav
  --canonical-retention <reviewed-nonzero-tip-distance>
```

The example is an argument list, not a ready-to-run configuration. All roots,
inputs and artifact parents must already exist and satisfy the library placement
rules. `--data` is a separately prepared, existing activation source: genesis,
activation profile and the complete legacy ledger containing the exact activation
parent. Its writer must be stopped; use a verified consistent source, not a live
filesystem copy. This source directory must be disjoint from all effect-owned
roots, replica and artifact directories. `--chain` names the original protected
WorkChain directly; the command never discovers or creates a default work tree.

`--data` is read through `pebblestore.OpenExistingReadOnly`: existing directory and
original regular `LOCK`, `ReadOnly`/`ErrorIfNotExists`, exact genesis/schema/state
checks and no initializer. Missing, empty, incomplete or mismatched history fails
without being bootstrapped. The detached activation base is verified against the
inventory binding, and the source is closed before effect ownership begins.
This local source check does not prove current remote authority or physical copy
fencing; paths must remain immutable/operator-controlled during open and use.

The root metadata is bounded to 256 KiB, with exactly these fields:

```json
{
  "authorities": [
    {"assignment_id": "<original-assignment-id>", "authority": "../authority-a", "authority_pins": "../authority-a-pins"}
  ],
  "replicas": [
    {"assignment_id": "<same-original-assignment-id>", "directory": "../replica-a"}
  ]
}
```

Supply exactly every selected original assignment, up to 64 in each array, with
one authority pair and replica directory per ID. IDs use canonical lowercase
64-digit hex; relative paths resolve against the metadata file's parent.
Duplicate/unknown/case-changed/missing fields, nulls, wrong types, duplicate IDs,
invalid UTF-8 and trailing values fail. Metadata cannot live inside an owned,
replica or output tree; it may share a retained immutable-input parent.

Lineage mode additionally requires `--lineage-evidence` and
`--lineage-evidence-id`. Initial mode rejects these flags even with empty values.
The mode itself comes only from the externally pinned inventory. Replay bounds
are `--max-archive-blocks`, `--max-archive-chunks`, `--max-archive-bytes`. Storage
controls are `--max-history-bytes`, `--fork-retention`, `--checkpoint-every`,
`--checkpoint-keep`, `--canonical-retention`. History budget defaults to the
activation profile; other defaults follow the existing storage/replay policies.
Canonical retention is disabled by default and must be explicitly nonzero.
Actual effective values are displayed and bound in the library review ID.
Repeated flags and positional arguments are rejected.

### Supervised control protocol

After readiness, the controlling process keeps both pipes open and exchanges
these complete LF-terminated commands, each at most 96 bytes including LF:

```text
review
execute <review-id-reported-by-this-session>
close
```

Send one command and consume its response before the next. A review response
starts with `work_prune_archive_effect_review`, then readable JSON showing
canonical paths, labelled owner positions, complete activation-base/configuration
fields and hex IDs, and ends with `work_prune_archive_effect_scope_end`.
Only a completely written review response enables Execute in that same session.
An ID from a different invocation alone is insufficient. No automatic refresh or
retry occurs. Queuing is bounded to one command; extra pipelining fails closed.
The terminal read/error channel is independent of that queue, so a queued command
cannot hide EOF while verification or execution is running.

EOF, partial/oversized framing, signal/context cancellation, read failure or
output failure cancels ongoing work and drains the owned service before return.
Complete command syntax is checked in order: an invalid queued command ends the
session after the preceding accepted action drains, without executing that
invalid command. Keep stdin open until the requested result is observed. An explicit
queued `close` is ordered after the preceding action and drains it. Control does
not recover uncertainty. A process kill releases OS ownership but preserves the
retained pending/start/result distinctions for separate review/recovery.

A successful result line starts with `work_prune_archive_effect_executed` and
includes the canonical terminal bytes as `canonical_hex`, their ID and the exact
inventory/policy pins. These bytes feed the existing independently reviewed
Complete-signing pipeline; the command never signs or submits Complete itself.
Owners remain retained after the result until Close/EOF/failure. Lost stdout may
follow a durable effect: preserve all roots and inspect the retained exact result
instead of treating missing output as permission to execute again.

The original primary command service must stop/drain/close before this effect
command opens; busy roots fail. Close the effect session before reopening command
delivery, including completion-only secondary service. This explicit stop/reopen
workflow is tested in real processes. It does not perform an in-place ownership
transfer, automatically stop another process or add network effect requests.

### Validation boundary

The new service is opt-in. Consensus rules, requests, signed commands, authority
and executor journals, wire formats and atomic effect formats are unchanged.
Existing direct prepared-archive execution retains its previous behavior; the two
new comparison callbacks are private synchronous checks used only by this owner.
The library-only path adds no decoder or interpreter surface. The operator CLI
adds the bounded local metadata decoder described above, with dedicated fuzz
coverage; it does not change a network or consensus decoder.

Unit tests cover actual initial/lineage pruning, mixed renewal prefixes, ownership
and partial-open cleanup, stale review and artifact loss, pending/Started/terminal
rejection, detached configuration, concurrent execution and Close drain. The
integration process test kills real service owners at seven boundaries in each
mode and reopens twice without automatic journal progress or ticket completion.
The CLI additionally tests real initial/lineage activation sources, default
read-only review, command/effect/command process handoff, SIGTERM/kill/EOF, lost
readiness/result output, interruptible full native output pipes and bounded strict
metadata decoding with fuzz seeds. These are process and local-I/O checks, not
power-loss, physical-device or cross-host acceptance evidence. Managed Audit/Serve
enforcement, in-place owner transfer, remote partition handling and independent
physical/copy fencing remain open.
