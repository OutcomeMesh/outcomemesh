# Owned prepared-archive effect runtime

Status: opt-in colocated library tooling, not an activated network service.
The broader M5 operator/acceptance gate remains open in [PLAN.md](PLAN.md).

`OpenPruneArchiveEffectService` owns one already prepared archive-prune operation.
It opens the original protected executor pair, **every** original coordinator pair
selected by the independently pinned inventory, and one position-pinned WorkChain.
It exposes `Review`, `Execute` and `Close`; no raw owners or generic callbacks are
available to callers. Existing command services must stop, drain and close before
this separate owner opens their roots. This is not an in-place transfer from the
one-assignment command service, a CLI command or a remote execution endpoint.

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

The new service is opt-in. Consensus rules, requests, signed commands, authority
and executor journals, wire formats and atomic effect formats are unchanged.
Existing direct prepared-archive execution retains its previous behavior; the two
new comparison callbacks are private synchronous checks used only by this owner.
No decoder or interpreter surface is added.

Unit tests cover actual initial/lineage pruning, mixed renewal prefixes, ownership
and partial-open cleanup, stale review and artifact loss, pending/Started/terminal
rejection, detached configuration, concurrent execution and Close drain. The
integration process test kills real service owners at seven boundaries in each
mode and reopens twice without automatic journal progress or ticket completion.
These are process-crash checks, not power-loss, physical-device or cross-host
acceptance evidence. Operator CLI integration, managed Audit/Serve enforcement,
remote partition handling and independent physical/copy fencing remain open.
