# Owned scheduled Prune execution

`OpenScheduledPruneEffectService` retains one existing scheduled execution
placement across `Review`, `Execute`, `Recover` and `Close`. The one-shot
`work-archive-prune-scheduled` CLI uses this same service and closes it before
writing output. There is no new listener, remote execution permission or journal
format in this change.

This lifetime is the prerequisite for placing the actual storage capability
behind an isolated service. The subsequent [service-bound admission](PRUNE_SERVICE_ADMISSION.md) path adds
mandatory enrollment and a live guard check for explicitly versioned requests.
Isolated ownership and remote Prune execution remain separate work. A delivery receipt, local
review ID or historical custody signature cannot grant deletion permission.

## Ownership

The configuration selects the existing inventory and content ID, original
executor and independent pins, every original authority pair, migrated protected
WorkChain and position journal, original replica directories and custody journals.
It also fixes the independently retained storage migration ID, activation base,
storage policy, replay bounds and optional claim collector.

Opening validates the complete labelled placement before acquiring owners. It
detaches mutable configuration, opens the executor, acquires authority pairs in
assignment-ID order, opens the protected chain, and acquires each original
custody journal decision in assignment-ID order. Existing configuration order
is preserved in local comparison IDs. Duplicate, missing, overlapping or
substituted roles are rejected. A partial opening releases only the successfully
acquired owners, in reverse order.

Every owner remains private to the service. Other command owners, chain writers
and custody-journal writers cannot acquire these roots while the service is
open. In particular, custody renewal must wait for this execution placement to
close. Use the service for a bounded operation, rather than keeping an unused
placement open indefinitely. Separate assignments or copied directories do not
become current owners through these local locks.

## Review and action

`Review(ctx)` returns detached original executor, authority, storage and custody
journal state. It reloads the pinned inventory, checks original ownership and
confirmed storage positions, and replays the custody journals. The existing
scheduled-runtime scope/review domains and configured input ordering are
unchanged for existing request versions; service-bound requests use review v2.
Review does not collect a claim or establish live receipt freshness.

`Execute(ctx, reviewID)` calculates that review again while retaining every
owner. A changed or zero ID is rejected. The existing scheduled executor then
replays the complete archive quorum, checks retention and source access, obtains
the original request-wide witness claim when required, and consumes the live
one-use permit at the actual storage target. It reuses the service's exact
held custody decisions; it does not release and reacquire them around execution.

The service serializes actions and returns detached results. Concurrent calls
with the same pre-execution review can apply at most one storage effect. Deletion
does not complete authority tickets, reset spent operations or change custody
receipt history. The complete fenced result remains mandatory on that path.

`Recover(ctx, reviewID)` retains the existing explicit recovery semantics. It
can recover the exact confirmed outcome without repeating deletion. It cannot
reconstruct a lost session signature, resume unconfirmed records, infer that
nothing happened, or replace an observed-effect settlement with a bare effect.
Use the separate [outcome](PRUNE_SCHEDULED_OUTCOMES.md) and
[settlement](PRUNE_SETTLEMENT.md) procedures for those retained states.

## Close and interruption

`Close` waits for an accepted synchronous action, including storage and outcome
publication, before releasing custody decisions, the chain, authority pairs and
executor in reverse acquisition order. Cancellation does not release a live
service automatically; its owner must still call `Close`. The one-shot wrapper
does so on every exit and before producing CLI output.

An uncertain owner or storage write makes that service instance refuse further
actions. Repeated calls return the retained failure without accumulating another
error history. Closing reports the failure and releases locks; it does not alter
the pending record. Reopening preserves the original unknown state for explicit
review and recovery. No missing root, pin journal or session is recreated.

Process death releases kernel ownership while retaining original files. Coverage
includes an idle fully opened service, cuts before and after the storage effect,
the existing fenced claim/result boundaries, competing processes, partial
opening, caller mutation, stale reviews, concurrent execution and close, and
cold recovery with unchanged obligations. CI runs the process recovery campaign.

These are local ownership and controlled process-failure guarantees. They do not
establish independent operators, non-exportable keys, full-machine rollback
protection or physical-device power-loss durability.
