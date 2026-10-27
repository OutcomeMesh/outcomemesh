# Independent custody witness protocol — experimental foundation

`node/custodyfence` implements a separate bounded protocol and durable witness
journal. It moves non-equivocation locks outside the two copied participants.
It is not integrated into V0/V1 assignments, custody transport, proof acceptance,
ticket completion or consensus. It does not close the independent fencing gate.

## Scope and fault assumptions

An independently pinned immutable scope binds the assignment, intent, plan and
Begin IDs, distinct owner/controller control keys, and a sorted unique witness
set. It requires 4–16 witnesses and a threshold strictly greater than two thirds
of the set. The usual four-member configuration needs three signatures. Fewer
than one third of witnesses may equivocate or lose/clone their durable locks.
Witness keys must differ from both participant control keys. They are held by
independently operated services, never distributed to A or B.

Any two valid quorums intersect in more witnesses than the allowed faulty set.
At least one honest witness in that intersection retains its single proposal at
that position and refuses a conflict. Copying A/B's control keys and complete old
journals therefore cannot obtain a second conflicting quorum, provided the
witness assumptions and pinned scope are preserved. A copied witness key counts
as a faulty witness; copying enough witnesses invalidates this assumption.

The new assignment must bind the exact scope ID before use. Merely including an
assignment ID in an independently created scope would let an attacker choose a
fresh scope for the same work. The future adapter must reject that substitution,
check witness separation from every other participant role, and prohibit legacy
downgrades. Those adapter rules are not implemented in V1 by this package.

Do not attach a fresh unused scope to an existing V1 session to clear its
uncertainty. A newly created witness history cannot exclude an earlier execution
that never required its claim. V1's original Serve obligation remains pending.

## Outcome rules

There is one slot and at most three transitions. Its initial position has
sequence zero and head equal to the scope ID.

| Transition | Required phase | Signer | Result |
| --- | --- | --- | --- |
| Claim | Unused | Owner | Fixes one claim ID; holds the obligation. |
| MarkUnknown | Claimed | Controller | Records an observation for the exact claim; keeps the obligation. |
| RecordResult | Claimed or Unknown | Owner | Commits one result/evidence ID for the same claim; keeps the obligation. |
| CloseUnclaimed | Unused | Controller | Closes this scope before a quorum claim; forbids all later claims. |

Each command names the exact prior sequence/head. Unknown cannot become Unused,
change owner, acquire another claim or close as unclaimed. A later result is
attached to the original claim, not another execution. There is no clock, TTL,
lease expiration, timeout, force-complete, membership change or reset operation.
Uncertainty and the obligation survive every replay. The history retains the
earlier unknown observation even when a result is subsequently recorded.

Evidence IDs are opaque immutable commitments. Witnesses do not verify archive
chunks, proof age or acceptance in A's source. RecordResult does not establish
successful custody or release any ticket. CloseUnclaimed proves no quorum claim
in this pinned scope under the stated assumptions, not absence of physical work
through another interface. Neither votes nor historical certificates are current
permission to execute an effect.

## Durable witness

`Create` explicitly enrolls a new private root and member key. It refuses an
existing/partial root. Deployment enrollment must prevent duplicate enrollment
of one member key; missing storage must not trigger Create. `Open` requires an
independently retained exact position, including the pending proposal ID, and
only replays existing files. It does not sign or create anything.

`Vote` checks the current state, persists the complete owner/controller-signed
proposal using no-replace publication, syncs the file and directory, and only
then exposes its witness signature. The permanent kernel lock serializes native
owners. An exact retry rechecks bytes and syncs them again before signing. A
conflict is rejected before another vote. A crash before signature output leaves
the durable lock in place. Existing partial files are retained and fail closed.

`Commit` requires a complete valid quorum certificate and persists it before
updating state. A minority witness that voted differently may follow an actually
certified transition; its old vote remains immutable evidence on disk. Different
valid quorum subsets for the same command produce the same transition/head ID.
This avoids a fork caused solely by certificate signature selection.

Any uncertain write poisons that owner. Close it and explicitly use RecoverVote
with the retained pre-attempt pin and full exact command, or RecoverCommit with
the exact attempted certificate. Recovery accepts only the original state or
the particular pending/one-transition extension. It does not sign or implicitly
submit anything. Another explicit Vote/Commit is necessary. Open with an old pin
cannot silently adopt a newer position. Root/lock replacement, changed private
permissions, unexpected files and altered history fail closed. Directory reads,
record sizes and transition counts are bounded.

Native locking is implemented on Darwin and supported Unix platforms, including
Linux. Unsupported platforms fail enrollment/opening. These are local filesystem
durability rules, not physical-device power-loss certification.

## Formats and checks

The package uses its own format version zero, unrelated to custody assignment
version zero. Scope/command/vote/certificate magic values are `OMCFSC00`,
`OMCFCM00`, `OMCFVT00` and `OMCFQC00`. Domains have the prefix
`OMESH/custody-fence/` and distinct scope ID, command ID, command signature and
vote signature suffixes ending in `/v0`. Commands are 211 bytes and votes 138;
all arrays/counts are bounded. Witness keys/votes are strictly ordered and unique.
Decoders reject unknown versions, malformed lengths and trailing bytes.

Decoding a command checks its shape; `Verify(scope)` additionally authenticates
the selected owner/controller. A certificate additionally authenticates witness
membership, threshold and all signatures. State/Witness entry points perform
these scope-specific checks before changing state or signing.

The deterministic test scope ID is
`d4e3af76f965480b597aff058092e5cf40d34d7612378febd6a464dfde49571b`;
its first claim ID is
`43779ea010f7d43645d85f69647c6588e602f825ce44330db32bb431ff1313e7`.
Fixed vectors and fuzz tests protect the encoding. Tests cover quorum subsets,
role/scope substitution, copied-owner conflicting results, one compromised
witness, persistence uncertainty, concurrent conflicts, exact recovery and real
process death after directory sync but before signature release.

## Required integration before deployment

1. Introduce an explicitly versioned assignment and mandatory fence certificates
   on every effect/result/acceptance path. Reject unsigned, wrong-scope and legacy
   bypasses. The effect target must enforce consumption/deduplication as well as
   the result verifier: one copied historical claim cannot be a reusable grant.
2. Deploy independent witness services with authenticated bounded transport,
   protected keys and monotone recovery pins outside participant backups. Test
   actual distinct failure domains, stale witness recovery, partitions and copy
   attempts. A rollback of all witnesses/pins is not detected by local file checks.
3. Bind each result commitment to the complete typed custody evidence and A's
   accepted source. Define which independently certified disposition can close
   Serve while preserving retention and all other obligations.
4. Add safe progress/recovery for split votes. This foundation deliberately
   stalls if proposals split without a quorum; it has no view-change algorithm.
   Do not restore progress by discarding old locks or selecting a timeout winner.
5. Run the full native/WAN acceptance, device campaigns and independent review.

The [negative Audit workflow](REMOTE_CUSTODY_NEGATIVE.md) remains within V1's
original-owner trusted-key boundary. The [placement profile](REMOTE_CUSTODY_PLACEMENT.md)
continues to detect local substitutions. Neither is silently upgraded to this
experimental witness protocol.
