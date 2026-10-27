# V1 custody startup from position zero

The V1 lifecycle can now be prepared, executed and completed through CLI. Its
starting inputs are an existing immutable archive manifest, initial replica
receipt, B's archive objects, explicit custody policy, public role keys and
separate local seed/nonce files. No Go helper is needed to create V1 assignments,
source journals, admissions, challenges, plans, worker state or completions.
This is an operational custody workflow, not consensus activation or mainnet
acceptance.

The [offline guide](REMOTE_CUSTODY_OFFLINE.md) describes canonical publication
and independent actor/authority signing. The [operator guide](REMOTE_CUSTODY_OPERATOR.md)
describes the fixed-session network actions and their explicit recovery paths.

## New local source journals

Use `work-archive-custody-remote-source` independently at A and B. Review is the
default and opens no source or artifact owner. All selected output parents must
exist; source and artifact roots must be disjoint from each other and every
selected metadata directory.

At A:

```sh
omd work-archive-custody-remote-source \
  --role audit \
  --assignment "$ASSIGNMENT" --assignment-id "$ASSIGNMENT_ID" \
  --manifest "$MANIFEST" --receipt "$INITIAL_RECEIPT" \
  --journal "$A_JOURNAL" --artifacts "$A_ARTIFACTS" \
  --max-challenge-lifetime-seconds "$MAX_CHALLENGE_LIFETIME" \
  --max-proof-age-seconds "$MAX_PROOF_AGE" \
  --max-renewal-term-seconds "$MAX_RENEWAL_TERM" \
  --journal-max-bytes "$JOURNAL_MAX_BYTES" \
  --journal-max-paths "$JOURNAL_MAX_PATHS"
```

Review returns a comparison ID binding the selected V1 assignment, local role,
canonical paths and limits. Repeat the exact inputs with `--mode create
--expected-review-id ID` only for new roots. Both destinations are checked before
either is created. The filesystem constructors exclusively claim a new root,
persist its permanent lock and header, and verify their identities before
reporting success. All locks close before output.

At B, use the same immutable archive/assignment/policy with `--role serve
--journal "$B_JOURNAL"`. B cannot select A's `--artifacts`. Do not transfer or
copy either live source, authority or pin root between hosts. Only public
immutable artifacts are distributed. Local paths and lock files do not fence
independent copies of owners or keys.

The source journal retains its existing V0 evidence format. The CLI verifies
that the selected V1 assignment derives from its archive, initial receipt and
policy; it does not add a network authority or assignment grant to that header.

`--mode verify` opens only existing source/lock/header files and reports local
sequence, head and receipt. It creates or repairs nothing. After output loss,
use verify rather than create. Existing or partially initialized roots are never
reset or removed: a partial root is retained for investigation, and normal verify
fails if required files are missing. Failure while creating the second root can
leave the first root intact; there is no automatic rollback or reinitialization.

## Initial Audit admission and challenge

Create the fresh A authority/pin roots with `remote-authority-bootstrap`, and
publish the unsigned intent using `work-archive-custody-audit-intent`. Select the
exact initial receipt, source sequence zero, zero source head, B's transport
peer, fixed times and a separate public nonce file.

Prepare and independently sign/co-sign the Audit Admit using the offline V1
commands at authority position `(0, Assignment.ID)`. The operation is Intent.ID.
Apply the resulting pinned entry at A:

```text
omd work-archive-custody-remote-admission-apply
  --assignment FILE --assignment-id ID
  --manifest FILE --receipt INITIAL_RECEIPT
  --intent FILE --intent-id ID --previous-receipt EXACT_PREDECESSOR
  --authority ORIGINAL_A_ROOT --authority-pins ORIGINAL_A_PINS
  --journal ORIGINAL_A_JOURNAL
  --entry AUDIT_ENTRY --entry-id AUDIT_TICKET_ID --purpose audit
  [the same custody-policy and journal-limit flags]
```

Default review loads no seed, starts no host, appends no entry and closes owners
before reporting. `--mode control` uses dedicated native stdin/stdout pipes on
macOS/Linux. The supervising operator reads the full review before each action:

```text
review
apply REVIEW_ID
close
```

The displayed control ID includes a fresh process nonce and is consumed before
the action. The service compares the original authority position and exact
source predecessor again while holding both original guards through append and
independent intent confirmation. Audit signing alone does not satisfy this gate.
An exact confirmed retry reads retained history; it does not append again.

If an authority attempt is pending, ordinary Apply refuses it. Inspect a fresh
review and issue the separate `resume REVIEW_ID` only for that exact selected
entry. Open, review and Apply never enter this recovery path implicitly.

Now select the confirmed Audit entry using `work-archive-custody-remote-challenge`
with the same public scope/owner/source flags, `--purpose audit`, and
`--artifacts ORIGINAL_A_ARTIFACTS`. Review requires no auditor seed. For explicit
control add `--mode control --auditor-key EXISTING_AUDITOR_SEED`, then use:

```text
review
prepare REVIEW_ID
close
```

The service requires the exact Audit ticket to be confirmed, still pending and
usable under the original A owner. The selected source must still match the
intent's predecessor. It signs only the intent's fixed nonce and times. Original
authority, artifact lock and journal decision remain held through challenge
publication, with input/root/lock identity checks before and after the effect.
An active remote Begin, completed ticket, unapplied proposal, pending authority
attempt, substituted source/artifact root or stale comparison is refused.

The complete review displays `ChallengePath`. It is the canonical retained file
`A_ARTIFACTS/cycle-%020d/challenge.omcc`, using `intent.PriorSequence + 1`.
The result reports Challenge.ID. Read/distribute only those exact public bytes
with their independent ID. If stdout is lost, retain the roots and repeat the
explicit reviewed preparation: the same challenge is revalidated and re-synced,
without a new nonce, issue time or source entry. Preparation never starts B or
completes a ticket.

## Serve admission through independent completion

Sign/co-sign Serve Admit at authority position `(1, AuditTicket.ID)`, selecting
the exact signed challenge. Apply it using `remote-admission-apply --purpose
serve --challenge FILE --challenge-id ID`, retaining the same original A source.
A does not open or copy B's private source journal for this step. B's own runtime
checks its original local source before execution.

Then publish the fixed plan, independently sign/co-sign the Begin proposal at
position `(2, ServeTicket.ID)`, and create B's new record-only worker using the
offline commands. Creating the worker or signing Begin grants no fresh work.
Run the existing B server and A operator commands using these exact public pins
and each host's own local roots/seeds. A's `prepare` is now an exact retry of the
already retained challenge. A must explicitly confirm Begin before Start can
authorize one owned attempt. Seal/drain, terminal capture and each Complete
remain separate reviewed actions.

| Step | Confirmed authority sequence afterward | A/B source sequence afterward |
| --- | ---: | --- |
| Fresh assignment, authority and local sources | 0 | 0 / 0 |
| Apply Audit Admit | 1 | 0 / 0 |
| Prepare signed challenge | 1 | 0 / 0 |
| Apply Serve Admit | 2 | 0 / 0 |
| Publish plan, sign Begin proposal, prepare B worker | 2 | 0 / 0 |
| A confirms Begin | 3 | 0 / 0 |
| Successful owned data exchange | 3 | 1 / 1 |
| Seal B and confirm exact Drain | 4 | 1 / 1 |
| Capture typed terminal | 4 | 1 / 1 |
| Sign/co-sign/apply first Complete | 5 | 1 / 1 |
| Sign/co-sign/apply second Complete | 6 | 1 / 1 |

The two Complete entries use their separately selected admissions and the same
accepted typed terminal. Each explicitly selects its next authority head; no
command silently refreshes it. Use `remote-authority-bootstrap --mode verify`
afterward: `pending_operations=0`, `active_remote=false`,
`retained_attempt=false`, and the exact final sequence/head close this successful
session. These fields describe retained local state, not a remote live grant.

## Acceptance and remaining boundary

The from-zero tests create a new V1 assignment, all source/authority/worker
roots, intent, both admissions, challenge, plan and Begin through CLI. They run
real QUIC, capture the original-A result and independently sign/apply both
completions. A final CLI inspection verifies sequence six with no pending
operations or active remote obligation. The native-process version crosses the
actual dispatcher and pipes for every state-changing step. It deliberately loses
the first admission reply after review and recovers the same confirmed entry
through a new process, without a seventh append or implicit pending resume.

Separate tests cover new/partial root refusal, no-create inspection, source
preflight, missing locks, invalid policy/role/placement, read-only default review,
explicit exact pending recovery, wrong evidence key, active-Begin refusal,
original artifact-root replacement, lost challenge output and exact retry.
The initial output-observer test had a race in its own session assignment; the
observer now uses a pre-created channel, and the corrected race tests pass.

The [acceptance record](evidence/remote-custody-bootstrap-20261027.json) pins the
exact test selection. Focused macOS integration/race checks passed (cmd/omd
121.673 seconds, workarchive 3.769, store 9.954), including the unchanged V0 CLI
process lifecycle. Native Linux/amd64 Go 1.26.7 with CGO_ENABLED=0, offline/read-only
modules and two build workers passed the same selection (cmd/omd 7.777 seconds,
workarchive 0.128, store 1.625; 27.204 seconds including orchestration/build).
No test-group children remained, and its temporary SSH master was closed.

The 619-file Go/module source manifest matched before and after native execution:

```text
6a9237d73e4d1e9d424ed28b89df5dca50d4a020b7f4053a029fc6dc98ed32e7
```

It uses sorted relative paths with SHA256(file bytes), two spaces, path and LF
for each `.go`, `go.mod` and `go.sum` file at this revision. The native evidence
is for one-host command/process acceptance, not same-assignment WAN acceptance.

The first full repository run passed formatting, vet and its Archive race group,
then hit the previous combined group's unchanged ten-minute package deadline.
The currently running test had taken one second; no assertion failure was
reported before the cumulative timeout. The race target now partitions every
test into five disjoint groups: Archive, Prune, remaining, ManagedCustody and
Remote. The default timeout and test set are unchanged.

The partitioned Go 1.26.7 `make -j1 test-all` passed formatting, full vet and all
five race groups. Archive reused its unchanged successful run (store 266.936
seconds); fresh store groups took 323.574, 190.212, 154.074 and 79.510 seconds.
The Go source pin remained unchanged. Integration-tag vet also passed.

Same-assignment cross-host fault/soak acceptance, unknown/unseen disposition
closure, independently enforced key/root copy fencing, device-failure campaigns,
independent audits and sustained public-testnet launch gates remain open.
