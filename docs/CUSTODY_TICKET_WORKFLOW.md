# Reviewed Audit and Serve ticket workflow

The custody ticket commands connect retained unsigned intent preparation to local
Audit/Serve admission and explicit completion. They operate on one existing
original authority, its existing pin journal, and the selected active custody
journal. They do not initialize missing roots or run a network exchange.

| Command | Default | Explicit action |
| --- | --- | --- |
| `work-archive-custody-command-sign` | Review one unsigned consumer command | `--mode sign`: publish the exact consumer-signed command |
| `work-archive-custody-command-cosign` | Review one verified consumer-signed command | `--mode sign`: publish its authority co-signature as an entry |
| `work-archive-custody-terminal` | Review the selected committed terminal result, then close owners | `--mode control`: reviewed `capture` into an immutable file |
| `work-archive-custody-command-apply` | Review one already co-signed entry, then close owners | `--mode control`: reviewed `apply`, or separate explicit `resume` |

A signature does not admit a ticket. Admission takes effect only after the
co-signed entry has been applied and confirmed by the original coordinator.
An exchange or a terminal capture does not complete either ticket. Each
completion needs its own consumer signature, authority co-signature, and local
application.

The ownership checks described here are local. They do not provide a remote
authority broker, cross-host revocation, copied-key fencing, or independent
physical storage. They do not establish mainnet readiness. See
[CUSTODY_AUTHORITY.md](CUSTODY_AUTHORITY.md),
[CUSTODY_MANAGED_RUNTIME.md](CUSTODY_MANAGED_RUNTIME.md), and [PLAN.md](PLAN.md)
for the wider boundaries.

## Inputs and exact flags

All four commands require the following static scope. Input artifacts are
bounded canonical regular files. Independently retained IDs and public keys
must be exact lowercase, nonzero, 32-byte hexadecimal values. Duplicate flags,
unknown flags, and positional arguments are rejected.

| Flag | Meaning |
| --- | --- |
| `--assignment`, `--assignment-id` | Canonical assignment and its independent ID pin |
| `--manifest` | Archive manifest committed by that assignment |
| `--receipt` | The journal's immutable **initial** replica receipt |
| `--intent`, `--intent-id` | Retained unsigned audit intent and its independent ID pin |
| `--previous-receipt` | Exact predecessor receipt whose ID is retained in the intent |
| `--purpose audit\|serve` | Explicitly selected ticket purpose |
| `--max-challenge-lifetime-seconds` | Custody policy bound; default `120` |
| `--max-proof-age-seconds` | Custody policy bound; default `120` |
| `--max-renewal-term-seconds` | Custody policy bound; default `2592000` |

Supply the policy values committed by the assignment. Defaults are not a policy
discovery mechanism. The command reconstructs the assignment from the manifest,
initial receipt, policy, and retained assignment fields and compares its ID.
Trusted auditor keys come from the pinned assignment. The predecessor receipt
must match the intent and the same replica/storage scope. For the first cycle,
`--previous-receipt` may name the same file as `--receipt`.

The new four commands never read a private seed in review mode. In sign mode,
all public content, role, expected-position, and review-ID checks precede the
first seed read. A signer seed is exactly 32 bytes, with distinct consumer and
authority roles. The managed auditor and paired runtime have their own evidence
and transport seed requirements; their review behavior is documented separately
in [CUSTODY_OPERATOR_CLI.md](CUSTODY_OPERATOR_CLI.md).

### Static consumer signing and authority co-signing

Both signing commands accept `--mode review` (the default) or `--mode sign`.
They require `--kind admit|complete`, `--expected-sequence`, and
`--expected-head` in addition to the common scope.

The sequence is an explicit canonical decimal integer, including `0`.
The head is an explicit canonical ID. Sequence zero uses the assignment ID as
the authority head; a later position cannot reuse that genesis head. These
commands never open an authority owner, query a latest head, obtain a peer's
position, refresh a timestamp, or retry by rebuilding the command at a newer
position. Static signing cannot prove that its chosen position is current.

| Selection | Additional required flags | Forbidden flags, including empty values |
| --- | --- | --- |
| Audit Admit | `--consumer-public-key` matching the intent's Audit consumer | `--challenge`, `--challenge-id`, `--admission`, `--admission-id`, `--terminal`, `--terminal-id` |
| Serve Admit | `--consumer-public-key`, `--challenge`, `--challenge-id` | `--admission`, `--admission-id`, `--terminal`, `--terminal-id` |
| Audit or Serve Complete | `--admission`, `--admission-id`, `--terminal`, `--terminal-id` | `--consumer-public-key`, `--challenge`, `--challenge-id` |

Serve may select a different consumer from Audit if the assignment authorizes
that key for Serve. Its signed challenge must exactly match the intent's nonce,
times, sample count, auditor, and predecessor receipt. Complete derives its
consumer from the exact admission. Its selected purpose must match that
admission, although the Complete wire command itself has a zero purpose field.

Co-signing additionally requires `--command`, the exact canonical consumer-signed
command. It verifies that signature and compares every unsigned field with the
draft reconstructed from the supplied public scope.

In review mode, `--out`, `--expected-review-id`, and the role's seed flag are
forbidden, even with empty values. In sign mode, all three are required:

| Command | Seed flag | Output |
| --- | --- | --- |
| `work-archive-custody-command-sign` | `--consumer-key` | Canonical consumer-signed command |
| `work-archive-custody-command-cosign` | `--authority-key` | Canonical authority co-signed entry |

`--expected-review-id` must equal the exact signature-message review ID reported
for that role and those fixed inputs. Consumer and authority review IDs are
different comparisons; neither is an entry ID or a live execution grant.
The output parent must already exist. Publication never replaces a conflicting
file. An exact retained output is verified and reused before any seed read;
this permits recovery of a published artifact after stdout is lost without
signing it again. Keep the same inputs, review ID, and destination for that
retry. Inspect retained state before deciding that any failed invocation had
no effect.

### Owned local application

`work-archive-custody-command-apply` requires `--entry`, `--entry-id`,
`--authority`, `--authority-pins`, and `--journal` in addition to the common
scope. It accepts only already co-signed Audit/Serve Admit or Complete entries;
it has no signer or network execution path.

For an Audit Admit, omit challenge, admission, and terminal flags. For a Serve
Admit, add `--challenge` and `--challenge-id`, and omit admission and terminal
flags. For either Complete, add `--admission`, `--admission-id`, `--terminal`, and
`--terminal-id`, and omit challenge flags. The selected admission must be exactly
the admission inside the terminal envelope.

`--journal` selects the auditor journal for Audit and the replica journal for
Serve. Both commands that open a journal also accept `--journal-max-bytes`
(default `4294967296`) and `--journal-max-paths` (default `262144`). These are
local growth limits, separate from the signed custody policy, and enter the
review comparison.

Default review closes the original coordinator before writing its report. The
report includes confirmed and observed authority positions, a pending attempt
and its entry ID if present, `AlreadyApplied`, and the selected journal's
sequence/head/current receipt. Review does not append or resume an entry.

An Admit application checks the exact intent predecessor in the selected active
journal. A Complete application rechecks the exact terminal against the current
active head and, for a new completion, the selected pending ticket. Checking a
canonical historical entry alone cannot authorize either transition. Exact
already-applied entries can be reported without appending them again, but source
continuity is still required; an old Admit is not a retry path after that journal
has advanced through the exchange.

### Owned terminal capture

`work-archive-custody-terminal` requires `--admission`, `--admission-id`,
`--authority`, `--authority-pins`, and the selected `--journal` in addition to the
common scope and journal limits. Default review forbids `--out` and publishes
nothing. Control mode requires `--out` in an existing parent separate from live
authority/pin/journal roots. The canonical output path enters the control review
ID.

Capture holds the original selected pending-ticket guard and the active journal
decision through immutable file publication. It accepts only the intent's
immediate result at `PriorSequence + 1`, with the exact predecessor and current
head. It does not search an older result beneath an advanced head, choose a
different challenge, promote a standalone receipt/record into a journal commit,
or reconstruct a missing active source.

The terminal envelope includes the assignment ID, full co-signed admission,
retained intent, and committed custody journal entry. Its ID becomes the
Complete command's `EvidenceID`. The renewed receipt ID alone is insufficient.
Audit and Serve have separately bound terminal envelopes even when the exchange
produces the same renewed receipt.

Historical signature and proof verification uses the record's original
`RespondedAt`. Capture and completion do not refresh that time or claim the proof
is fresh now. Current pending-ticket and active-head checks remain separate from
that historical verification. A captured file is historical evidence, not a
portable live grant or a proof that a renewed receipt remains unexpired.

## Supervised control protocol

The two owned commands accept `--mode control`. On macOS/Linux, native stdin
and stdout must be dedicated readable/writable pipes; a terminal or regular
control file is rejected before owners open. An embedded caller must provide
the corresponding interruptible input/output lifetime. Keep stdin open and
drain stdout while the process runs.

1. Consume the complete `work_archive_custody_command_ready` line.
2. Send `review` followed by LF.
3. Consume the review header, all readable `scope` content, and the
   `work_archive_custody_command_scope_end` line.
4. Send the selected action and that process's exact reported review ID.
5. Consume the result, then obtain a new review before another action.
6. Send `close` followed by LF to release the original owner.

| Command | Action line |
| --- | --- |
| Terminal capture | `capture REVIEW_ID` |
| Local application | `apply REVIEW_ID` |
| Explicit pending-attempt recovery | `resume REVIEW_ID` |

A one-shot review ID cannot substitute for a same-session control token. The
token includes the underlying observation and displayed local scope, including
the terminal output path where applicable. It becomes usable only after the
complete readable report has been written and is consumed before the action.
The service compares live state again while holding the original coordinator
and active source decision. A changed observation requires another review;
the token does not freeze other operations or confer authority.

`apply` rejects every pending authority attempt, including an equal entry. The
separate `resume` verb requires a new fully reported review, a pending attempt
equal to the selected co-signed entry, and the exact reviewed authority positions
and current source evidence. The observed authority can still be at the confirmed
predecessor, or already contain that attempted entry while pin confirmation is
pending; both positions are reported and compared. Resume cannot choose or repair
an unrelated pending attempt. Open, review, and normal application never resume
automatically.

Input lines are bounded, complete, LF-terminated commands, with at most one
queued line. Wait for each response. Partial input followed by EOF is an error;
clean EOF cancels the session. SIGINT/SIGTERM, cancellation, and I/O failure drain
the runtime and release owners. A nonzero result can follow an already committed
append or published terminal. Preserve files and inspect the exact original
authority, pins, journals, and selected entry before a new reviewed action.

## Full sequence for one fresh cycle

The following order starts from an existing empty coordinated authority and two
existing active journals for the same assignment. Bootstrap, object import,
independent pin retention, and key generation are separate prerequisites.
Other commands may already occupy authority positions in a real deployment;
then use the explicitly reviewed retained position instead of the illustrative
sequence numbers below.

| Step | Authority transition | Custody journal effect |
| --- | --- | --- |
| Retain unsigned intent | None | None |
| Sign, co-sign, apply Audit Admit | `0 / AssignmentID` → `1 / AuditTicketID` | Check auditor predecessor |
| Managed auditor `prepare` | None | Retain exact signed challenge |
| Sign, co-sign, apply Serve Admit | `1 / AuditTicketID` → `2 / ServeTicketID` | Check replica predecessor |
| Managed paired `exchange` | None | Commit the exact result in both journals |
| Capture Audit and Serve terminals | None | Read each selected current `prior+1` head |
| Sign, co-sign, apply Audit Complete | `2 / ServeTicketID` → `3 / AuditCompleteID` | Recheck auditor terminal/head |
| Sign, co-sign, apply Serve Complete | `3 / AuditCompleteID` → `4 / ServeCompleteID` | Recheck replica terminal/head |

The authority genesis head is the assignment ID. The custody journal's initial
predecessor head is zero. They are different histories and must not be
interchanged. Do not advance either selected custody journal into a later cycle
while its completion still depends on this current-head terminal.

The examples below use shell arrays only to retain the exact same argument
values. Populate uppercase variables with independently reviewed paths, IDs,
policy limits, and role-specific seeds. Every source/root and output parent
already exists. Control invocations require the supervisor's dedicated pipes
as described above; do not run them against terminal stdin/stdout.

```sh
scope=(
  --assignment "$ASSIGNMENT_FILE" --assignment-id "$ASSIGNMENT_ID"
  --manifest "$MANIFEST_FILE" --receipt "$INITIAL_RECEIPT_FILE"
  --intent "$INTENT_FILE" --intent-id "$INTENT_ID"
  --previous-receipt "$PREVIOUS_RECEIPT_FILE"
  --max-challenge-lifetime-seconds "$CHALLENGE_LIFETIME"
  --max-proof-age-seconds "$PROOF_AGE"
  --max-renewal-term-seconds "$RENEWAL_TERM"
)
owner=( --authority "$AUTHORITY_ROOT" --authority-pins "$AUTHORITY_PINS_ROOT" )
limits=( --journal-max-bytes "$JOURNAL_MAX_BYTES" --journal-max-paths "$JOURNAL_MAX_PATHS" )
```

### 1. Retain the unsigned intent

Use `work-archive-custody-audit-intent` to review and then explicitly publish the
fixed intent. Its required construction fields include consumer/auditor public
keys, replica transport ID, prior sequence/head/receipt, issue/expiry/renewal
times, sample count, and an existing separate 32-byte cryptographic nonce file.
For the first cycle, retain `prior-sequence=0`, the zero custody predecessor
head, and the initial receipt ID. Repeat the same construction with
`--mode publish --intent-id INTENT_ID`; then retain that canonical ID. See the
complete invocation in [CUSTODY_OPERATOR_CLI.md](CUSTODY_OPERATOR_CLI.md#retain-an-unsigned-audit-intent).
No challenge has been signed at this point.

### 2. Admit Audit

```sh
audit_admit=(
  "${scope[@]}" --kind admit --purpose audit
  --expected-sequence 0 --expected-head "$ASSIGNMENT_ID"
  --consumer-public-key "$AUDIT_CONSUMER_PUBLIC_KEY"
)
omd work-archive-custody-command-sign "${audit_admit[@]}"
```

Read and retain `AUDIT_COMMAND_REVIEW_ID` from that complete review. Then:

```sh
omd work-archive-custody-command-sign "${audit_admit[@]}" --mode sign \
  --consumer-key "$AUDIT_CONSUMER_SEED" \
  --expected-review-id "$AUDIT_COMMAND_REVIEW_ID" --out "$AUDIT_COMMAND_FILE"

omd work-archive-custody-command-cosign "${audit_admit[@]}" \
  --command "$AUDIT_COMMAND_FILE"
```

Read the separate authority review and retain `AUDIT_ENTRY_REVIEW_ID`. Then:

```sh
omd work-archive-custody-command-cosign "${audit_admit[@]}" \
  --command "$AUDIT_COMMAND_FILE" --mode sign --authority-key "$AUTHORITY_SEED" \
  --expected-review-id "$AUDIT_ENTRY_REVIEW_ID" --out "$AUDIT_ADMISSION_FILE"
```

Retain the reported co-signed `entry_id` as `AUDIT_TICKET_ID`. Review local
application without a signer:

```sh
omd work-archive-custody-command-apply "${scope[@]}" "${owner[@]}" "${limits[@]}" \
  --purpose audit --journal "$AUDITOR_JOURNAL" \
  --entry "$AUDIT_ADMISSION_FILE" --entry-id "$AUDIT_TICKET_ID"
```

Start the same application invocation with `--mode control` on dedicated pipes.
In that process, perform `review`, consume the complete scope, then send
`apply REVIEW_ID`. Consume the result and close it. A signature file alone does
not make the subsequent managed auditor admissible.

### 3. Prepare the admitted Audit challenge

Use `work-archive-custody-managed-audit-quic` with the existing assignment,
manifest, **initial** receipt, original authority/pins, auditor journal, artifact
root, intent/ID, auditor evidence seed, and auditor transport-ID pin. Its
admission flags are `--admission "$AUDIT_ADMISSION_FILE"` and
`--ticket-id "$AUDIT_TICKET_ID"`; the new ticket commands use
`--admission-id` instead. Supply the same custody policy and journal limits.

After default review, run that managed auditor under supervised control. Send
`review`, then `prepare REVIEW_ID` using its fully reported same-session token.
Retain the returned signed `CHALLENGE_ID` and canonical challenge file. Its
path is `ARTIFACT_ROOT/cycle-%020d/challenge.omcc`, where the decimal cycle number
is `PriorSequence + 1`; the first is `cycle-00000000000000000001`.
`prepare` uses the retained nonce and times. Close the auditor before reopening
the same original authority for Serve admission. The exact managed-auditor
flags and control contract are in
[CUSTODY_OPERATOR_CLI.md](CUSTODY_OPERATOR_CLI.md#owned-auditor).

### 4. Admit Serve for that exact signed challenge

```sh
serve_admit=(
  "${scope[@]}" --kind admit --purpose serve
  --expected-sequence 1 --expected-head "$AUDIT_TICKET_ID"
  --consumer-public-key "$SERVE_CONSUMER_PUBLIC_KEY"
  --challenge "$CHALLENGE_FILE" --challenge-id "$CHALLENGE_ID"
)
omd work-archive-custody-command-sign "${serve_admit[@]}"
```

Repeat the two-role review/sign/co-sign procedure from Audit with distinct
Serve command/entry review IDs, `SERVE_CONSUMER_SEED`, `SERVE_COMMAND_FILE`, and
`SERVE_ADMISSION_FILE`. Retain its co-signed `entry_id` as `SERVE_TICKET_ID`.
The signing and co-signing invocations keep `serve_admit` unchanged.

```sh
omd work-archive-custody-command-apply "${scope[@]}" "${owner[@]}" "${limits[@]}" \
  --purpose serve --journal "$REPLICA_JOURNAL" \
  --entry "$SERVE_ADMISSION_FILE" --entry-id "$SERVE_TICKET_ID" \
  --challenge "$CHALLENGE_FILE" --challenge-id "$CHALLENGE_ID"
```

Use a new supervised process with the same arguments plus `--mode control`,
then its complete `review` and explicit `apply REVIEW_ID`. Close it before
opening the pair.

### 5. Exchange through the owned local pair

Open `work-archive-custody-managed-pair-quic` with both exact admission files and
`--audit-ticket-id`/`--serve-ticket-id`, the retained intent/ID and challenge ID,
same original authority/pins, both journals, artifact root, and verified object
store. It also needs auditor and replica evidence seeds, separate auditor and
replica transport seeds/ID pins, the matching policy, and effective local limits.
The pair does not accept the new commands' `--purpose`, `--previous-receipt`, or
`--admission-id` flags; use its explicit flag mapping in
[CUSTODY_OPERATOR_CLI.md](CUSTODY_OPERATOR_CLI.md#owned-local-pair).

Default review exchanges nothing. Under supervised `--mode control`, send
`review`, consume its complete scope, then `exchange REVIEW_ID`. Consume the
result and close the pair. A successful exchange commits the exact renewal in
both selected journals and leaves both authority tickets pending. Failure or
lost stdout may leave one or both journals committed; inspect those retained
positions and use the separate managed exact-recovery workflow where valid.

### 6. Capture both terminals

Review the Audit terminal:

```sh
omd work-archive-custody-terminal "${scope[@]}" "${owner[@]}" "${limits[@]}" \
  --purpose audit --journal "$AUDITOR_JOURNAL" \
  --admission "$AUDIT_ADMISSION_FILE" --admission-id "$AUDIT_TICKET_ID"
```

For capture, start the same arguments with `--mode control --out
"$AUDIT_TERMINAL_FILE"` on dedicated pipes. Perform the complete `review`, then
`capture REVIEW_ID`. Retain the reported `terminal_id` as `AUDIT_TERMINAL_ID`;
close the process. Default review cannot be given `--out`.

Repeat with `--purpose serve`, `--journal "$REPLICA_JOURNAL"`,
`--admission "$SERVE_ADMISSION_FILE"`, `--admission-id "$SERVE_TICKET_ID"`, and a
separate `SERVE_TERMINAL_FILE`. Retain its `SERVE_TERMINAL_ID`. Neither capture
submits completion. Capture both before moving either selected journal to a
later cycle.

### 7. Complete Audit

```sh
audit_complete=(
  "${scope[@]}" --kind complete --purpose audit
  --expected-sequence 2 --expected-head "$SERVE_TICKET_ID"
  --admission "$AUDIT_ADMISSION_FILE" --admission-id "$AUDIT_TICKET_ID"
  --terminal "$AUDIT_TERMINAL_FILE" --terminal-id "$AUDIT_TERMINAL_ID"
)
omd work-archive-custody-command-sign "${audit_complete[@]}"
```

Review/sign with the admission's Audit consumer seed, then independently
review/co-sign with the authority seed, following the same static procedure.
Use new immutable `AUDIT_COMPLETE_COMMAND_FILE` and `AUDIT_COMPLETE_ENTRY_FILE`
destinations and retain the co-signed `AUDIT_COMPLETE_ID`.

```sh
omd work-archive-custody-command-apply "${scope[@]}" "${owner[@]}" "${limits[@]}" \
  --purpose audit --journal "$AUDITOR_JOURNAL" \
  --entry "$AUDIT_COMPLETE_ENTRY_FILE" --entry-id "$AUDIT_COMPLETE_ID" \
  --admission "$AUDIT_ADMISSION_FILE" --admission-id "$AUDIT_TICKET_ID" \
  --terminal "$AUDIT_TERMINAL_FILE" --terminal-id "$AUDIT_TERMINAL_ID"
```

After default review, use the same arguments in a new supervised control
process and explicitly review/apply/close. Its `EvidenceID` is the Audit terminal
envelope ID. This closes only Audit.

### 8. Complete Serve independently

```sh
serve_complete=(
  "${scope[@]}" --kind complete --purpose serve
  --expected-sequence 3 --expected-head "$AUDIT_COMPLETE_ID"
  --admission "$SERVE_ADMISSION_FILE" --admission-id "$SERVE_TICKET_ID"
  --terminal "$SERVE_TERMINAL_FILE" --terminal-id "$SERVE_TERMINAL_ID"
)
omd work-archive-custody-command-sign "${serve_complete[@]}"
```

Review/sign with the Serve admission's consumer seed and independently
review/co-sign with the authority seed into new Serve completion files. Retain
`SERVE_COMPLETE_ID`. Review and then explicitly apply it with:

```sh
omd work-archive-custody-command-apply "${scope[@]}" "${owner[@]}" "${limits[@]}" \
  --purpose serve --journal "$REPLICA_JOURNAL" \
  --entry "$SERVE_COMPLETE_ENTRY_FILE" --entry-id "$SERVE_COMPLETE_ID" \
  --admission "$SERVE_ADMISSION_FILE" --admission-id "$SERVE_TICKET_ID" \
  --terminal "$SERVE_TERMINAL_FILE" --terminal-id "$SERVE_TERMINAL_ID"
```

The new control process still needs its own complete `review` and explicit
`apply REVIEW_ID`. Serve completion is signed at the fixed position after Audit
completion; a Serve completion pre-signed at the preceding head is not silently
refreshed. The final confirmed authority position in this otherwise empty
example is sequence `4`, head `SERVE_COMPLETE_ID`. Keep both terminal files,
co-signed entries, retained intent, and independent pins as historical evidence.
