# V1 remote custody preparation and offline signatures

These opt-in commands prepare immutable public inputs for the existing
[remote operator/server commands](REMOTE_CUSTODY_OPERATOR.md). They neither
start a host nor establish current authority. Version-0 signing commands keep
their existing version checks and bytes.

| Command suffix after `work-archive-custody-remote-` | Default | Explicit actions |
| --- | --- | --- |
| `assignment` | `review` | `publish` a fresh V1 assignment |
| `authority-bootstrap` | `review` placement | `create` both new A roots; `verify` existing roots |
| `plan` | `review` | `publish` one fixed session plan |
| `command-sign` | `review` without a seed | `sign` an Admit, Begin proposal or Complete |
| `command-cosign` | `review` without a seed | `sign` the authority co-signature |
| `worker-prepare` | `review` placement | `create` a new B-local worker; `verify` an existing worker |

Every output parent must already exist. Publication preserves exact canonical
bytes with no replacement, syncs the file and parent, and rejects an output
aliasing a verified input. A conflicting retained artifact is an error. No
command invents an issue time, successor position or nonce.

## Assignment and authority roots

Starting inputs are an existing archive manifest and initial replica receipt,
explicit custody policy, fresh incarnation, role public keys and bounded
admission/pending budgets. Public keys are lowercase 64-digit hexadecimal.
Auditors and consumers must be sorted by their public-key bytes, without
duplicates. Each consumer must declare its actual purpose set; the union must
cover Audit, Serve and Prune. All evidence, consumer, authority, B control and B
transport keys must be separate, as required by the V1 assignment codec.

For example, with reviewed values supplied as shell variables:

```sh
omd work-archive-custody-remote-assignment \
  --manifest "$MANIFEST" --receipt "$INITIAL_RECEIPT" \
  --incarnation-id "$INCARNATION_ID" \
  --authority-public-key "$AUTHORITY_PUBLIC" \
  --auditor-public-keys "$SORTED_AUDITOR_PUBLIC_KEYS" \
  --consumers "$SORTED_CONSUMERS" \
  --remote-control-public-key "$B_CONTROL_PUBLIC" \
  --remote-transport-public-key "$B_TRANSPORT_PUBLIC" \
  --max-operations 16 --max-pending 4 \
  --max-challenge-lifetime-seconds 120 \
  --max-proof-age-seconds 120 --max-renewal-term-seconds 86400
```

`SORTED_CONSUMERS` has the form `PUBLIC_KEY:audit+serve+prune` for one
all-purpose consumer, or comma-separated individually scoped members. The
budgets and policy above illustrate syntax; choose the actual reviewed values.
Retain the complete displayed assignment and `assignment_id`. Repeat the same
inputs with `--mode publish --assignment-id ID --out FILE`. This produces a new
V1 identity; it does not migrate an existing V0 assignment or enrollment.

Review A's two separately placed roots:

```sh
omd work-archive-custody-remote-authority-bootstrap \
  --assignment "$ASSIGNMENT" --assignment-id "$ASSIGNMENT_ID" \
  --authority "$A_AUTHORITY" --authority-pins "$A_PINS"
```

The review ID commits the assignment and canonical root paths. Review opens no
owner and does not inspect retained journal contents. Repeat with `--mode create
--expected-review-id ID` only for two new roots. Existing or partially created
roots are never reset, removed or attached to new pins. After lost output, use
`--mode verify` against the same roots; it reports confirmed position and retained
attempt without implicitly settling it. Both owners close before success output.
Separate filesystem paths do not prove independent devices or copy fencing.

## Static signing scope

All signing and plan commands require:

```text
--assignment FILE --assignment-id ID
--manifest FILE --receipt INITIAL_RECEIPT
--intent FILE --intent-id ID --previous-receipt EXACT_PREDECESSOR
--max-challenge-lifetime-seconds N
--max-proof-age-seconds N --max-renewal-term-seconds N
```

The existing `work-archive-custody-audit-intent` command can publish the unsigned
intent. Select the V1 assignment and B's pinned transport peer ID, the exact
predecessor sequence/head/receipt, fixed times and a separately retained nonce
file. The new signing scope independently derives the V1 assignment from the
archive/policy and verifies the intent's consumer, auditor, B transport,
predecessor and time constraints before accessing a private seed.

For each unsigned draft select `--expected-sequence N --expected-head ID`.
These are explicit historical compare-and-append inputs. The command never
queries a live root or substitutes a newer position.

| `--kind` / `--purpose` | Additional public inputs |
| --- | --- |
| `admit` / `audit` | `--consumer-public-key`; commits the unsigned Intent.ID; challenge flags are rejected |
| `admit` / `serve` | `--consumer-public-key`, `--challenge FILE --challenge-id ID`; commits the verified signed challenge |
| `begin` / `serve` | Signed challenge and `--plan FILE --plan-id ID`; actor is the pinned B control role |
| `complete` / `audit` or `serve` | Signed challenge, plan, `--begin FILE --begin-id ID`, `--admission FILE --admission-id ID`, `--terminal FILE --terminal-id ID` |

Complete verifies the full typed remote terminal, exact selected admission and
intent, original Begin, sealed Drain and successful original-A result. The two
tickets require separate Complete drafts and separate exact authority positions.
Unknown, unseen, B-only or A-rejected results cannot be represented as successful
completion, including a response rejected for expiry. Already accepted terminal
evidence is checked at its original response time without refreshing that time.

Run `command-sign` with the public scope and selected kind/purpose to obtain the
exact command `review_id`. Review rejects seed/output/signing flags. Repeat the
same inputs with:

```text
--mode sign --expected-review-id ID --actor-key EXISTING_SEED_FILE --out COMMAND
```

The actor seed is the selected consumer for Admit/Complete or B control for
Begin. Seeds are existing regular 32-byte Ed25519 seed files. Public pins, full
scope and review equality are checked before the first seed read.

For A's independent co-signature, repeat the same public selection using
`command-cosign --command COMMAND`. Review verifies the actor signature and exact
unsigned draft, then returns a different authority `review_id`. Repeat with:

```text
--mode sign --expected-review-id ID --authority-key EXISTING_SEED_FILE --out ENTRY
```

Retain the resulting entry and `entry_id`. Co-signing does not apply an entry or
prove a current grant. After output loss, repeat the exact signing invocation:
the command verifies and syncs an existing identical output before reading the
seed, so the same artifact can be recovered even when the seed is unavailable.
No signature is replaced and no position or nonce is refreshed.

Offline Drained signing is deliberately unavailable in this CLI. Only the
owned B runtime can produce it after durable sealing and actual callback drain.
A pre-signed Begin proposal likewise cannot enable execution by itself.

## Plan and B worker

`plan` consumes the static scope above plus:

```text
--challenge FILE --challenge-id ID
--admission SERVE_ENTRY --admission-id SERVE_TICKET_ID
--authority-transport-public-key A_CONTROL_TRANSPORT_PUBLIC
--audit-transport-public-key A_AUDIT_TRANSPORT_PUBLIC
--nonce-file EXISTING_32_BYTE_NONZERO_NONCE
```

Both A transport keys must be distinct from one another and every assignment
role. The plan commits the original intent's exact predecessor, complete signed
Serve admission and explicit plan nonce. Review returns `plan_id` and the public
plan; publish repeats the same inputs with `--mode publish --plan-id ID --out
FILE`. An existing nonce file is consumed unchanged, never generated or replaced.
Its bytes become public plan data; use a separate public nonce, never a private
key seed.

After separately reviewing and co-signing Begin, use `worker-prepare` with the
static scope, signed challenge, pinned plan and Begin, and `--worker NEW_B_ROOT`.
The root must be disjoint from all selected metadata directories. Review returns
a placement/session `review_id` without opening or creating a worker. Repeat
with `--mode create --expected-review-id ID` to create its record-only Prepared
state. An existing or partial worker is never reinitialized. `--mode verify`
opens only the existing worker, reports stage/pending state and closes it without
Start, Seal, signature or automatic recovery. In particular it does not seal an
already Started worker.

## Acceptance and remaining bootstrap work

Tests compare assignment, admission, plan and Begin bytes against the canonical
V1 codecs; reject substituted scope, purpose, role, predecessor and review;
exercise no-replace output and exact signature retries without seeds after lost
stdout; and check new-root review/create/verify semantics. Actual subprocesses
exercise dispatch, both signatures and fresh authority roots. The real-QUIC CLI
workflow now obtains both independent completion signatures through these
commands before applying them under the original owner. Focused macOS integration/
race checks passed (cmd/omd 25.331 seconds, authority 2.666, store 3.290).

Native Linux/amd64 Go 1.26.7 with CGO_ENABLED=0, offline dependencies, read-only
modules and two build workers passed the same selected tests, including actual
command subprocesses (cmd/omd 3.738 seconds, authority 0.012, store 0.468; 21.942
seconds including orchestration/build). No test-group children remained afterward;
the temporary SSH master was closed. This is one-host native acceptance, not WAN
acceptance. Its 611-file Go/module source manifest matched before and after:

```text
5b56e0b2d250ff674bd9401835fce468b2e310b7473c591578ea3f1364d6aee1
```

The [acceptance record](evidence/remote-custody-offline-20261027.json) records the
exact test selection and platform boundaries. The manifest uses sorted relative
paths and SHA256(file bytes), two spaces, path and LF for every tracked/new `.go`,
`go.mod` and `go.sum` file at this revision.

Go 1.26.7 `make -j1 test-all` also passed formatting, full vet and all three
disjoint repository race groups (store 220.276, 508.010 and 170.233 seconds).
No timeout extension was used and the source manifest remained unchanged.
Integration-tag vet also passed.

This was the offline preparation slice. The subsequent
[position-zero workflow](REMOTE_CUSTODY_BOOTSTRAP.md) now covers initial A/B
source journals and source-guarded V1 admission/challenge preparation before a
Plan/Begin exists. It uses a separate pre-Begin challenge command; the operator's
later `prepare` action consumes the complete fixed session. Same-assignment WAN
fault/soak acceptance, negative-disposition closure, independent copy fencing and
mainnet gates remain open. Do not copy live authority, pin or source journals.
