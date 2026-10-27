# Remote custody operator and server commands

Two opt-in commands supervise the existing fixed-session V1 protocol:

- `omd work-archive-custody-remote-audit`: A's original authority/Audit owner.
- `omd work-archive-custody-remote-serve`: B's separate worker/Serve owner.

Both default to `--mode review`. Review starts no listener, signs no challenge,
submits no authority entry, and closes owners before writing its report. In
particular, B inspection releases its existing worker lock without invoking the
live service's irreversible sealing Close. Missing roots are never initialized.
`--mode control` explicitly retains owners on dedicated stdin/stdout pipes on
macOS/Linux. This mode is intended for a supervising operator, not a terminal
with an unattended open listener.

## Existing public inputs

Every invocation requires canonical existing files and independent pins:

```text
--assignment FILE --assignment-id ID
--plan FILE --plan-id ID
--begin FILE --begin-id ID
--manifest FILE --receipt FILE --previous-receipt FILE --challenge FILE
--journal ORIGINAL_LOCAL_JOURNAL
--control-key LOCAL_CONTROL_SEED --key LOCAL_TRANSPORT_SEED
```

Assignment, plan, Begin, archive, predecessor, policy and signed challenge are
checked before seeds are read. Policy flags are the existing
`--max-challenge-lifetime-seconds`, `--max-proof-age-seconds` and
`--max-renewal-term-seconds`; they must derive the assignment's committed policy.
Journal/object count and byte budgets remain explicit local limits.
`--timeout` is 100ms..2m, with a 10s default. `--listen` selects a direct canonical
IP/UDP/QUIC-v1 address and defaults to loopback with an ephemeral port.

The [V1 offline preparation commands](REMOTE_CUSTODY_OFFLINE.md) now create the
assignment, authority roots, plan, Begin proposal and B worker, and separately
sign/co-sign Audit/Serve admissions and successful completions. Initial source
journals and source-guarded admission/challenge preparation before Plan/Begin
still require the SDK; the full position-zero CLI workflow remains open.
Existing V0 signing commands do not silently accept V1. No private seed belongs
in a command-line value: seed flags name existing regular 32-byte seed files.

## B server

B additionally requires `--worker`, `--objects` and `--replica-key`. Its
`--control-key` is B's command-signing role; `--key` is B's independent transport.
B cannot select A's authority/pin roots, intent, audit keys or result artifacts.

Control starts with a `remote_custody_ready` line and no listener. Send `review`,
read the complete `remote_custody_review` and JSON scope through
`remote_custody_scope_end`, then send:

```text
serve REVIEW_ID
```

The runtime compares the displayed state again under its own control lock before
installing the pinned host. `remote_custody_serving` reports its actual routes.
Fresh signing still requires the authenticated A-control Start from the original
confirmed A owner; starting this listener itself grants no custody work.

`close`, EOF, a signal, malformed control or lost output triggers full service
shutdown. Live control's shutdown retains a sealed/uncertain worker branch,
stops data admission and drains data/control callbacks before releasing its lock.
It never clears A's remote obligation. Default one-shot review does not seal.

## A operator

A additionally selects:

```text
--authority ORIGINAL_A_ROOT --authority-pins ORIGINAL_A_PINS
--intent FILE --intent-id ID
--audit-admission FILE --audit-ticket-id ID
--artifacts ORIGINAL_A_ARTIFACTS
--authority-key AUTHORITY_SEED --auditor-key AUDITOR_EVIDENCE_SEED
--peer PINNED_B_MULTIADDRESS
--drain DEDICATED_METADATA_FILE --terminal DEDICATED_TERMINAL_FILE
```

Here `--control-key` is A's independent control transport; `--key` is A's
different Audit transport. A cannot select B's worker/object roots or proof key.
The peer route must identify the B transport committed in the assignment.
Outputs have existing dedicated parents outside every original protected root
and the intent directory. Publication never replaces different existing bytes.

Each action requires a complete fresh `review` report and its one-use same-process
ID. The ID binds public scope, actual root positions, pending state, source head,
local limits, selected artifact IDs, configured input/output paths, route and
listen address. A random process nonce prevents a report from another process
being reused. The underlying runtime compares the base state again under its
original authority lock immediately before any effect.

```text
review
prepare REVIEW_ID
review
begin REVIEW_ID
review
execute REVIEW_ID
review
seal REVIEW_ID
review
capture REVIEW_ID
close
```

Do not literally reuse `REVIEW_ID`: consume each newly displayed value only
after reading the full scope. `prepare` explicitly retains the exact challenge;
`begin` confirms the configured Begin before `execute` can send Start.
`execute` accepts a fresh/cached response only through A's original Audit source.
`seal` explicitly closes B, confirms A's Drain and durably publishes metadata.
`capture` publishes the typed terminal while holding the same original authority
and source decision through the file's durable publication.

## Retained artifacts and explicit recovery

The portable drain artifact uses the canonical metadata-response encoding, with
the exchange nonce normalized to the immutable Seal.ID. Its separate ID domain
is `OMESH/custody-authority/remote-drain-artifact/id/v0`. It is historical signed
metadata, not a retained live-channel acknowledgement. Fresh exchange nonces
therefore do not change the artifact on an exact retry.

Existing inputs require `--drain-id` or `--terminal-id` respectively. The CLI
publishes exact no-replace bytes and syncs file and parent before success output.
If stdout is lost, retain all evidence and reopen the same owners and scope:

- `reconcile REVIEW_ID` reads B's confirmed metadata and can republish the same
  drain artifact even after A's Drain was already confirmed. It cannot Start,
  sign an A entry, refresh proof time or settle a pending authority mutation.
- `resume-begin REVIEW_ID` settles only the exact retained Begin.
- `resume-drain REVIEW_ID` reads B's already sealed metadata and confirms only
  the same retained pending Drain before publishing it.
- `capture REVIEW_ID` can repeat only the same accepted original source result;
  a B-only/expired/unseen/unknown result cannot manufacture a successful terminal.

To close each ordinary ticket, independently prepare and co-sign its canonical
V1 Complete entry against the retained typed terminal, then select
`--complete-entry FILE --complete-entry-id ID` and the pinned terminal on A.
`apply-complete REVIEW_ID` applies that command; `resume-complete REVIEW_ID`
explicitly settles only that same pending command. Open, review, ordinary Apply,
Seal and Reconcile never implicitly resume it. Close/reopen with the other
selected Complete for the second ticket. Completion signing remains offline
through the separate V1 offline commands; A's operator never loads a consumer
control key.

Control input permits one bounded complete LF-terminated queued command. Keep
stdin open until the action result is observed; EOF cancels ongoing work rather
than replaying an unobserved command. Each result consumes the prior report ID,
including when I/O, output or storage fails. Inspect durable files/owners before
the separate explicit recovery action.

## Acceptance boundary

Tests cover default review with unchanged retained trees, wrong pins before key
loading, one-use reviews, real QUIC execution, metadata/terminal persistence,
independent ticket completions, EOF/malformed control, and separate processes
with output broken after a confirmed Drain. The reopened operator recovers the
same immutable evidence without another effect.

This CLI does not close same-assignment WAN fault/soak acceptance, the remaining
position-zero V1 source/admission bootstrap, negative-disposition closure, independent physical/key
copy fencing, device-failure campaigns or the public-testnet/audit launch gates.

The focused integration/race run passed on macOS (cmd/omd 33.884 seconds, store
82.984). Native Linux/amd64 Go 1.26.7 with CGO_ENABLED=0, offline dependencies,
read-only modules and two build workers passed the same new CLI/operator tests
(cmd/omd 4.782 seconds, store 1.659). This includes actual command subprocesses,
not a claim that A and B ran on separate machines. The native process group had
no remaining children after the run, and its temporary SSH master was closed.

The 603-file Go-only source manifest matched before and after native execution.
Files are tracked `.go`, `go.mod` and `go.sum`, sorted by relative path; each line
is SHA256(file bytes), two spaces, path and LF. Manifest SHA256:

```text
c0df4e80158cd3e1c94e6998c511ce502caacc0e27ee462f89f52762a12c074f
```

Final Go 1.26.7 make test-all passed formatting, full vet and all three repository
race groups (store 218.879, 531.899 and 148.600 seconds), plus integration-tag vet,
without extending test timeouts.
