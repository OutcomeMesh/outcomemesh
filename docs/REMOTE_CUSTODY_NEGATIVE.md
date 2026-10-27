# Retained remote custody negative observations

The A operator can now retain an explicit, authority-signed observation when a
sealed remote session has no result accepted in its original source. This is
the capture portion of the [negative work plan](REMOTE_CUSTODY_NEGATIVE_PLAN.md).
Capture does not settle either ordinary ticket. A separate explicit administrative
Audit completion is described below; Serve remains pending. An unresolved outcome is not renamed
to cancellation, successful custody or absence of an effect.

## Classification and retention

| Kind | CLI number | Required evidence | Ordinary tickets |
| --- | ---: | --- | --- |
| `RemoteCustodyUnseen` | 1 | B's durable Unseen seal and A's confirmed Drain; original A source still at the exact predecessor. | Both remain pending. |
| `RemoteCustodyUnknown` | 2 | B's NoResult seal after Start and A's confirmed Drain; original A source unchanged. | Both remain pending; no claim that nothing happened. |
| `RemoteCustodyUnverifiedResult` | 3 | B's RetainedResult commitment and A's confirmed Drain; no complete B journal entry supplied. | Both remain pending; the digest is not presented as a verified proof. |
| `RemoteCustodyUnacceptedResult` | 4 | Complete B entry matching its seal, verified historically against the selected archive, predecessor, challenge and policy; original A source still has not accepted it. | Both remain pending; no import or proof refresh. |

No branch advances the accepted source, extends a receipt, earns custody credit,
authorizes pruning or grants another execution attempt. Ordinary ticket retention
continues to constrain the original authority. In particular, the maximum-pending
budget is not bypassed by moving uncertainty into an untracked diagnostic file.
The existing pending Serve ticket carries that durable obligation after an
optional administrative Audit completion. No separate diagnostic file replaces
that ticket. Resolving Serve itself remains an implementation/acceptance gate.

## Explicit administrative Audit disposition

All four observations can close the auditor's obligation to record the selected
outcome, with the auditor consumer's signature and authority co-signature. This
is an administrative disposition, never successful custody or cancellation of
the remote effect. Only the exact Audit admission is eligible. Even Unseen
cannot complete Serve: a local worker seal cannot exclude a separately copied
participant under the V1 trust boundary.

The typed builder is `BuildRemoteCustodyNegativeAuditCompleteCommand`. Application
uses `ApplyNegativeAuditComplete`; only `ResumeNegativeAuditComplete` may resume
the retained exact pending attempt. They retain the original owner and source
decision, validate the whole signed observation, compare the exact confirmed
Drain, require the original Serve operation still pending, and require A's source
still at the observed predecessor. A changed source or another pending authority
command refuses application. An exact historical retry returns the same entry
without another append. A completed Audit must reference this same observation.

Use the existing V1 offline signature commands with the full selected scope and:

```text
--kind negative-audit-complete --purpose audit
--negative /ABS/negative --negative-id PINNED_NEGATIVE_ID
--admission /ABS/audit-admission --admission-id PINNED_AUDIT_ID
--expected-sequence SEQUENCE --expected-head HEAD
```

Review, sign with the Audit consumer, then independently review and co-sign with
the authority, as in the [offline guide](REMOTE_CUSTODY_OFFLINE.md). Selecting
`--purpose serve`, a positive terminal or another admission is refused. Offline
review proves the static message, not current live eligibility.

On A's operator select the pinned negative and external Complete entry, with no
`--terminal` selected. Obtain a fresh same-session review and explicitly issue:

```text
apply-negative-audit-complete REVIEW_ID
```

If an exact attempt was retained but not confirmed, review again and use
`resume-negative-audit-complete REVIEW_ID`. Opening/reviewing never submits it.
After successful application, a first-cycle authority is at position five with
one pending Serve operation; its original sources, receipt and proof time are
unchanged. Stop cannot retire this assignment across that outstanding operation.
The drained worker cannot execute again. This does not introduce a Serve
completion, successor owner, pruning permission or rewards.

Retain the selected negative file before completing Audit. Capture still requires
both tickets pending and cannot generate/enrich another disposition afterward.
Default review verifies the exact retained observation after Audit completion.
For controlled native/WAN follow-up use
`scripts/remote_acceptance/negative_settlement.py` with the separately retained
WAN and negative reports. This explicitly mutates only A's administrative ticket;
the earlier negative-capture campaign remains historical evidence.

## Owned capture

`RemoteCustodyAuditRuntime.CaptureNegativeToFile` retains the original A owner,
artifact lock and source decision through validation, signing and no-replace
publication. It requires:

- The exact independently pinned assignment, intent, Audit/Serve admissions,
  plan, Begin and authenticated B seal/Drain.
- A's independently confirmed Drain, no active Begin and no unrelated pending
  authority mutation; both exact ordinary admissions still pending.
- The original A source at the intent's exact predecessor sequence, head and
  receipt, with original root/lock identities checked before and after.
- If supplied, the complete B entry committed by the seal. Its signatures and
  historical proof are verified at the original RespondedAt; current time cannot
  make that proof fresh or turn it into A acceptance.

An already accepted A response cannot be recorded as absent. Later source advance
invalidates a retained absence/unaccepted-result observation for current owned
verification. `VerifyNegative` performs that current check; `Validate` checks
only historical public scope/signatures. Neither is an execution permission.

## CLI workflow

Use the same fully pinned A/B arguments as the
[operator guide](REMOTE_CUSTODY_OPERATOR.md), preferably with the explicit
[local placement profile](REMOTE_CUSTODY_PLACEMENT.md). New A flags are:

```text
--negative /ABS/OUTPUT/observation
--negative-id INDEPENDENT_EXISTING_OBSERVATION_ID
--remote-result /ABS/PUBLIC/complete-b-entry
--remote-result-id INDEPENDENT_B_ENTRY_ID
```

The first flag selects a dedicated output. Its ID is mandatory when selecting an
existing file. The optional remote-result pair must select an existing complete
entry; a caller cannot request that A create, import or refresh it. Output paths
must be distinct and outside the original owner/source/intent roots. They cannot
replace scope files, keys or another selected artifact.

After explicit Seal or ResumeDrain has independently confirmed A's Drain and
retained its pinned artifact, review the full current report and submit:

```text
capture-negative REVIEW_ID
```

The result reports `negative_id`, `kind`, `ordinary_tickets_retained=true`,
`completion_submitted=false` and `source_advanced=false`. Default review with a
pinned existing negative artifact also checks it against the current original
source/owner. A selected negative observation cannot be used with successful
completion input. The successful terminal decoder/signing path rejects its format.

For a RetainedResult branch, B can export its complete historical result without
starting a network host or another effect. Open its existing sealed worker in
control mode with a dedicated `--result-out /ABS/OUTPUT/b-entry`, review, then:

```text
export-result REVIEW_ID
```

This requires a confirmed Sealed/RetainedResult worker and its original matching
source entry. It signs nothing, does not seal an open session, and preserves the
proof ID and RespondedAt. Existing output requires `--result-out-id`. Only the
public signed entry needs to cross to A; no source journal or private key is
transferred. A can then capture kind 4 in a NEW output path. A previous kind-3
observation is retained unchanged, rather than overwritten by later enrichment.

Lost stdout is not a completion acknowledgement. Retain the files, reopen the
same owners with their independent drain/negative pins, review and repeat the
exact capture. Deterministic signatures and no-replace publication recover the
same bytes and ID. No nonce, intent time, source proof or admission is refreshed.

## Encoding and compatibility

The bounded `OMCRNEG0` envelope has its own version and signature/ID domains:

```text
OMESH/custody-authority/remote-negative/signature/v0
OMESH/custody-authority/remote-negative/id/v0
```

It commits the class, session, admissions/intent, B seal, co-signed Drain, exact
A source observation and optional complete B entry. A's authority signature
covers all of those fields. Decoders reject unknown versions, trailing bytes,
mixed classes, substituted signatures and inconsistent optional entries. The
existing `OMCRTERM` success encoding and its golden vector are unchanged.

Synthetic codec vectors (not live-owner evidence) are fixed in the tests:

| Vector | Bytes | ID |
| --- | ---: | --- |
| Commitment-only | 1391 | `4e9c7faf416cfe9b4b8c0732b6625f0a3be849eb40dfd100ec8d9c4c613f12cd` |
| Complete B entry | 3946 | `d7eeae45600305da37d5f2e85128ccd4040faf41b5e959d2b52215287fb7a100` |

## Acceptance boundary

SDK, CLI and native-process tests cover all four classifications, exact retries,
restart, lost output, accepted-source refusal, stale observations after source
advance, immutable enrichment and format substitution. The standard-library
[`negative.py`](../scripts/remote_acceptance/negative.py) additionally processes
retained closed original roots from the earlier WAN campaign, with explicit
current binary pins and local placement enrollment. It validates unchanged
original sources/owners and rejects separate scratch copies before publishing a
private report. It creates no authority or source root and starts no fresh work.

The [2026-10-27 sanitized record](evidence/remote-custody-negative-placement-20261027.json)
binds three actual retained negative scenarios on the two selected Linux hosts.
All four classes were exercised with unchanged original authority/source states;
the six ordinary tickets remain pending. Thirty-three private scratch copy probes
were refused. A cold review also verified kind 4 without selecting its separate
B input file and rejected the negative envelope as a successful terminal.

This evidence remains within the original-owner trusted-key boundary. A local
observation cannot establish global absence under cloned keys/roots. Independent
fencing, Serve disposition, device failures, audits and public-testnet
launch gates remain open.
