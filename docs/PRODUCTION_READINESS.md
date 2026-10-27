# Production readiness baseline

Assessment date: 2026-10-26. **Approximately 40/100 toward the full planned launch.**
Status remains research/pre-alpha: do not secure real value with this code.

The requested target is **mainnet with real value on 2026-11-01**, recorded on
2026-10-26. That leaves six days and does not satisfy the current launch plan.
In particular, the six-month adversarial public-testnet stability gate has no
completed qualifying evidence, and independent verification/external audits
remain open. No release date is certified or gate waived by this target.
WorkGraph also still requires the conjunctive [ER-2–ER-7 activation evidence](ACTIVATION_REVIEW.md),
including 30 continuous days of public calibration. See the hard blockers below;
the source/local preview capabilities in README are not mainnet acceptance.

This is a coarse, judgment-based engineering estimate, not an externally audited
measurement, success probability, ETA, percentage of lines written or completed
checkboxes. The denominator is milestones 0–10 in [PLAN.md](PLAN.md); narrowing
the product scope would require a separate explicit decision. Point allocations
are planning weights, not measured fractions of effort. A small implementation
step does not earn an automatic percentage increase.

| Area | Weight | Credited | Evidence / remaining boundary |
| --- | ---: | ---: | --- |
| v0 specification, deterministic kernel, ledger and PoW (M0–3) | 20 | 20 | Repository exit gates recorded complete; this does not imply external security approval. |
| Devnet and WorkGraph (M4–5) | 20 | 12 | M4 complete; M5 experimental implementation/research exists, but activation, independent review and calibration gates remain open. |
| Protected storage and operator lifecycle (part of M5) | 15 | 8 | Pinned journals, delivery, preparation, maintenance, exact recovery, local archive acceptance with explicit renewal-prefix verification and inventory-bound start history exist; full operator/audit/serve integration and physical-storage acceptance remain open. |
| Committee/application/privacy/proving scope (M6–8) | 15 | 0 | Not integrated; still gated by M5. |
| Independent verification and security audits (M9–10) | 10 | 0 | No completed independent consensus verifier or external audit evidence satisfying the plan. |
| Sustained adversarial public testnet (M9) | 10 | 0 | Local process tests are not a public testnet; the required six-month consensus stability gate is not met. |
| Release, ecosystem and production operations (M9–10) | 10 | 0 | Full signed/reproducible release, wallet/operator, incident-response, demand/security-budget and legal-review evidence is not complete. |
| Total | 100 | 40 | Approximate planning baseline only. |

The two M5 rows separate consensus/networking work from the storage/operator
subsystem so the same work is not credited twice. Implemented features and test
results are recorded in [STATUS.md](STATUS.md); open gates remain in the plan.

## Hard launch blockers regardless of score

- Finish and review M5 activation/economic/network/storage gates. Local locks and
  historical receipts do not establish live all-assignment authorization or fence
  copied owners. Device exhaustion, power loss and long-retention campaigns remain.
- Integrate and verify the planned M6–8 scope in the prescribed order, or explicitly
  revise that scope before claiming launch completion.
- Obtain independent consensus verification and external audits, resolve critical
  findings, and establish a public bug bounty and incident process.
- Satisfy the plan's public-testnet gate: at least six months without an unresolved
  consensus split, plus demonstrated partition/database-fault recovery and bounded
  real resource usage. Test runs in this repository do not start that clock.
- Establish signed/reproducible releases, explorer/faucet/wallet/SDK documentation,
  independent miners and operators, credible security-budget/demand evidence,
  reviewed wallets, upgrade/emergency procedures and distribution/interface legal
  review. Mainnet remains a separate explicit decision.

## Reporting rule

End each development report with the approximate score out of 100. Change it only
when evidence closes a meaningful weighted criterion; record the date, reason and
new allocation here. Failed evidence may lower the estimate. Never use the score
to bypass a launch blocker or imply a guaranteed launch date or coin value.

Initial 2026-09-13 baseline includes this pass's exact recovery work. It does not
claim that the project was previously measured lower, or that recovery completed
the production storage lifecycle.

2026-09-13 follow-up: the local initial-receipt archive-prune adapter now holds
every selected assignment guard through actual replay/deletion/result on pinned
storage. The score remains 40/100: renewal lineage, secondary terminal tooling,
managed audit/serve, operator ownership and physical/copy fencing do not yet close
the weighted storage/lifecycle criterion. No audit or testnet credit was added.

2026-09-14 follow-up: separately pinned, bounded renewal-prefix verification now
feeds local archive pruning under all original authority guards. The score stays
40/100: evidence preparation, retained inventory, secondary completion and the full
operator/storage lifecycle remain open. No independent-audit, public-testnet or
physical-storage acceptance credit is claimed.

2026-09-14 inventory follow-up: the bounded canonical preparation package now
retains exact policy, request, selected receipts and historical signed admissions
under independent inventory/mode-policy pins, with no-replace publication and
read-only loading. It does not certify actual use of that policy, current pending
authority, verified lineage bodies or physical durability. Runtime-bound inventory
and the wider lifecycle gate remain open; the score stays 40/100.

2026-09-14 bound-execution follow-up: the opt-in colocated adapter now binds the
exact prepared inventory to a versioned start in both executor journals, preserves
it through exact recovery and provides read-only local provenance inspection.
Legacy starts/results cannot acquire the binding retroactively. This is still not
the full operator lifecycle, secondary completion, managed audit/serve, remote
certificate, physical/copy fencing or public-testnet evidence. The score stays 40/100.

2026-09-14 lineage-retention follow-up: complete supplied historical prefixes now
have bounded preparation, an immutable streaming file format, three independent
pins and read-only full verification. They can feed the existing guarded library
executor, but its start does not commit the evidence file ID. Live-journal extraction,
secondary admission/completion, CLI ownership and physical/remote acceptance remain
open. This closes a preparation substep, not the weighted lifecycle criterion;
the score stays 40/100 and no audit or public-testnet credit is added.

2026-09-19 secondary-admission follow-up: one exact packaged secondary candidate
can now be submitted locally under the executor and both original coordinator
guards, preserving the primary request ID and existing publication/recovery rules.
This closes the colocated admission substep, not terminal handling, operator
signing/delivery/CLI, the wider lifecycle or physical/remote acceptance. No audit
or public-testnet gate is satisfied; the weighted score remains 40/100.

2026-10-26 secondary-completion follow-up: an explicit local adapter can now drain
one actually admitted secondary ticket using the executor's independently confirmed
success or pre-start cancellation. Success requires its original inventory-bound
start; cancellation retains its original request/ticket/executor scope. Exact
retained recovery and historical retries preserve the terminal evidence. Operator
signing/delivery/CLI, managed audit/serve, physical/remote acceptance and the wider
lifecycle remain open; the weighted score stays 40/100.

2026-10-26 secondary-signing follow-up: explicit offline consumer/authority
commands can now prepare secondary admissions and completions against the
unchanged primary request. Both assignments and, for completion, both admissions
are independently pinned; historical terminal checks remain separate from live
executor validation. Typed outbox preparation retains these entries, while the
secondary server/delivery and supervised ownership handoff are still open. The
weighted lifecycle criterion remains incomplete; readiness stays 40/100.

2026-10-26 secondary-network follow-up: explicit library sessions can receive one
selected secondary's existing Admit/Complete exchanges under pinned inventory,
policy and peer identities, while preserving guarded confirmation and exact
outbox recovery. They do not own/open hosts or journals or add a supervised CLI
service. Mainnet's requested 2026-11-01 target still lacks the mandatory temporal,
independent-review and operator/physical evidence; no launch gate is closed by a
local network test. The weighted score remains 40/100.

2026-10-26 secondary-service follow-up: an explicit owned service/CLI now opens
one pinned executor and selected target, plus the primary only for admission.
Its selected handlers drain before every journal lock is released; completion-only
does not open the primary. Stop/drain, separate offline work and explicit reopen
remain distinct steps. This closes command-service ownership, while reviewed
effect handoff, managed audit/serve, live-journal extraction and physical/remote
acceptance remain open. No audit or public-testnet credit is added; the weighted
score stays 40/100.

2026-10-26 source-extraction follow-up: a reviewed library batch now extracts
exact historical renewal prefixes from existing journal checkpoints into the
unchanged retained evidence format. All source locks remain held through replay,
bounded copying and revalidation. Inventory integration derives assignments and
selected receipts from external content pins; historical exports do not grant
current authority. Operator extraction tooling, supervised effect handoff,
managed audit/serve and physical/remote acceptance remain open. This closes a
library preparation step, not the weighted lifecycle criterion; readiness stays
40/100, with no independent-audit or public-testnet credit added.

2026-10-26 operator-extraction follow-up: explicit review/extract/verify modes
now expose the historical source extractor, immutable publisher and retained-file
loader. Review displays canonical scope and binds source/output paths, external
checkpoint pins and evidence ID in a local comparison digest; extract rechecks
that digest, and verify works with the original sources offline. No current
permission or effect is granted. Supervised effect handoff, managed audit/serve,
physical/cross-host enforcement and the wider release gates remain open. This
closes the operator preparation substep; weighted readiness remains 40/100.

2026-10-26 owned-effect follow-up: an opt-in library service now owns the pinned
executor, every required original coordinator and position-pinned WorkChain across
explicit local review and exact guarded execution. Scope/state comparison occurs
under all original guards, including after retained evidence fences before final
authorization. It neither resumes uncertain starts nor completes tickets. This
closes a local ownership substep; operator CLI command/effect transfer, managed
Audit/Serve, remote partitions, physical/copy fencing and the wider launch gates
remain open. Weighted readiness stays 40/100; no audit or public-testnet credit
is added.

2026-10-26 effect-CLI follow-up: the owned effect runtime now has an explicit
operator command, default non-executing review and supervised macOS/Linux control
pipes retaining every original owner through the result. Existing read-only
activation history cannot be initialized, and input/output cancellation and lost
result handling preserve retained uncertainty. Real local processes exercise
command drain/close, effect and command reopen. This closes the colocated CLI
workflow, not managed Audit/Serve, in-place transfer, remote/partition acceptance,
physical/copy fencing, independent review or public-testnet duration. Weighted
readiness remains 40/100; no launch gate is bypassed.

2026-10-26 managed-Serve follow-up: an explicit journal-backed library adapter
now binds a pre-existing signed Serve admission to the exact challenge and
authenticated peer. The original coordinator guard covers fresh signing, exact
cached/recovered delivery, auditor EOF, stream Close and cancellation drain.
Existing-only journal opening cannot initialize or repair evidence; no exchange
implicitly completes a ticket. Managed Audit, owned serving runtime/CLI, remote
partitions and physical/copy fencing remain open. Local library/QUIC/crash
coverage adds no independent-audit or public-testnet-duration credit. The
weighted lifecycle criterion remains incomplete; readiness stays 40/100.

2026-10-26 managed-runtime follow-up: Audit now binds a retained unsigned intent
before challenge signing and holds the original guard through response validation,
actual stream retirement, journal acceptance, output publication and exact recovery.
A local pair checks both pending tickets under that owner once and drains both
private participants; the separate owned Serve host/CLI drains handlers before
owner release. Audit operator tooling, owned paired hosting, remote partitions,
physical/copy fencing and the wider release gates remain open. Local process and
QUIC checks add no independent-audit or public-testnet-duration credit. The
weighted lifecycle criterion is still incomplete; readiness remains 40/100.

2026-10-27 operator-runtime follow-up: explicit commands now review/publish/verify
the fixed unsigned intent, supervise Audit preparation/recovery/network actions,
and own a local paired QUIC exchange. Fully reported session tokens bind readable
scope to retained owner/journal positions, compared again under the original
guard before effects. Both network hosts and accepted callbacks drain before
owner release; lost output preserves exact evidence and pending tickets.
Reviewed Audit/Serve admission/terminal tooling, remote partitions, independently
enforced physical/copy fencing and the wider launch evidence remain open. Local
tests add no independent-audit or public-testnet-duration credit; weighted
readiness remains 40/100.

2026-10-27 ticket-workflow follow-up: reviewed consumer signing and authority
co-signing now retain exact fixed positions; local owned application admits and
completes Audit/Serve against the original source journal. A canonical terminal
commits the signed admission, intent and complete current-head journal result.
Capture publication and append/confirmation hold both original guards. Uncertain
attempts require explicit reviewed Resume; exact confirmed retries preserve the
entry ID while reporting current state. The complete local process lifecycle
starts at position zero and closes both tickets independently. This closes the
first current-head local tooling slice, not remote partitions, independently
enforced physical/copy fencing, independent review or the public-testnet stability
period. Weighted readiness remains 40/100.

2026-10-27 remote-acceptance follow-up: two provided Linux VPS instances ran
identical pinned Go binaries with separate freshly bootstrapped local Audit and
Serve assignments. Five actual WAN custody scenarios passed: healthy delivery,
loss before the request, replica-commit/response-loss plus process kill, bounded
loss/delay, and rejection after the original proof aged out. Exact recovery kept
the original response and explicit completion remained separate. An ordinary
development chain also passed restart/outage handling, independent height-5/7
fork mining, selection of the greater-work branch and full replay on both hosts.
See REMOTE_ACCEPTANCE.md and evidence/remote-acceptance-20261027.json. This closes
the measured two-host transport/recovery substep. Single-assignment distributed
current authority, independently enforced physical/copy fencing, independent
security review and sustained adversarial testnet duration remain open. Short
controlled runs do not satisfy those parent gates; weighted readiness stays 40/100.

2026-10-27 remote-authority foundation follow-up: an opt-in V1 reference state
now retains RemoteBegin/RemoteDrained obligations intrinsically through original
coordinator restart and pending append recovery. A separate record-only worker
journal makes Sealing irreversible and permanently rejects delayed Start,
including the unseen-attempt branch. A drained remote ticket cannot enter a
generic live Serve callback again. Targeted race/process tests join both records
without manufacturing a proof or completing tickets. Version-0 bytes are preserved
and legacy delivery rejects V1. See REMOTE_AUTHORITY_FOUNDATION.md. This closes
the local state/recovery foundation only; owned remote execution/handler drain,
typed terminal verification, same-assignment WAN acceptance and independent
physical/copy fencing remain open. No parent launch gate or independent-review
credit is added; weighted readiness stays 40/100.

2026-10-27 managed-remote follow-up: the opt-in V1 library now implements a
separate bounded authenticated control protocol, original-A confirmed Begin
before enabling Start, independently pinned Audit data exchange, B monotone
sealing and complete handler drain before signed Drain. A typed terminal must
match the result already accepted in the same original A journal; Audit and
Serve complete independently through explicit source-guarded actions. Real
process tests cover B death before data and after commit before response, A owner
reopen, no fresh restart and exact cached recovery. Tagged race, wire isolation
and proof-expiry/uncertain-confirmation regressions pass. See
REMOTE_CUSTODY_EXECUTION.md. Operator/server CLI, negative-disposition tooling,
same-assignment WAN acceptance, independent physical/copy fencing and external
review remain open. This closes the owned library slice, not the parent launch
gate; weighted readiness remains 40/100.
