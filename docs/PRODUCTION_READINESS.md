# Production readiness baseline

Assessment date: 2026-10-29. **Approximately 44/100 toward the full planned launch.**
Status remains research/pre-alpha: do not secure real value with this code.

The requested target is **mainnet with real value on 2026-11-01**, recorded on
2026-10-26. On this reassessment date, three calendar days remain; that does not satisfy the current launch plan.
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
| Protected storage and operator lifecycle (part of M5) | 15 | 12 | Previous retained storage/prune baseline: 8; owned local Audit/Serve and reviewed ticket workflow: +2; fixed-session remote authority/execution/result verification: +1; V1 CLI/operator same-assignment WAN faults and original-root 32-cycle reuse acceptance: +1. Negative-disposition workflow and physical-storage/copy fencing remain open. |
| Committee/application/privacy/proving scope (M6–8) | 15 | 0 | Not integrated; still gated by M5. |
| Independent verification and security audits (M9–10) | 10 | 0 | No completed independent consensus verifier or external audit evidence satisfying the plan. |
| Sustained adversarial public testnet (M9) | 10 | 0 | Local process tests are not a public testnet; the required six-month consensus stability gate is not met. |
| Release, ecosystem and production operations (M9–10) | 10 | 0 | Full signed/reproducible release, wallet/operator, incident-response, demand/security-budget and legal-review evidence is not complete. |
| Total | 100 | 44 | Approximate planning baseline only. |

The two M5 rows separate consensus/networking work from the storage/operator
subsystem so the same work is not credited twice. Implemented features and test
results are recorded in [STATUS.md](STATUS.md); open gates remain in the plan.

The 2026-10-27 reassessment corrects stale accounting, rather than awarding
points because a report was requested. Earlier follow-ups below deliberately
kept the old 40-point baseline; their statements remain historical. The current
row now explicitly credits two implemented criteria previously described as open:
owned local Audit/Serve with reviewed admission/terminal tooling (2 points), and
the fixed-session remote execution library with original-owner result checking
(1 point). Evidence is in CUSTODY_TICKET_WORKFLOW.md, REMOTE_ACCEPTANCE.md and
REMOTE_CUSTODY_EXECUTION.md, including native/race/process checks. Transport
functionality already credited in the devnet row is not counted again.

The remaining three lifecycle points are reserved for negative-disposition
lifecycle, independent key/root copy fencing, and device exhaustion/power-loss/
long-retention acceptance (one each). The V1 operator/WAN point was credited
only after the complete same-assignment fault matrix and original-root 32-cycle
reuse series passed on two hosts; see the dated follow-up below. Their work can be
incremental, but each point needs its stated acceptance evidence. The four
zero-credit areas still account for 45 of the 100 planned points; a higher code
completion count cannot replace those launch gates. The score remains a rough
planning estimate, not a measured probability or a launch approval.

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

2026-10-27 V1 offline-preparation follow-up: distinct public preparation and
reviewed signing commands now cover assignment, authority/worker roots, plan,
Audit/Serve admissions, Begin proposals and typed successful completions.
Canonical V1 signatures remain compatible; V0 workflows remain separate. Exact
immutable signature retry precedes seed access, and worker inspection does not
seal a Started branch. Focused integration/race tests and subprocess acceptance
pass. See REMOTE_CUSTODY_OFFLINE.md. The remaining initial source/admission/
challenge bootstrap and complete position-zero CLI workflow, same-assignment WAN
fault/soak, negative dispositions and independent copy fencing remain open. The
current weighted baseline stays 43/100; no additional lifecycle point is earned
by this preparation slice alone.

2026-10-27 position-zero CLI follow-up: fresh source journals and artifacts,
source-guarded V1 admission application/explicit Resume and pre-Begin challenge
preparation now complete the successful operational lifecycle through CLI.
Actual subprocesses cover lost first-admission output and exact retry, real
QUIC, original-A result capture and two independent completions at position six.
Focused race/integration tests include the unchanged V0 process workflow; native
Linux tests pass on the same source pin. See REMOTE_CUSTODY_BOOTSTRAP.md. This
closes the remaining successful local bootstrap/tooling substep. The reserved
V1 operator/WAN point still requires same-assignment cross-host fault/soak
acceptance; negative dispositions, independent copy fencing, device campaigns,
independent review and launch gates remain open. The baseline stays 43/100.

2026-10-27 same-assignment WAN acceptance: the complete V1 CLI/operator matrix
passed on two explicitly selected Linux hosts. Ten independent scenarios cover
healthy exchange, partitions/loss/delay, both process roles before/after result
effects, lost sealed reply, expired cache and Unseen seal. A separate 32-cycle
series reuses one assignment and the original authority/source roots/locks,
including loss/delay every fourth cycle. It finishes at A authority position
192, both source positions 32, zero pending operations and no active remote hold.
Negative scenarios retain their two ordinary tickets; metadata-only Reconcile
does not confirm Drain, and each sealed branch rejects delayed Start through a
live authenticated connection. The retained-report validator checks scope,
identities, exact result IDs/times, relay counters and common build/source pins.
See [the procedure](REMOTE_CUSTODY_WAN.md) and
[sanitized acceptance index](evidence/remote-custody-wan-20261027.json).

This closes the reserved V1 operator/WAN criterion: protected storage/operator
lifecycle rises from 11 to 12 of 15, and total readiness from 43 to approximately
44/100. The evidence is controlled fault/bounded reuse acceptance with trusted
owner keys and original roots. It does not fence independent key/root copies,
resolve negative tickets, prove device power-loss durability, supply an external
audit or satisfy the public-testnet stability/calibration gates. The next
[negative-disposition work plan](REMOTE_CUSTODY_NEGATIVE_PLAN.md) earns no credit
until its implementation and acceptance criteria pass.

2026-10-27 negative-observation/local-placement follow-up: signed, separately
versioned observations now classify Unseen, unknown after Start, unverified
retained commitment and verified-but-unaccepted B entry. Owned A capture/review
and read-only sealed B export preserve original sources, historical proof time
and both ordinary tickets. Lost-output/process recovery and later source-advance
refusal are tested. A separate opt-in placement profile checks original native
root/lock/key-file identities under an independently retained local pin, before
CLI seed loading and during A/B actions. It rejects ordinary copies, but cannot
fence a raw key holder, an unbound V1 caller or a full identity-preserving clone.

The same frozen implementation passed native Linux tests, three retained WAN
negative branches with 33 copy refusals, and six normal-CLI guarded WAN scenarios
(13 successful cycles, including an eight-cycle reuse series). Both ordinary
tickets remained pending in each branch at that capture stage. The complete historical
B entry can be verified in a new A process without its separate input file and
is rejected as a successful terminal. See REMOTE_CUSTODY_NEGATIVE.md,
REMOTE_CUSTODY_PLACEMENT.md and the
[sanitized negative/placement acceptance record](evidence/remote-custody-negative-placement-20261027.json).

No weighted point is added: negative ticket settlement/uncertainty holds and
independently enforced protected-key/root fencing remain incomplete. The local
profile is a detection layer, not that independent authority. Total readiness
stays approximately 44/100; device, audit and sustained public-testnet gates are
unchanged. The placement guide specifies the required external-issuer/protocol
conditions for the next fencing stage without claiming them implemented.

2026-10-27 administrative-disposition/witness follow-up: explicitly signed
Audit-only negative Complete now closes the historical administrative observation
while preserving the exact original pending Serve ticket for every negative
class. Explicit Resume, exact retry, original source/Drain checks and retirement
refusal are verified. A follow-up on the three original two-host negative cases
closes three Audits and retains three unresolved Serve obligations, without source
advance, proof refresh or fresh execution. Earlier capture reports are historical
snapshots taken before these administrative completions.

A separately versioned experimental witness SDK/journal now implements >2/3
quorum certificates, durable proposal locks before signing, unknown-result holds
and exact replay/recovery. Its copied-owner/one-fault, codec/fuzz and real SIGKILL
tests pass, including native runs on both Linux hosts. The four-witness tests use
local fixtures on each host, not four independent witness services. See
[CUSTODY_FENCE.md](CUSTODY_FENCE.md) and the
[sanitized acceptance index](evidence/custody-negative-audit-witness-20261027.json).

There is no additional weighted point: negative Serve resolution remains open,
and this witness foundation is not yet mandatory in assignment, transport,
effect consumption or proof acceptance. Independently protected service
deployment, split-vote progress, device campaigns, independent review and sustained
public-testnet gates remain open. MIT licensing and the contribution guide add
project governance documents, not completed legal-review/release acceptance.
Total readiness remains approximately **44/100**.

2026-10-27 witness-network/result-binding follow-up: the experimental journal now
has authenticated bounded QUIC transport, action-bound reviewed CLI workflows,
exact request/observation pins and offline quorum assembly. A separate typed
historical custody-result verifier requires the complete claim/[unknown]/result
certificate history and exact custody entry; it refuses opaque-digest/legacy
substitution and participant keys counted as witnesses. It does not accept a
current source, refresh proof or close Serve.

The controlled normal-CLI WAN campaign runs four logical members on two hosts,
not four independently protected failure domains. It checks insufficient and
duplicate quorums, three-member progress, exact retries, verified SIGKILL with
retained Unknown, stale reopening and late-command refusal. All four histories
finish at position three with obligations held. Native binaries, fixed vectors,
full repository race groups, integration/process checks, 33 helper tests and new
wire/result fuzz targets pass. See the
[acceptance index](evidence/custody-witness-network-20261027.json) and
[protocol/operator guide](CUSTODY_WITNESS_NETWORK.md).

No additional weighted point is assigned: new assignment/policy binding,
mandatory consumption/acceptance in the actual custody path, negative Serve
resolution, protected independent witness deployment and split-vote progress
remain open. Device, independent-verifier/audit, release and public-testnet gates
are unchanged. Total readiness remains approximately **44/100**.


2026-10-27 mandatory-V2 follow-up: a separate assignment/job version now commits
its witness policy and derives the execution scope. Session-bound fence V1,
actual target consumption before chunk/proof work, full result quorum binding and
original-A acceptance with retained explicit recovery are implemented. Normal
CLI/process tests traverse that complete path; compatibility, persistence fault,
copy/session, lost reply and exact historical recovery tests accompany it.
See [CUSTODY_V2.md](CUSTODY_V2.md) and the [V2 acceptance index](evidence/custody-v2-20261027.json) for exact evidence.

This is an experimental node-side custody path, not global consensus activation.
The volatile-key guarantee assumes the honest target implementation; signatures
cannot prove that a hostile implementation did not persist/copy its session key.
Physical/independent key protection, four independent witness domains, split-vote
progress, certified Serve resolution, migration, external audits and sustained
public-testnet/calibration gates remain open. No weighted launch gate is closed
by this prototype slice. Total readiness remains **44/100**.


2026-10-28 joint-V2 WAN follow-up: the same signed jobs now run through normal
CLI/QUIC on two Linux kernels, with four logical witnesses split 2/2. Three fresh
scopes cover post-commit reply loss/SIGKILL/receipt recovery, pre-effect session
loss, and expired B-only evidence. Original source counts, exact signed bytes,
quorum refusal/recovery and retained obligations are checked; public signed
artifacts and native/script/source pins accompany the acceptance index. Cleanup
finds no selected listener or task process. See [CUSTODY_V2_WAN.md](CUSTODY_V2_WAN.md)
and [the acceptance index](evidence/custody-v2-wan-20261028.json).

This controlled matrix does not establish four independently protected witness
or execution/key domains, release Serve, solve split votes or complete activation,
admission, audit and stability gates. It closes the joint prototype acceptance
slice only. No weighted launch gate is waived; readiness remains **44/100**.


## 2026-10-28 follow-up: typed V2 Serve (score unchanged)

The opt-in per-job V2 adapter now closes fulfilled work or original-quorum
no-claim cancellation through complete typed proposals, both participant role
signatures, a separate permanent decision quorum and original-owner A-then-B
application. Unknown and expired B-only work remain pending; archive retention
is never released. Reviewed standalone CLI, original-source checks, eight local
persistence boundaries, cold process recovery and the joint two-host matrix are
recorded in [CUSTODY_V2_SERVE.md](CUSTODY_V2_SERVE.md) and its
[acceptance index](evidence/custody-v2-serve-20261028.json).

The reserved negative-lifecycle point still requires assignment-wide V2
admission/budgets and explicit migration/activation rules for legacy tickets.
No V1 pending Serve is silently closed. Typed Serve RPC, independent protected
witness deployment, split-vote progress, physical device acceptance and the
M5–M10 audit/economic/public-testnet gates remain open. No weighted launch gate
is waived; readiness remains **44/100**.


## 2026-10-28 follow-up: assignment-wide coordinator (score unchanged)

[V2 admission accounting](CUSTODY_V2_ADMISSION.md) now has a shared permanent
witness history across job Plans, signed two-unit budgets, nonrefundable lifetime
spending, one active job, full Serve A/B accounting closure and exact cold
recovery. Its reviewed CLI and [two-host evidence](evidence/custody-v2-admission-20261028.json)
exercise the coordinator, without starting an execution or changing source data.

This does not yet make admission mandatory in raw V2 execution. The reserved
lifecycle point still needs the signed runtime profile, original-source/current
owner checks, consumption/delivery recovery and an implemented activation/
accounting bridge. [V1 migration rules](CUSTODY_V2_MIGRATION.md) are a specification,
not an import command or release of old pending Serve. Independent protected
witness deployment, physical storage, external review and sustained adversarial
testnet gates remain unchanged. Readiness remains **44/100**.


## 2026-10-28 follow-up: mandatory signed profile (score unchanged)

[Required admission](CUSTODY_V2_REQUIRED.md) now binds complete accounting proof
into new signed policy-3 owners. Downgrade/raw-open paths fail, original-source/
session checks remain, and binding-aware consumption precedes current archive
reads. Original A acceptance, Serve A/B and accounting closure preserve the same
proof through cold recovery. [Acceptance evidence](evidence/custody-v2-required-20261028.json)
records the complete required path and unknown holds on two hosts.

This closes the signed-profile/runtime-binding slice. The reserved lifecycle
point still requires durable admission distribution/recovery and implemented
activation/cutover/accounting-bridge evidence. Legacy policies and their pending
obligations are not promoted. Independent protected deployment, physical-storage,
audit and sustained adversarial public-testnet conditions are unchanged.
Readiness remains **44/100**.


## 2026-10-28 follow-up: retained proof delivery (score unchanged)

[Durable admission delivery](CUSTODY_V2_DELIVERY.md) now fixes an original
receiver enrollment, full proof intent and route in retained inbox/outbox roots.
Authenticated delivery, original-source checks, deterministic acknowledgements,
explicit lost-output/cold recovery and reviewed operator CLI are implemented.
Proof delivery neither creates an execution owner nor clears a pending budget
or archive obligation; the required runtime remains independently gated.

This closes the prototype distribution/recovery slice for bounded new profile-3
jobs. Protected independent enrollment and original external pins, implemented
legacy exclusion/activation/accounting bridge, physical device acceptance,
external review and sustained public-testnet evidence are still required. No
reserved weighted lifecycle point is awarded before its complete gate passes.
Readiness remains **44/100**.


## 2026-10-28 follow-up: one-choice enrollment foundation (score unchanged)

The [resource registry](CUSTODY_REGISTRY.md) now separates a stable externally
provisioned anchor from its mutable assignment/policy descriptor and retains one
three-role-signed candidate through a permanent witness quorum. Original-root
journals and reviewed CLI support exact vote/commit recovery and minority-record
retention without granting custody execution or migration.

Physical resource uniqueness, independently protected issuer/witness histories,
mandatory runtime enforcement and the version/source/accounting bridge remain
required. The terminal profile-3 selection cannot be reset or silently promoted
into another assignment/profile. This is a prototype selection component; the
reserved lifecycle point and all launch blockers remain open. Readiness stays
**44/100**.

2026-10-28 disabled legacy cutover review: complete bounded V1 replay, original
A/B source observations, no-refund review arithmetic, three-role agreement and
immutable non-runtime preparation now have a reviewed CLI. Fourteen new Go tests,
seven race groups, 65 helper tests, five decoder fuzz targets and native checks on
two Linux kernels are recorded in
[custody-cutover-review-20261028.json](evidence/custody-cutover-review-20261028.json).
Linux inode reuse found during acceptance is covered by permanent lock change
time checks. These remain local placement checks. Full successor assignment and
source/spending import, protected exclusion of old grants, independent deployment,
physical failures and the wider release gates remain open. This preparatory
slice closes no additional weighted launch criterion; readiness stays **44/100**.


## 2026-10-28 follow-up: imported accounting (score unchanged)

[Profile5](CUSTODY_IMPORTED_ACCOUNTING.md) now imports the verified old lifetime
spending, accepted source predecessor and retention floor into the existing
admission machine and durable witnesses. A full Selection3 quorum is required,
with the same Descriptor2 namespace and one-choice journal used by native
Selection2. Changing format cannot acquire another slot or reset a retained vote.
Exact cold recovery keeps imported counters and immutable selection evidence.

This closes the accounting carry-over implementation slice. It does not close
protected deployment or activation: all imported execution owner constructors
still refuse policy5. Local copy/lock checks and historical selection cannot
exclude old raw-key or full-machine copies on paths that never consulted a
protected gate. Original-source handoff, monotone version enforcement on every
effect/acceptance path, independently operated protected witnesses, device fault
acceptance, external audits and the existing M5–M10 launch gates remain required.
See the [test record](evidence/custody-import-20261028.json). No weighted launch
criterion is waived; readiness remains **44/100**.


## 2026-10-29: sealed source transfer (score unchanged)

Original A/B sources now retain one exact selected imported successor and its
complete proof, with ordered permanent sealing, cold recovery and checks on held
action paths. [Source handoff](CUSTODY_SOURCE_HANDOFF.md) preserves spending,
source lineage and retention. Tests verify failures before archive reads and
receipt publication, original guards, root/lock replacement and lost CLI output.
This does not establish independent protected execution/key deployment, global
revocation of arbitrary old copies, or active imported execution. Those and the
existing M5–M10 gates remain required. Readiness remains **44/100**.


2026-10-29 isolated gateway follow-up: a new issuer-approved service now owns a
fresh signing key and performs sealed-source inspection and original chunk reads
behind a separate Linux UID, with exact per-action pins, durable replies and
irreversible revocation. Native participant processes are denied direct access
to key/source/object files. This is an OS isolation component, not completed
all-assignment activation or protection against root/full-service-VM copies.
Imported execution and independently protected deployment remain disabled/open;
the copy-fencing point and total remain unchanged at approximately **44/100**.
