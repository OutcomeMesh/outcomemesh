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
