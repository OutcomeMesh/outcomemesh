# Production readiness baseline

Assessment date: 2026-09-13. **Approximately 40/100 toward the full planned launch.**
Status remains research/pre-alpha: do not secure real value with this code.

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
| Protected storage and operator lifecycle (part of M5) | 15 | 8 | Pinned journals, command delivery, preparation, maintenance and exact recovery exist; integrated live policy, all-assignment and physical-storage acceptance remain open. |
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
