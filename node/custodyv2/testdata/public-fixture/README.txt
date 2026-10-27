Public deterministic test fixture, not deployment material.

context is a canonical custody V2 Context. The hash-named file is its real archive
chunk. It was generated from the existing CLI archive fixture. All participant
keys are public testing keys from internal/fencetest: authority 1, auditor 3,
consumer 4, remote control 14, server transport 15, client transport 46, replica
61, witnesses 70–73. No private seed is stored here. These keys MUST NOT be used
for deployed witnesses, replicas, funds or independent-failure-domain claims.

Historical unit tests use the original challenge time. Live transport tests
create a new signed challenge/plan with the real current clock and fresh sources;
production requests have no caller-supplied proof-time override.
