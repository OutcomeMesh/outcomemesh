# Accepting a retained result after delivery delay

This separate opt-in path applies only to guarded profile-5 deployments. A target
may have durably completed work and obtained the original result quorum while
its response reached A after the ordinary proof-age limit. Authority and Serve
consumer can consent to accepting that exact completed result. An unknown outcome
without the original verifiable result remains held. No timeout or operator
inventory substitutes for a session signature, result quorum or source record.

The consent commits to ContextID, BundleID, incident EvidenceID and a nonzero
inclusive NotBefore/NotAfter interval of at most 86,400 seconds. Authority and
consumer sign distinct role domains. EvidenceID names the incident inventory;
its contents are not treated as a work proof. Both signatures are mandatory.
The original bundle must verify, the result must have been fresh at its actual
RespondedAt, and its archive retention must cover the acceptance time. This
waives delivery age only. It cannot authorize execution, reset spending, replace
a source or extend storage retention.

Protected command kinds 9 (`ProtectedAcceptRetained`) and 10
(`ProtectedResumeRetained`) carry the full bundle and consent. The service uses
its clock, verifies the original admission and source position, and retains the
complete pending evidence before changing the accepted source. Lost replies and
process death recover only that same evidence at the original checked time.
A different consent, bundle or ordinary acceptance cannot replace a retained
attempt. Fresh expired consent fails before a new service position is consumed.
An exact retained attempt may finish after its window because the durable initial
check already fixed its time; restart does not refresh either proof or consent.

The new receipt includes the consent in its independently sealed artifact ID.
Removing or changing it invalidates the effect. Historical verification uses the
original AcceptedAt. Serve then uses the existing fulfilled proposal, original
Serve quorum, A/B applied receipts and admission closure. Closing pending
operations does not refund lifetime spend, shorten retention or erase witness
history. Partial A/B closure stays pending until the original matching evidence
is present. Claimed work without a complete result, split votes, damaged original
histories and lost sessions have no new closing permission.

## Wire compatibility

Legacy V2 and existing profile-5 bytes remain unchanged. New readers accept a
separate receipt magic `OMCVLAC5`; old readers reject it and command kinds 9/10.
Upgrade all participating services and verifiers together before opting into this
experimental workflow. No consensus or mainnet activation occurs.

The fixed 248-byte consent uses `OMCVRAC1`, three 32-byte IDs (context, bundle,
evidence), two big-endian uint64 times, and two 64-byte signatures (authority,
consumer). Signing hashes the unsigned bytes with
`OMESH/custody/v5/retained-acceptance/{authority|consumer}`. Data wrapper
`OMCVRAD1` contains one canonical length-prefixed Bundle followed by the consent.
Receipt core binding hashes the legacy receipt ID and complete consent under
`OMESH/custody/v5/retained-accepted-source/core`. The protected wrapper carries
length-prefixed core data (length-prefixed legacy receipt plus consent), followed
by the original service Effect. Sizes are bounded before decoding or verification.

## CLI flow

Use `work-archive-custody-profile5 --action sign-retained` with a public JSON input
containing canonical `Context` and `Bundle` bytes (JSON base64) and a `Consent`
object. Supply `--role authority` or `--role consumer`, the existing offline hex
seed file, and a fresh output path. Review first; run with the exact review ID.
Each signing output preserves the public JSON for the next signer.

`--action retained-acceptance` converts that JSON into the canonical Data bytes.
Use the existing `--action command` with Kind 9, original admission binding and
those Data bytes, then `sign-request` and the original service delivery path.
The normal Serve and admission tools consume the resulting retained receipt.
Kind 10 is explicit pending recovery; the service also supports its existing
exact signed request recovery. None of these commands create an execution owner.

[Historical evidence recovery](CUSTODY_EVIDENCE_RECOVERY.md) returns existing
result, acceptance and applied Serve receipts through the original service even
after closure. It does not complete an unfinished intent or release unknown work.
