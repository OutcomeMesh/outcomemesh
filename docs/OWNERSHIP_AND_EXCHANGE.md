# Ownership, agreed prices and exchange

Status: product principle and current implementation boundary. This document
adds no consensus rule, exchange format, price feed or activation switch.

## Who chooses a transaction's terms

The holder of specific resources chooses whether to spend those resources and
which transaction to authorize. A seller may offer one coin for ten dollars;
another seller may offer one coin for one million dollars. The intended exchange
model permits either agreement when the counterparties authorize its exact terms
and every common protocol requirement is satisfied.

The protocol checks authorization, asset conservation and the agreed verifiable
outcome. It does not need an official exchange rate to judge whether a voluntary
price is economically attractive. A participant may choose a minimum received
amount, permitted recipient, deadline and fee bound for their own transaction.
Another participant chooses whether to accept those terms.

Ownership applies to the holder's funds and authorizations. Creating the native
coin or operating a node does not confer authority to spend other holders'
resources, alter their signed transactions or impose a private mandatory price
on everyone. Network-wide rules, including signatures, conservation, maturity,
fees and consensus validity, still apply to every transaction. Changing those
rules requires an explicitly specified protocol change.

## An agreed price and a market quote

Different trades can use different prices for the same asset. A completed
one-million-dollar trade records that agreement; it creates no obligation for
other buyers to offer one million dollars. A displayed quote, an offer and a
completed trade are different observations. Liquidity and the willingness of
other participants to trade remain relevant to an executable market price.

Allowing participants to select prices is not a fixed peg, a guaranteed resale
value or a promise of liquidity. An optional future application may reference a
price feed, but that must be an explicit part of its agreed verification rules.
No mandatory USD, RUB, EUR or exchange-market price feed exists in version 0.

## What version 0 actually enforces

The [protocol specification](PROTOCOL.md) and current execution code implement:

- One Ed25519 signer per transaction; every consumed input belongs to that
  signer's address.
- A signature over the complete canonical unsigned transaction, including
  inputs, outputs, GuardVM program, fee, expiry height and nonce.
- Checked conservation for each asset and fees in the native asset.
- Input maturity, structural limits, expiry and an atomic state transition.
- A bounded GuardVM that can inspect before/after balances, transaction fee and
  block height. Rejection leaves the original state unchanged.

Amounts are checked `uint64` raw asset units. Consensus uses no floating-point
price arithmetic. A user interface's label of one whole coin needs an explicitly
defined unit scale; it does not alter the integer amounts signed by the holder.
The current GuardVM has no opcode for fetching a bank payment, a dollar rate or
an external market quote.

`PolicyHash` and `PayloadHash` are committed resource fields. Version-0 execution
does not resolve `PolicyHash` into an executable spending policy or require a
consuming transaction to preserve that hash in its outputs. The signed GuardVM
program governs this transaction. It does not automatically attach inherited
transfer restrictions, royalties, issuer vetoes or resale-price rules to all
future holders. Any such feature would need separately specified semantics,
authorization and versioned validation before it could be claimed.

Version 0 consequently cannot atomically consume a seller's resources and a
different buyer's resources in one ordinary transaction. Both inputs would have
to belong to its sole signer. Two independently signed transfers are two
separate state transitions; recording agreed terms does not make them an atomic
exchange. No multi-owner swap implementation is enabled by this document.

## Dollars in a bank and assets in the ledger

An on-chain asset identified as USD is still a ledger asset. Its label alone
does not establish a redeemable claim on bank dollars. A real bank transfer is
an external event that the current consensus and GuardVM cannot observe.

A future fiat settlement mechanism would need a defined payment rail, a trusted
and verifiable way to attest its outcome, and explicit handling of unknown,
delayed, disputed or reversible payments. Counterparty agreement on the price
does not by itself prove payment or make the bank event atomic with the ledger.
Custody witness receipts concern archive operations; they are not attestations
that a buyer paid dollars and must not be reinterpreted as payment evidence.

## Requirements for a future exchange format

A later proposal for multi-party settlement must bind at least:

1. The network and protocol version, exact assets, raw amounts and recipients
   for every leg, with no reliance on an ambiguous symbol such as `USD`.
2. Every required participant's authorization over the same complete terms,
   including fees and which participant pays them.
3. Exact input versions or another specified reservation mechanism, deadlines
   and unique nonces, with replay and duplicate-fill protection.
4. The complete post-state constraints and deterministic all-or-nothing
   execution. Partial fills require their own expressly authorized rules.
5. For any external payment or third-party attestation, the precise trust,
   finality, dispute and unknown-outcome rules. A missing reply cannot be treated
   as proof that payment or an effect did not occur.
6. Canonical encodings, signature domains, compatibility decisions, negative
   tests, fuzz coverage and activation evidence under [PLAN.md](PLAN.md).

This is design work for the planned settlement system. It does not bypass the
current custody, activation, security-review or public-testnet gates and does
not claim that atomic fiat settlement already exists.
