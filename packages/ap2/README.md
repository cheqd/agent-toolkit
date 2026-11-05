# @cheqd/agent-identity-ap2

> **DRAFT — early exploration, not reviewed or stable.** The public API may change completely.
> Do not depend on it.

AP2 (Agent Payments Protocol) open-mandate verification: `cnf` key continuity, an authorised-
secondary-payment-key tier, the full open/closed mandate constraint chain (payment + checkout),
and per-mandate consumption tracking. See the [repository README](../../README.md) for how the
packages relate.

## What's here

- `src/types.ts` — a faithful port of AP2's "open mandate" (human-not-present) schema, read
  directly from `google-agentic-commerce/AP2`'s own JSON Schema and generated Pydantic models
  (`code/sdk/schemas/ap2/*.json`), not reconstructed from the spec prose. Field names,
  optionality, and the `Budget`-in-major-units/`AmountRange`-in-minor-units inconsistency are
  preserved exactly as upstream has them.
- `src/constraints.ts` — all 10 constraint evaluators (`amount_range`, `allowed_payees`,
  `payment.reference`, `agent_recurrence`, `allowed_payment_instruments`, `allowed_pisps`,
  `budget`, `execution_date`, `checkout.allowed_merchants`, `checkout.line_items`), a faithful
  port of `constraints.py`.
- `src/max-flow.ts` — the line-item requirement matcher (Dinic's algorithm), a faithful port of
  `max_flow_helper.py`. Its semantics are genuinely surprising: it checks that every CART item
  can be assigned to some requirement slot, not that every requirement slot gets filled - see
  the module's own doc comment.
- `src/mandate-chain.ts` — `PaymentMandateChain`/`CheckoutMandateChain`, a faithful port of
  `payment_mandate_chain.py`/`checkout_mandate_chain.py`. Operates on already-decoded payloads;
  owns only business-constraint and hash-chain linking (`transaction_id`, `checkout_hash`),
  matching upstream's own separation from SD-JWT crypto.
- `src/sd-jwt-presentation.ts` — SD-JWT-VC + Key Binding JWT verification using `@sd-jwt/core`
  (RFC 9901), covering the single-delegation-hop case: one Open Mandate, one KB-JWT presentation
  whose `transaction_data` claim binds it to a specific closed mandate's content. See "What's
  deliberately not here" below for why this is scoped to one hop.
- `src/cnf-fusion.ts` — WS5 decision 1: `thumbprint(mandate.cnf.jwk) == thumbprint(resolve(kid))`,
  the same RFC 7638 comparison the A2A proof binding already uses (spec §4.6 step 8), so AP2 and
  A2A share one notion of "the same key" without this package reaching into
  `@cheqd/agent-identity-a2a`'s gate internals.
- `src/payment-key-authorization.ts` — WS5 decision 2: the authorised-secondary-key path, as a
  short-lived Agent Payment Key Credential self-issued by the agent's primary key, reusing
  `@cheqd/agent-identity`'s generic `verifyEddsaJcs2022` proof verifier and status/revocation
  machinery rather than needing an on-chain DID-document write to rotate.
- `src/mandate-consumption-store.ts` — WS5 decision 4: persistent per-mandate consumption
  tracking (`MandateContext`: `total_amount`/`total_uses`/`last_used_date`, for `budget`/
  `agent_recurrence` constraints) and one-time-use consumption, with its own lifetime
  independent of the A2A proof's 60-second replay window - deliberately not a reuse of
  `FileNonceCacheProvider`.

## What's deliberately not here: the delegation-chain protocol

AP2 layers its own `~~`-joined, multi-hop delegation-chain extension on top of base SD-JWT
(`mandate.py`/`chain.py`/`kb_sd_jwt.py` upstream - an unratified Google draft,
`draft-gco-oauth-delegate-sd-jwt-00`, not RFC 9901 itself). Porting that protocol's crypto from
scratch, with no reference TypeScript implementation to check against, is a materially larger
and riskier undertaking than verifying AP2's own schema - so it is out of scope here.

Instead, this package covers the single-hop case documented directly in AP2's own
`models/mandate.py` (`PaymentMandate.user_authorization` docstring): a Key Binding JWT whose
`transaction_data` claim carries secure hashes of the specific closed mandate content being
authorised. That is what an autonomous-payment agent needs for its OWN transaction. Agent-to-
sub-agent re-delegation (the deeper `~~`-chain case) would be separate follow-on work.

## License

[Apache 2.0](../../LICENSE)
