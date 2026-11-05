# Threat model

> **DRAFT — early exploration, not reviewed or stable.** Covers `packages/core`, `packages/a2a`
> and `packages/ap2` as implemented so far (stacked PRs #16-#20). Part of WS6; this document and
> `conformance/vectors/a2a-gate.json` are the two WS6 artifacts built so far — dependency review,
> release pipeline and operator runbook are not yet done.

## Scope and trust boundaries

Three roles: a **client agent** (signs A2A proofs, optionally presents AP2 mandates), a
**server agent** (verifies them, runs the executor), and a set of **external resolvers**
(`resolver.cheqd.net`, `did:web` HTTPS endpoints, DID-Linked Resource and status-list
resolvers) that the server agent chooses to trust. The attacker is anyone who can send HTTP/gRPC
requests to the server agent, anyone who can serve content from a resolver the server agent
queries, and anyone who can present a signed proof or mandate they did not mint themselves.

Out of scope: compromise of a private key itself (the signer/KMS boundary - see "Known gaps"
below), compromise of the resolvers' own infrastructure, and anything upstream of this
programme's own code (`@a2a-js/sdk`, `@kya-os/mcp`, `@sd-jwt/core`, cheqd's ledger).

## Threats and mitigations

| # | Threat | Mitigation | Where |
|---|---|---|---|
| T1 | Agent Card signature mistaken for full trust. The SDK accepts the card if **any one** of several signatures verifies, and extension `params` are covered but unknown top-level fields are not. | The `retrievePublicKey` resolver pins the DID it expects and rejects any `kid` belonging to another DID; verifiers are told to re-derive trust-bearing values from the resolved DID document and Entity Card, not trust the card's own copy. | `retrieve-public-key.ts`, `v1/spec.md` §5.3 |
| T2 | `did:web`/`did:cheqd` substitution - a signer nominates its own trust root via `jku`, or an anchored `did:cheqd` claim is unilateral. | `jku` is accepted for shape compatibility and never read (CWE-863). Reciprocal `alsoKnownAs` linkage is required before an anchored DID is trusted - a one-directional claim proves nothing. | `retrieve-public-key.ts`, `reciprocal-linkage.ts`, `trust-extension.ts` |
| T3 | `cnf` downgrade - a caller with two independent keys (proof-signing and sender-constraint) is silently treated as fully fused. | `verifyCardProof` returns `L3` only on same-key fusion, `L3-minus` with an explicit `cnf_present_but_token_unfused` warning otherwise - never silent. AP2's authorised-secondary-key tier is a third, distinct outcome (neither `L3` nor `L3-minus`), reached only via a verified, non-revoked authorisation chain. | `@kya-os/mcp/card`, `cnf-fusion.ts`, `payment-key-authorization.ts` |
| T4 | Replay across `contextId`/`taskId`, or against a different request than the one signed. | `requestHash` is recomputed from the WIRE body (never the SDK's re-serialised typed object - confirmed this falsely rejects valid payloads in the other direction, see `v1/spec.md` §4.6.1) and covers the full `{method, params}`, so altering `contextId`/`taskId`/any message field after signing is a hash mismatch. Nonces are single-use via `FileNonceCacheProvider`, persistent across a restart. | `covered-request.ts`, `file-nonce-cache.ts`, `VEC-A2A-NEG-ALTERED-*`/`VEC-A2A-NEG-REPLAYED-NONCE` |
| T5 | Stale policy treated as policy-absent - a DLR manifest or status check that cannot be completed is treated as "no policy configured" rather than a failure. | `trust-extension.ts` fails closed on every incomplete check (`manifest_resource_unavailable`, `status_check_unavailable`, etc.) - there is no code path where "could not check" resolves to "allowed". | `trust-extension.ts`, `resolve-manifest.ts`, `VEC-A2A-NEG-STALE-POLICY` |
| T6 | Key substitution - a `kid` syntactically naming the right DID, signed by a key never actually published under it. | `resolveDidKeys` membership check (RFC 7638 thumbprint) plus the `kid`-DID-prefix check close this independently of each other. | `@kya-os/mcp/card`'s `verifyCardProof`, `VEC-A2A-NEG-KEY-SUBSTITUTION` |
| T7 | A transport-specific covered-form mismatch silently breaks verification, or - worse - silently widens what a signature is understood to cover. **This already happened once**: the gRPC gate hashed the SDK's deserialised protobuf object instead of the client's canonical-JSON form, until fixed in #18. | Every transport MUST hash the same canonical form the client signs, confirmed by a real client/server round trip per transport, not by code review alone. Any NEW transport binding added later inherits this as a standing requirement, not a one-off fix. | `grpc-user-builder.ts`, `smoke-test-grpc.mjs` |
| T8 | `cnf` fusion gives key continuity, not decision authenticity - a compromised or manipulated agent can still present a validly-fused mandate for a transaction the user never actually intended (arXiv 2609.11757, summary only; figures unverified). | Not mitigated by this binding at all, by design - `v1/spec.md` §11 requires any AP2 threat model to say so explicitly, which this does. A decision-authenticity control (e.g. a user-visible confirmation step) is out of scope for `packages/ap2`. | `v1/spec.md` §11 |
| T9 | AP2 mandate replay - the SAME Open Mandate authorising two different transactions in two different A2A calls, each individually proof-valid. | A dedicated, mandate-scoped consumption store (`mandate-consumption-store.ts`), not a reuse of the A2A proof's 60-second nonce cache - a mandate's own reuse window is a different lifetime entirely. `consumeOnce` is exclusive-create atomic for one-time mandates; `recordUse`'s cumulative tracking is correct within one process, not across them (documented, not silently assumed). | `mandate-consumption-store.ts` |
| T10 | A wildcard `checkout.line_items` constraint provides much weaker assurance than an allowlist one - found while building `max-flow.ts`. The matcher checks that every CART item can be assigned to *some* requirement slot, never that every slot is filled, so a wildcard slot accepts arbitrary extra or substituted items without violation. | Not a bug - this is upstream AP2's own semantics, preserved faithfully rather than "fixed" (a divergence from AP2 would itself be a worse interop risk). Documented loudly in `max-flow.ts`'s doc comment and this threat model so an integrator choosing a wildcard constraint understands what it does and does not assure. | `max-flow.ts` |
| T11 | Status-list integrity - a revoked credential or payment key read as live because nobody checked the list's own proof, or because the list itself has no integrity evidence. | Two paths, deliberately not conflated: `verifyLedgerAnchoredStatus` (checksum/ledger-anchoring, no issuer proof needed) and `createCheqdStatusChecker` (proof-checked, `eddsa-jcs-2022`). Both fail closed on every unreadable/stale/inconsistent case. Neither has live on-chain data to verify against yet - see "Known gaps". | `ledger-anchored.ts`, `eddsa-jcs-status.ts` |
| T12 | Junk proofs driving resolver load - a flood of garbage proofs, each triggering a DID resolution before being rejected. | Noted as a risk in `PLAN.md` (cheap pre-checks before resolution bring this from 200 to 66 resolutions in the original spike) but not independently re-verified against the current `packages/a2a` gate in this programme. **Not yet covered by a vector or a test** - candidate for the fuzzing pass below. | `PLAN.md` §8 (risk table) |

## Known gaps (explicitly not mitigated yet)

- **KMS/HSM-backed signing is unproven.** The seams for it exist on both the client (`ProofSigner`)
  and server (`ProofGenerator`'s `CryptoKey`) sides and need no new design, but nothing in this
  codebase has tested either against a real or realistic KMS/HSM - every example uses an
  in-process extractable key. Tracked as `cheqd/agent-toolkit#19`.
- **No real on-chain signed status list exists yet.** `cheqd/did-provider-cheqd#657`/`#658` (open,
  unmerged) block a genuine `BitstringStatusListCredential` whose proof covers `encodedList`;
  `createCheqdStatusChecker` is tested against a fixture signed with `#658`'s own branch code,
  not live data.
- **Agent-to-sub-agent AP2 re-delegation is out of scope.** AP2's own unratified `~~`-joined
  delegation-chain draft is not ported; `packages/ap2` covers the single-delegation-hop case only
  (see `packages/ap2/README.md`).
- **Junk-proof resolver-load protection (T12) is not independently re-verified** against the
  current gate - see the fuzzing note below.
- **Streaming and push-notification proof integrity** remain out of scope, per `v1/spec.md` §9
  (`PLAN.md`'s original scope note).
- **Task-addressed methods other than `SendMessage`/`SendStreamingMessage`** (`GetTask`,
  `ListTasks`, `CancelTask`, `SubscribeToTask`) carry no caller identity yet - `v1/spec.md` §4.8,
  still open.

## Negative-vector coverage

`conformance/vectors/a2a-gate.json` + `conformance/run-a2a-gate-vectors.mjs` cover T2-T6 directly
(wrong audience, expired proof, replayed nonce, altered message/`contextId`/`taskId`, key
substitution, `alg`/key mismatch, downgraded `cnf`, revoked credential, stale policy) against the
real gate over real HTTP, plus `VEC-A2A-RESP-1`/`VEC-A2A-GATE-1`. T1, T7, T8, T9, T10, T11 are
covered by the packages' own unit/smoke tests cited in the table above, not yet pulled into the
same consolidated vector suite. **Fuzzing over proof/covered-request parsing (T12 and malformed-
input robustness generally) has not been done** - the next WS6 step.

## License

[Apache 2.0](../../LICENSE)
