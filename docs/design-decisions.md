# Design decisions

> **DRAFT.** This covers the TypeScript implementation of cheqd's A2A trust-binding spec and
> its AP2 (Agent Payments Protocol) extension, across `packages/core`, `packages/a2a` and
> `packages/ap2`. Every package is pre-release (`private: true`); nothing here has shipped.
> Written for an external architect reviewing code quality and key design decisions before the
> PR stack (`#16` → `#17` → `#18` → `#20` → `#21`) merges.

## How to read this

Each decision below is Context / Decision / Why / Consequences / Revisit-if, in the order the
code was built. It is not a line-by-line design doc — it is the set of choices most likely to
be wrong, or most load-bearing if they are. File references point at where to go deep;
`docs/security/threat-model.md` and each package's own README cover ground this document
doesn't repeat.

---

## D1. Where request verification runs on the A2A server

**Context.** `@a2a-js/sdk` offers several places to hook request verification in. A naive
choice (an `AgentExecutor` decorator) is unsafe: the SDK appends an incoming message to a live
task's history *before* the executor runs, so a throwing executor still leaves an unverified
message written into task state — the caller sees a failed task, not a rejected request.

**Decision.** Verification happens in a `userBuilder` that reads the raw wire body, verifies
it, and returns either the verified DID or an unauthenticated user carrying the rejection
reason — it never throws. A separate enforcing wrapper over `A2ARequestHandler` rejects any
write that lacks a verified identity, then makes the response proof over the final result.

**Why.** It is the only approach tested (five were) that both verifies the actual wire payload
(not an SDK-reserialised approximation, which silently rejected 7/10 valid real-world payload
shapes in testing — unknown fields, numeric enums, explicit defaults) and runs strictly before
the SDK touches task state. Fails closed if the `userBuilder` isn't installed. No fork or patch
of the SDK.

**Consequences.** No HTTP 401 — the SDK has no auth error code, so failures surface as
JSON-RPC errors under HTTP 200. An Express middleware form exists as an optional add-on where a
real 401 matters. The `userBuilder` seam is Express-specific for the JSON-RPC transport; REST
and gRPC each needed their own equivalent (`packages/a2a/src/user-builder.ts`,
`grpc-user-builder.ts`).

**Revisit if** the SDK changes how it builds request context, or adds a native auth error code.

---

## D2. Agent Card key resolution trusts `kid`, never `jku`

**Context.** A2A §8.4.3, as published, says to retrieve the signing key "using the `kid` and
`jku`" headers. `jku` lets the *signer* nominate its own trust root — a verifier that fetches
whatever URL the signer supplies verifies against a key the attacker controls, not one the
caller actually trusts (CWE-863).

**Decision.** `createRetrievePublicKey` (`packages/core/src/agent-card/retrieve-public-key.ts`)
accepts a `jku` argument only for call-shape compatibility with the SDK's callback signature,
and never reads it. Resolution is strictly by `kid`, against DID documents (`did:web`, `did:key`,
opt-in `did:cheqd`) the caller has chosen to trust.

**Why.** The spec's own wording is unsafe to implement literally. This is a deliberate,
documented deviation, not an oversight — see the module's own header comment.

**Consequences.** Any future spec revision that makes `jku` meaningful would need an explicit,
separate trust decision — not a default resolver change.

---

## D3. Status/revocation checks are fail-closed, against a fixture pending a real on-chain list

**Context.** cheqd's on-chain status-list resource is currently a bare, unsigned record — not
the signed VC envelope the obvious resolver (`createCheqdStatusListResolver`) requires. That
resolver throws on the real testnet resource today. Fixing this (`did-provider-cheqd#657`/
`#658`) is an external dependency with no merge date.

**Decision.** Built against `@kya-os/mcp`'s generic `createStatusListProofVerifier` +
`createRevocationChecker` pair instead (not the cheqd-specific resolver, which turned out to
have its own, different, undocumented wire format). `packages/core/src/status/*` wires this to
the `did:cheqd` resolver. Tested against a fixture signed with `did-provider-cheqd#658`'s own
(unmerged) branch code — not a hand-rolled stand-in for it.

**Why.** The architecture doesn't need to wait on an external PR; only the presence of a *real*
signed list on-chain does. Checks fail closed (reject) rather than skip when status can't be
resolved.

**Consequences.** Until `#657`/`#658` land, there is no real on-chain signed status list in
production use anywhere in this stack — only the fixture. Tracked as a known gap, not silently
assumed away (`docs/security/threat-model.md`, "Known gaps").

**Revisit if** `#657`/`#658` merge — swap the fixture signer for the real resolver output; no
architecture change expected.

---

## D4. Replay protection is a persistent, short-TTL cache — scoped to one A2A call

**Context.** The SDK ships only dev-only in-memory nonce caches.

**Decision.** `FileNonceCacheProvider` (`packages/core/src/replay/file-nonce-cache.ts`),
persistent, process-restart-safe, single-call/short-TTL (60s) scope — wired into all three
transports in `sample/run.mjs`.

**Why.** Matches the spec's proof lifetime exactly: one A2A request proof is meant to be used
once, briefly. Deliberately **not** reused for AP2 mandate consumption (see D8) — a mandate's
lifetime is a different shape entirely.

**Consequences.** Not cross-process-atomic beyond what exclusive-create file semantics give you;
fine for the single-node deployment this targets, would need a real lock service multi-node.

---

## D5. AP2 key continuity reuses the A2A proof's own key-fusion primitive

**Context.** AP2's open Payment Mandate carries a `cnf` claim (RFC 7800). The A2A gate already
performs triple-key fusion (`token.cnf.jkt === proof.cnf.jkt === thumbprint(resolve(kid))`) to
establish "this proof and this token name the same key."

**Decision.** `packages/ap2/src/cnf-fusion.ts` reuses the identical RFC 7638 thumbprint
comparison, but operates on whichever already-resolved agent key JWK the caller supplies — it
does not reach into `@cheqd/agent-identity-a2a`'s gate internals.

**Why.** One notion of "same key" shared across A2A and AP2, without coupling the two packages'
internals together.

---

## D6. The authorised-secondary-key path is a credential, not a DID-document key, and gets its own trust tier

**Context.** AP2 needs to support a payment-specific key that differs from the agent's primary
signing key. Two options existed: add it as another `verificationMethod` in the agent's DID
document (an on-chain write via `did-provider-cheqd`), or issue it as a short-lived credential.
Separately, the A2A spec's existing `L3`/`L3-minus` trust tiers assume the proof-signing key
and the bound key are the *same* key — neither tier has defined meaning for a mandate
deliberately bound to a *different*, authorised key.

**Decision.** The secondary key is a short-lived, self-issued **Agent Payment Key Credential**
(`packages/ap2/src/payment-key-authorization.ts`) — signed by the agent's primary key, status-
checkable, not written on-chain. It establishes a **new, distinct trust tier**
(`authorised-secondary-key`), verified by checking the *authorisation chain*
(primary key → signed credential → secondary key), not key identity.

**Why.** The credential path reuses this codebase's own status-list/revocation machinery
directly (D3), rather than needing an on-chain DID-document write to rotate a payment key.
Giving it its own tier — rather than overloading `L3`/`L3-minus` — avoids silently redefining
what those tiers mean for every other caller of the A2A spec.

**Consequences.** `verifyAgentPaymentKeyCredential` fails closed on a *missing*
`credentialStatus`, not only on an explicit revocation — an agent payment key with no status
mechanism at all is treated as unverifiable, not implicitly trusted.

---

## D7. AP2 mandate-presentation verification is scoped to one delegation hop

**Context.** AP2 layers its *own*, separate, unratified delegation-chain extension
(`draft-gco-oauth-delegate-sd-jwt-00`: `~~`-joined, multi-hop tokens) on top of base SD-JWT-VC
(RFC 9901). This is a materially larger protocol than RFC 9901 itself, with no reference
TypeScript implementation to check against.

**Decision.** Implemented the single-hop case AP2's own `models/mandate.py` documents directly
— a Key Binding JWT whose `transaction_data` claim binds the presentation to a specific closed
mandate's content — using `@sd-jwt/core` (OpenWallet Foundation) for the base RFC 9901 crypto.
The multi-hop `~~`-chain case (agent-to-sub-agent re-delegation) is explicitly out of scope.

**Why.** Single-hop covers what an autonomous payment agent needs for *its own* transaction —
the realistic near-term case — without reimplementing an unratified protocol from scratch on a
"trust me" basis. Using a real third-party library for the base crypto, rather than hand-rolling
it, was a deliberate choice once this scoping was settled.

**Consequences.** Agent-to-sub-agent re-delegation is not supported. This is documented in
`packages/ap2/README.md` and is the single largest functional gap in the AP2 package, not an
implementation detail to discover later.

**Revisit if** a reference TypeScript (or otherwise checkable) implementation of the
delegation-chain draft becomes available, or the draft is ratified.

---

## D8. AP2 mandate consumption tracking is its own store, not a reuse of the A2A replay cache

**Context.** `budget` and `agent_recurrence` constraints need to track a mandate's cumulative
use (`total_amount`, `total_uses`, `last_used_date`) across multiple calls — unlike an A2A proof
nonce, which is single-call and short-TTL (D4).

**Decision.** `packages/ap2/src/mandate-consumption-store.ts` — its own store, its own lifetime
model, with a separate one-time-use `consumeOnce` (atomic exclusive-create) alongside a
read-modify-write `recordUse`, explicitly documented as **not** cross-process-atomic.

**Why.** A mandate's consumption lifetime and an A2A proof's replay window are different
concepts with different scopes; conflating them would have been the easier-looking but wrong
move.

**Consequences.** `recordUse`'s non-atomicity is a real constraint for a multi-process
deployment — flagged in the module's own comment, not hidden.

---

## D9. Full mandate-chain verification (all 10 constraints, both mandate pairs) was built now, not deferred to a minimal `cnf`-only slice

**Context.** A narrower scope — verify `cnf` continuity only, defer the full open/closed
constraint-chain verification (`amount_range`, `budget`, `allowed_payees`,
`allowed_payment_instruments`, `allowed_pisps`, `agent_recurrence`, `execution_date`,
`payment_reference`, `allowed_merchants`, `line_items`) — was available and would have shipped
faster.

**Decision.** Built the full chain now: both `PaymentMandateChain` and `CheckoutMandateChain`,
all 10 evaluators, ported directly from AP2's own JSON Schema and generated Pydantic models
(not reconstructed from spec prose) — including preserving an inconsistency upstream itself has
(`Budget` in major units vs. `AmountRange` in minor units), rather than "fixing" it.

**Why.** `cnf`-only verification establishes *who* is presenting a mandate but not *what it
actually authorises* — a materially weaker guarantee that would need revisiting almost
immediately for anything beyond a toy case.

**Consequences.** Larger surface to review and maintain than the minimal slice. Mitigated by
fuzzing all ten evaluators and the max-flow line-item matcher directly
(`conformance/fuzz-proof-parsing.mjs`) — see `docs/security/threat-model.md`.

**Note on `line_items`:** the matcher (`packages/ap2/src/max-flow.ts`, Dinic's algorithm) has
genuinely surprising real semantics, faithfully ported from upstream: it checks that every CART
item can be assigned to *some* requirement slot, not that every requirement slot gets filled.
This is documented in the module's own comment because it is easy to misread as the reverse.

---

## D10. Scoping the Python port against `@kya-os/mcp`

**Context.** `python/packages/core` ports `@cheqd/agent-identity`. Two of its nine TypeScript
modules — `status/status-list-resolver.ts` and `status/eddsa-jcs-status.ts` — exist only to
adapt this package's own logic to `@kya-os/mcp`'s provider seams (`StatusListResolver`,
`BitstringRevocationChecker`, `NonceCacheProvider`). No Python package published anywhere
implements `@kya-os/mcp`'s delegation/provider framework (checked PyPI directly for `kya-os`
and `kya-os-mcp`: neither exists); the only Python artefact from that project is an independent
*conformance verifier* for the proof-layer vectors, not the provider framework itself.

**Decision.** The Python core package ports every module that is cheqd's own self-contained
logic (`agent_card`, `did_cheqd`, `linkage`, `proof/eddsa_jcs_2022`, `status/ledger_anchored`,
`dlr/resolve_manifest`) faithfully, including its full test suite. It does NOT port
`status-list-resolver.ts` or `eddsa-jcs-status.ts`. `replay/file_nonce_cache.py` still exists,
but subclasses a plain Python ABC (`NonceCacheProvider`) defined locally in this package — the
same method contract `@kya-os/mcp`'s TypeScript interface declares, re-specified rather than
imported, since there is nothing to import from.

**Why.** Porting the two skipped modules would mean re-implementing a chunk of someone else's
MCP delegation framework in Python speculatively, with no consumer for it on the Python side -
out of scope for a trust-binding port, and a maintenance burden with no corresponding upstream
to track.

**Consequences.** The Python core package's public surface for credential-status checking is
`verify_ledger_anchored_status` only (the ledger-anchored, resolver-checksum path) — there is no
Python equivalent of the decision-6 `eddsa-jcs-2022` proof-based status list path yet. If a
Python KYA-OS-shaped delegation framework is ever built, these two modules are the template to
follow when wiring this package's ledger-anchored check into it.

**Revisit-if:** a Python `@kya-os/mcp` equivalent is published, or a consumer needs the
proof-based status list path specifically.

---

## D11. The Python AP2 port and the `sd-jwt` reference library's real gaps

**Context.** Unlike `packages/a2a`, almost all of `packages/ap2` is cheqd's own self-contained
logic (constraints, mandate-chain linking, max-flow line-item matching, the mandate
consumption store, `cnf` fusion, the authorised-secondary-key path) with no `@kya-os/mcp`
dependency - only `sd-jwt-presentation.ts`'s crypto layer is external (`@sd-jwt/core`). The
Python port uses PyPI's `sd-jwt` (the IETF SD-JWT spec's own reference implementation), the
closest Python equivalent. Verified empirically against two real defects in that library
(version 0.10.4), not assumed:

1. `SDJWTVerifier._verify_sd_jwt`/`_verify_key_binding_jwt` never check `exp`/`iat` at all - a
   literal `# TODO: Check exp/nbf/iat` left in its own source.
2. `SDJWTVerifier.__init__` calls `_verify_key_binding_jwt` without forwarding an explicit
   algorithm, so it silently defaults to `ES256` regardless of what algorithm the token
   actually used - an Ed25519-signed Key Binding JWT fails verification against the library's
   own default path (reproduced directly: `jwt.exceptions`-equivalent `InvalidJWSSignature:
   "alg" mismatch, requested "ES256", found "EdDSA"`).

**Decision.** `python/packages/ap2/src/cheqd_agent_identity_ap2/sd_jwt_presentation.py`
subclasses `SDJWTVerifier` (`_AlgPinnedVerifier`) to pass each signer's own algorithm, derived
from its JWK's `kty` (matching this programme's existing EdDSA/ES256 allow-list), and adds its
own `exp`/`iat`/skew check after the library's verification succeeds - the same shape
`@sd-jwt/core`'s `skewSeconds`/`currentDate` options already gave the TypeScript package. The
library also has no public way to add a `transaction_data` claim to a KB-JWT it builds
(`SDJWTHolder.create_presentation`'s KB-JWT payload is a fixed `{nonce, aud, iat, sd_hash}`
dict) - this only affects test-fixture construction (a verifier reads whatever claims are
present in an already-signed KB-JWT; it was never calling the holder's issuance path), so the
Python test suite builds its KB-JWT fixtures directly with `jwcrypto`, reproducing the
library's own `sd_hash` computation rather than reimplementing SD-JWT disclosure logic.

**Why.** Both defects are narrow and fixable by subclassing/wrapping the existing, tested
verification logic - not reasons to hand-roll SD-JWT-VC parsing or KB-JWT verification
ourselves. Silently trusting the library's untested-for-this-programme defaults (ES256-only KB-
JWT, no expiry enforcement) would have been a real security regression versus the TypeScript
package, caught here only because the port was run end-to-end against real Ed25519 keys rather
than assumed to work from the library's docs.

**Consequences.** `_AlgPinnedVerifier` is coupled to `sd-jwt` 0.10.4's private method
signatures (`_verify_sd_jwt`, `_verify_key_binding_jwt`, `_holder_public_key_payload`) - a
future upstream release could rename or remove them silently, since they are not part of the
library's public API. Covered only by this package's own test suite, not upstream's; revisit
on every `sd-jwt` version bump.

**Revisit-if:** `sd-jwt` ships a release that fixes either defect upstream (at which point the
subclass override becomes unnecessary and should be removed, not kept "for safety"), or renames
the private methods this subclass depends on.

---

## What this document doesn't cover

- **The full threat model and negative-vector suite** — `docs/security/threat-model.md`,
  `conformance/vectors/a2a-gate.json`, `conformance/run-a2a-gate-vectors.mjs`.
- **Known, named gaps** (KMS/HSM signing unproven, real on-chain signed status list pending an
  external PR, task-addressed method identity, streaming/push out of scope) —
  `docs/security/threat-model.md`, "Known gaps".
- **Operational guidance** (key rotation, incident response, reading gate rejections) —
  `docs/security/runbook.md`.

## License

[Apache 2.0](../LICENSE)
