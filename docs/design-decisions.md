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

**Decision (initial scope, later revisited below).** The Python core package ports every
module that is cheqd's own self-contained logic (`agent_card`, `did_cheqd`, `linkage`,
`proof/eddsa_jcs_2022`, `status/ledger_anchored`, `dlr/resolve_manifest`) faithfully,
including its full test suite. It did NOT initially port `status-list-resolver.ts` or
`eddsa-jcs-status.ts`. `replay/file_nonce_cache.py` still exists, but subclasses a plain
Python ABC (`NonceCacheProvider`) defined locally in this package — the same method contract
`@kya-os/mcp`'s TypeScript interface declares, re-specified rather than imported, since there
is nothing to import from.

**Why (at the time).** Porting the two skipped modules would have meant re-implementing a
chunk of someone else's MCP delegation framework in Python speculatively, with no consumer
for it on the Python side - out of scope for a trust-binding port, and a maintenance burden
with no corresponding upstream to track.

**Update: both modules are now ported, because this document's own "Revisit-if" fired.**
`status/status_list_resolver.py` and `status/eddsa_jcs_status.py` now exist, built the same
way as D13/D14/D17's a2a-engine work: reading `@kya-os/mcp`'s actual TypeScript source
directly (`card/revocation.ts`, `card/status-list-proof.ts`, `cheqd/status-list-resolver.ts`,
`utils/statuslist-bits.ts`, `utils/statuslist-purpose.ts`), not reconstructed from prose. This
did NOT require depending on `@kya-os/mcp`'s delegation framework, because that framework was
never actually load-bearing for these two specific files - re-reading them for this port
showed `status-list-proof.ts`'s `verifyEddsaJcs2022` is the SAME `eddsa-jcs-2022`
cryptosuite construction `proof/eddsa_jcs_2022.py` already ports (built earlier for agent-card
verification), so `status_list_proof.py` is a thin adapter over that EXISTING verifier, not a
second implementation of it. The only genuinely new code is `statuslist_bits.py` (index
parsing, GZIP inflation with the 16 MiB decompression-bomb cap, MSB-first bit read) and
`revocation.py` (the fetch/verify/decode/read pipeline, `RevocationChecker`, and
`evaluate_revocation_chain`'s cascading-fail-closed chain walk) - both re-specified locally,
the same `NonceCacheProvider` pattern this decision already used for the replay cache.

One deliberate deviation from the TypeScript original, documented in `statuslist_bits.py`'s
own module docstring: the `decompress` seam is a plain SYNCHRONOUS `bytes -> bytes` callable,
not async - the TypeScript seam is async only so a Workers/browser bundle can inject
`CompressionStream` instead of `node:zlib`, a bundler concern with no Python equivalent.

Confirmed end-to-end against a REAL, hand-signed `eddsa-jcs-2022` proof over a REAL
gzip-compressed `encodedList` (`tests/test_eddsa_jcs_status.py`) - not just unit-tested
pieces assembled on faith that they compose correctly.

**Consequences.** The Python core package's public surface for credential-status checking is
now both `verify_ledger_anchored_status` (the ledger-anchored, resolver-checksum path) AND
`create_cheqd_status_checker` (the decision-6 `eddsa-jcs-2022` proof-based status list path).
Same caveat as the TypeScript original: `did-provider-cheqd` 4.8.0 does not yet produce a
list this verifier accepts (cheqd/did-provider-cheqd#657); this is written against the format
the open, unmerged `#658` produces - nothing left to change here once it ships.

**Revisit-if:** `@kya-os/mcp` changes either `revocation.ts`'s or `status-list-proof.ts`'s
construction (re-read the source and re-sync, the same `D16`/`D17`-style conformance
discipline used for the a2a package) - there is no dependency relationship to flag this
automatically, since this is a from-spec re-specification of the provider seams, not an
import. Also revisit once `did-provider-cheqd#658` merges, to swap the synthetic test fixture
for a real on-chain resource.

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

**Reported upstream:** both defects filed against `openwallet-foundation-labs/sd-jwt-python`:
[#28](https://github.com/openwallet-foundation-labs/sd-jwt-python/issues/28) (`exp`/`iat`
never checked) and
[#29](https://github.com/openwallet-foundation-labs/sd-jwt-python/issues/29) (KB-JWT
verification hardcodes `ES256`). Neither had an existing issue on file. If either is fixed
upstream, remove the corresponding override in `_AlgPinnedVerifier` rather than keeping it.

---

## D12. The Python A2A port was initially partial - the proof-verification gate itself wasn't ported

**Context.** Unlike AP2, almost everything in `packages/a2a` imports directly from
`@kya-os/mcp/card`, `@kya-os/mcp/proof` or `@kya-os/mcp/providers`: `user-builder.ts` and
`grpc-user-builder.ts` call `verifyCardProof`; `client.ts` calls `buildCardProof` and
`ProofVerifier`; `wrapper.ts` calls `ProofGenerator`. These are not thin adapters over
cheqd's own logic (unlike `status-list-resolver.ts`/`eddsa-jcs-status.ts` in D10) - they ARE
the A2A trust binding's actual holder-of-key proof construction and verification, which this
programme has always deliberately reused from `@kya-os/mcp` rather than forked (see the
repository README's "What this builds on"). Only `covered-request.ts` (canonical request
shaping) and `trust-extension.ts` (composed from this package's own core building blocks) are
self-contained.

**Decision (superseded - see D13).** `python/packages/a2a` initially ported only
`covered_request.py` and `trust_extension.py`. A from-spec `org.kya-os/proof.v1` engine was
built afterward (D13) once the scope of that gap was sized and approved, so this no longer
describes the package's actual state - kept for the record of why the gap existed at all.

**Why.** `@kya-os/mcp`'s `org.kya-os/proof.v1` profile (RFC 8785 JCS canonicalisation, detached
JWS, RFC 9421 HTTP Message Signatures, RFC 7638 `cnf` thumbprint fusion) is published as a
cross-language-verified profile - its own conformance suite ships an independent Python
stdlib-only reference verifier (`conformance/verify.py`, MIT-licensed, confirmed directly
against `node_modules/@kya-os/mcp/CONFORMANCE.md` and `LICENSE`) precisely so other languages
don't re-derive this construction from spec prose. That reference verifier is a
conformance-vector checker, not a packaged library - so the engine (D13) was built by reading
`@kya-os/mcp`'s actual TypeScript source directly, not by consuming a library.

**Consequences.** Addressed by D13.

**Revisit-if:** n/a - see D13.

---

## D13. A from-spec Python `org.kya-os/proof.v1` engine, read directly from `@kya-os/mcp`'s source

**Context.** D12 left the Python A2A package without a working proof gate. `@kya-os/mcp`
(MIT-licensed) has no Python package to depend on, but its TypeScript source is directly
readable (`node_modules/@kya-os/mcp/dist/card/proof/*.js`), and the profile itself
(`org.kya-os/proof.v1`) is a published, cross-language-verified spec, not a proprietary
construction - reimplementing it from that source is porting a specification, not
reverse-engineering a product.

**Decision.** `python/packages/a2a/src/cheqd_agent_identity_a2a/proof/` ports
`canonical.ts`, `types.ts`, `signer.ts`, `build.ts` and `verify.ts` faithfully - every
fail-closed check in `verify_card_proof` (kid/did binding, DID-membership RFC 7638
thumbprint proof, audience, request-hash, replay via the atomic nonce seam, the
created/expires window, the detached-JWS signature, the small-order Ed25519 key rejection,
and the `cnf.jkt` sender-constraint fusion to L3/L3-minus) is present, read line-by-line from
the TypeScript source, not reconstructed from the SPEC prose alone.

Two things were INITIALLY deliberately not ported, then built later once a concrete need for
them was identified (both now in `signer.py`/`http_sig.py`, superseding the two bullets this
paragraph used to list as scope cuts):

- **`http-sig.ts`** (the RFC 9421 HTTP Message Signature "dual carrier") is now ported as
  `http_sig.py` (`http_signature_base`/`to_http_message_signature`/`verify_http_signature`).
  `build_card_proof` attaches `httpSig` whenever the signer exposes a `sign_raw` seam,
  mirroring the TypeScript original's dual-carrier logic exactly. This package's own
  `gate.py`/`client.py` still never call `verify_http_signature` - the A2A transports in use
  here are JSON-RPC/REST/gRPC via the `a2a-sdk`, not real HTTP headers a generic RFC 9421
  verifier reads - so this module exists for integrators who DO put proofs on real HTTP
  headers, not for this package's own gate.
- **An ES256 signer** now exists (`es256_signer_from_jwk`, `signer.py`), alongside the
  original Ed25519-only `ed25519_signer_from_jwk`. Both expose the `sign_raw` seam above.
  Confirmed interoperable with the real `@kya-os/mcp` reference implementation in both
  directions (Node-minted ES256 proof + `httpSig`, verified by Python; Python-minted ES256
  proof + `httpSig`, verified by Node's real `verifyCardProof`/`verifyHttpSignature`) - zero
  bugs found this time, unlike D16's first cross-language run.

At the time this paragraph was first written, the code wiring this engine into the SDK's own
hooks (`user_builder.ts`/`wrapper.ts`'s equivalents) did not exist yet. It does now - see
D15's `gate.py`/`client.py`, which fold what TypeScript splits into one Python module for a
structural reason (the SDK's sync/async split), not a straight `user_builder.py`/`wrapper.py`
port. `grpc_user_builder.ts`'s gRPC-transport equivalent remains unported - this package has
no gRPC transport wiring at all yet.

**Why.** The alternative - leaving the Python A2A package permanently unable to verify
anything - makes every other package built on top of it (a Python AP2 consumer wanting A2A
transport, for instance) unusable for its stated purpose. Reading the actual source rather
than the SPEC prose avoids the two failure modes of a from-spec reimplementation: missing a
narrow but load-bearing check (the small-order Ed25519 rejection is exactly this kind of
check - easy to miss from prose, a real forgery vector if skipped), and silently diverging
on a detail the spec leaves ambiguous but the reference implementation resolved one specific
way (e.g. the exact RFC 9421 Content-Digest string format the `requestHash` claim must use,
even though this package never sends that digest over real HTTP).

**Consequences.** This module has no corresponding TypeScript *test* file to port from
(`verify.ts`/`build.ts` are themselves the "specification" here, there being no
`@kya-os/mcp` TypeScript test suite shipped in the npm package either) - its 34 tests were
written directly against the fail-closed behaviour documented in `@kya-os/mcp`'s own source
comments, each one chosen to prove a specific claim in those comments true of this
reimplementation, not copied from an existing suite. A future `@kya-os/mcp` release could
change the profile in a way this package would not pick up automatically (no dependency
relationship exists to flag it) - revisit against the source on any reported interop failure
with a real `org.kya-os/proof.v1` peer.

**Revisit-if:** a Python package implementing this profile is ever published (switch to
depending on it instead of maintaining this reimplementation), or `user_builder.py`/
`wrapper.py`/`client.py` are scoped and built (the natural next step - this engine is what
they were blocked on).

---

## D14. A from-spec `org.kya-os/response-proof` engine, scoped narrowly

**Context.** `wrapper.ts` (server, signs the response) and `client.ts` (client, verifies it)
depend on a SECOND, different proof module from `@kya-os/mcp` - `src/proof/generator.ts`'s
`ProofGenerator` and `src/proof/verifier.ts`'s `ProofVerifier` (the legacy MCP-style
`org.kya-os/response-proof`, a full non-detached compact JWS - distinct from D13's
`org.kya-os/proof.v1`, which binds the CLIENT's request). Each TypeScript module has a much
larger surface than the two call sites actually use: `ProofVerifier` alone has
`verifyProofArtifact`, `verifyProofDetached` (deprecated), `fetchPublicKeyFromDID`, and an MCP
`_meta`-key-tolerance policy (`extractProofFromMeta`/`validateMetaStructure`) this A2A package
never touches (it reads `RESPONSE_PROOF_META_KEY` directly, never through MCP's `_meta`
namespace).

**Decision.** `python/packages/a2a/src/cheqd_agent_identity_a2a/proof/response.py` ports only
what `gate.py` and `client.py` (D15) actually call: `compute_canonical_hashes`,
`build_proof_jws_payload`, proof generation (full Ed25519 JWS, not detached), and the
verification pipeline's signer-binding, timestamp-skew, signature, content-binding and
nonce-replay checks. NOT ported: DID-based key resolution (this package's callers always pin
the server's key themselves), the deprecated verify paths, and the MCP `_meta`-tolerance
helpers.

**Why.** Porting the full TypeScript surface would mean carrying dead code for an MCP-specific
concern (`_meta` key coexistence under SEP-414) this A2A package has no reason to care about -
`org.kya-os/response-proof` happens to be implemented inside an MCP-focused package upstream,
but nothing about A2A's use of it is MCP-specific.

**Consequences.** Same as D13: no TypeScript test suite to port from, so `test_response_proof.py`'s
8 tests were written directly against the fail-closed behaviour in `verifier.ts`'s own source
comments (content-binding substitution detection, replay, signer binding, skew).

**Revisit-if:** a caller needs `verifyProofArtifact`'s pure historical-evidence path (no replay
state, no clock comparison) - not currently used anywhere in this A2A binding.

---

## D15. Collapsing `user-builder.ts` + `wrapper.ts` into one Python gate; dict-based, not proto-based

**Context.** Python's `a2a-sdk` (1.3.0) builds its `ServerCallContext` SYNCHRONOUSLY:
`ServerCallContextBuilder.build(request) -> ServerCallContext` is declared as a plain method,
and every dispatcher calls it without `await`
(`a2a/server/routes/jsonrpc_dispatcher.py:319`, `rest_dispatcher.py:108`, read directly, not
assumed). TypeScript's `userBuilder` seam is async (Express handlers are naturally async), so
`user-builder.ts` does its proof verification - DID resolution, nonce-cache I/O, both
genuinely async - right there. Python's equivalent seam cannot. The actual async hook Python
offers is one level down: `RequestHandler.on_message_send(params, context)` IS awaited by
every dispatcher, and nothing inside the default implementation touches task state before
that call - confirmed by reading `default_request_handler.py`'s `on_message_send`, not
assumed from the interface alone.

**Decision.** `gate.py`'s `AgentIdentityGate.handle_send_message(method, params, call_through)`
folds what TypeScript splits into `user-builder.ts` (verify) and `wrapper.ts` (enforce + sign
response) into one wrapping call around the real `on_message_send`, invoked by the integrator
before calling the real handler through. Separately: `gate.py`/`client.py` operate on plain
JSON-safe dicts (this package's own `CoveredRequest`/`covered_request()`/`covered_result()`
shapes), not the real `a2a-sdk`'s protobuf-typed `SendMessageRequest`/`Task` objects.
Converting between them (e.g. via `google.protobuf.json_format.MessageToDict`, the pattern
`a2a.utils.signing` already uses for Agent Card canonicalisation) is left to the integrator.

**Why.** Two independent reasons, not one: (1) the sync/async split above makes a literal
`user-builder.ts` port impossible as written, so the fold is a necessity, not a style choice;
(2) proto<->JSON round-trip fidelity for the REQUEST side specifically is security-sensitive -
the request hash a client signs must byte-for-byte match the canonicalisation the server
recomputes. `MessageToDict`'s exact behaviour (field casing, empty/default-value handling,
`oneof`s) was not independently verified against a real wire capture in the time available, so
claiming this module is correct for that conversion would overstate what was actually tested.
Keeping the conversion out of this module's responsibility means `gate.py`/`client.py`'s OWN
correctness (verify, enforce, sign, replay, content-binding) is provably right - proven with a
real client-to-server round trip in `tests/test_gate_and_client.py` - independent of that
unverified claim.

**Consequences (superseded in part - see below).** This is tested and proven correct for a
Python client talking to a Python server built on this package. The two PROOF ENGINES
underneath this layer (D13's `org.kya-os/proof.v1`, D14's `org.kya-os/response-proof`) are
verified cross-language against the real `@kya-os/mcp` - see D16.

**Update: the `MessageToDict`/`ParseDict` wiring layer is now built and tested against the
real `a2a-sdk`, not left to the integrator unverified.** `proto_bridge.py`
(`send_message_request_to_params`, `result_dict_to_proto`, `wrap_on_message_send`) is the
actual bridge, built against the REAL `a2a.types.SendMessageRequest`/`Task`/`Message`
protobuf classes installed in this repo's environment - not a hand-rolled stand-in - and
kept as its own module, deliberately separate from `gate.py`/`client.py`, for the same reason
D15 originally gave: so this module's own correctness (and its own test failures) never get
confused with the gate's.

`tests/test_proto_bridge.py` proves, with a REAL `SendMessageRequest`/`Task` proto round
trip (not simulated by hand): a client-minted proof survives `ParseDict`-then-`MessageToDict`
and still verifies on the server side; a request tampered with after minting (but before the
proto round trip) is still correctly rejected (`request_hash_mismatch`) after that round
trip; and the response proof the client verifies survives the same round trip on the way
back. The security-sensitive question D15 raised - "does the request-hash a client signs
byte-for-byte match what the server recomputes after a real proto round trip" - is now
answered with real evidence: **yes**, but not for free. One real finding surfaced along the
way:

`SendMessageRequest.message.metadata` is a `google.protobuf.Struct`, whose `Value.
number_value` is always a `double` - every number inside a proof that round-trips through a
real `SendMessageRequest` (`created`, `expires`, response-proof's `ts`) arrives as a Python
`float` (`1700000000.0`), never an `int`, even though the wire JSON had no decimal point.
Verified, not assumed, that this splits into two independent questions with two different
answers:

1. Does the REQUEST-HASH itself still match? Yes - `rfc8785.dumps({"created": 1700000000.0})`
   and `rfc8785.dumps({"created": 1700000000})` are byte-identical; RFC 8785's number
   formatting already collapses an integral float to the same canonical form as the
   equivalent int, matching JavaScript's own number semantics (JS has no `int` type at all).
2. Did the STRICT SCHEMA PARSER accept it? No, until fixed - `CardProofMeta`'s and
   `ResponseProofMeta`'s `isinstance(value, int)` checks rejected a well-formed proof
   outright once its `created`/`expires`/`ts` arrived as a float. Fixed in `proof/types.py`'s
   `_coerce_non_negative_int` and `proof/response.py`'s `_wire_to_meta` to accept a
   whole-number float as equivalent to an int - which is not a loosening relative to the
   TypeScript original, since `z.number().int()` already accepted exactly this shape (every
   JS number is a double; `.int()` only rejects a fractional part, never the underlying
   representation).

**Revisit-if:** a real cross-language A2A conformance run (TypeScript client -> Python
server, or vice versa) is attempted at the wiring layer - this remains unverified; only the
Python-proto-to-Python-gate round trip above is. Or `a2a-sdk` changes `SendMessageRequest`'s
`metadata` field type away from `google.protobuf.Struct` (unlikely, but would invalidate the
float-coercion fix's premise).

---

## D16. Real TypeScript↔Python conformance run on both proof engines - two bugs found and fixed

**Context.** D15 flagged that cross-language interop was unverified. The two PROOF ENGINES
(D13, D14) don't depend on `a2a-sdk` at all - `buildCardProof`/`verifyCardProof` and
`ProofGenerator`/`ProofVerifier` operate on plain `{method, params}`/`{data}` shapes
regardless of transport - so this part of D15's gap was directly testable without touching
the unverified `MessageToDict` boundary at all.

**What was run.** Using the REAL `@kya-os/mcp` package already installed in this repo's
`node_modules` (not a reimplementation, not mocked): minted a card proof (`proof.v1`) in
Node with `ed25519SignerFromJwk`/`buildCardProof` and verified it in Python with
`verify_card_proof`; minted the same proof type in Python and verified it with the real
`verifyCardProof` in Node; repeated both directions for the response-proof
(`ProofGenerator.generateProof` / `generate_response_proof`, `ProofVerifier.verifyProof` /
`verify_response_proof`); confirmed a Node-signed proof's `requestHash`/`responseHash` are
byte-identical to a Python-signed proof over the same content (JCS canonicalisation parity,
not just "verification passed"); confirmed a tampered field (audience) signed by Node is
correctly rejected by the Python verifier.

**Two real bugs found and fixed, not merely confirmed-correct:**

1. `CardProofMeta`'s strict parser (`types.py`) had no `httpSig` field, so any proof minted by
   a real signer with a `signRaw` seam (every `@kya-os/mcp` signer, by default) was rejected
   outright as `malformed_proof` - the Python verifier could not accept proofs from the real
   reference implementation at all until this was added. Fixed by adding the field (ignored
   for verification, matching D13's documented http-sig scope, but no longer a reason to
   reject the proof's presence).
2. `verify_response_proof`'s signature check never required the caller-supplied public JWK to
   declare the `kid` it was resolved for - `CryptoService.verifyJWS`'s TypeScript original
   does (`publicKeyJwk.kid !== options.expectedKid` fails closed), a real integrity check
   against a misconfigured or stale key resolver that the Python port silently dropped. Fixed
   by adding the same check; every existing Python test's fixture JWKs needed a `kid` field
   added as a result, which is itself evidence this was a genuine gap, not a cosmetic one.

**Why this matters.** Both bugs were invisible to the existing 185 Python-only tests, because
every one of them built its own matching key material end-to-end and never exercised what a
REAL, independently-built signer actually produces. This is exactly the blind spot a
same-codebase test suite cannot see into by construction - only a real second implementation
surfaces it.

**Consequences.** The two `org.kya-os/*` proof engines are now verified interoperable with
the real reference implementation, not merely internally consistent. The `gate.py`/`client.py`
wiring layer's `MessageToDict` boundary (D15) remains the one still-untested seam - a
different, transport-shaped question from "does the cryptography interoperate," which this
run answers conclusively: yes.

**Revisit-if:** `@kya-os/mcp` ships a new card-proof or response-proof field; re-run the same
two-directional mint/verify check on both engines before trusting a future `npm update`
silently stays compatible.

---

## D17. Response-proof nonce-cache TTL was floored too low - third bug, found by an independent gap audit

**Context.** After D16, a line-by-line audit of every Python check against its TypeScript
source (not another cross-language mint/verify run - a direct code comparison) found a third
bug D16's conformance run didn't surface, because D16 never let a nonce's cache entry actually
expire mid-test.

**The bug.** `verify_response_proof` (`response.py`) passed the bare `skew_sec` (default
120s) straight through as the nonce cache's TTL. The TS reference
(`ProofVerifier.consumeNonce`, `verifier.js`) instead floors the TTL at
`nonceRetentionSeconds` - at least 300s, extended to cover the full `ts ± skew` acceptance
window plus headroom.
Because the acceptance window is twice `skew_sec` wide but the Python cache entry was only
retained for one `skew_sec`, a nonce consumed near the start of its window could be evicted by
the cache before the timestamp-skew check alone would reject a replay of it - up to roughly
`skew_sec` seconds of extra replay exposure versus the TS reference. `proof.v1`'s own
`verify.py` already had the correct `_nonce_retention_seconds` floor for the *other* proof
engine, which is why this was clearly an accidental omission in `response.py`, not a
documented scope cut (D14 doesn't mention it).

**Fix.** Ported the same `_nonce_retention_seconds` floor (default 300s) into `response.py`
and call it before `consume_nonce_if_fresh`. Added
`test_nonce_cache_ttl_is_floored_to_default_retention_not_bare_skew`, since the existing replay
test's mock ignored its `ttl` argument entirely and would not have caught this even with the
bug present.

**Why this matters.** Neither the 185 Python-only tests nor D16's real cross-language
mint/verify run caught this, because both only ever checked whether a proof passed or failed
verification - never how long the nonce cache was asked to retain an entry. It took reading
the TS source's cache-TTL arithmetic line-by-line, not running it against a real peer, to find.
This is a different blind spot from D16's (schema/signature incompatibility vs. cache-lifetime
arithmetic) - both are necessary, neither alone is sufficient.

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
