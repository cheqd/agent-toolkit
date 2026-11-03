# Spikes, 13 October 2026

Scripts run against `@a2a-js/sdk` 1.3.0 and `@kya-os/mcp` 1.20.0 (see `package.json`; `npm install`
then `node spikes-a.mjs` or `node spike-card-signature.mjs`). `harness.mjs` is the chosen design
(verifying `userBuilder` + enforcing wrapper) with counters. A Python cross-language client was
planned and deliberately not built.

## A. How the real SDK client surfaces rejections

| Request | What the client throws |
|---|---|
| Valid proof | Returns the task |
| No proof | `JsonRpcExtensionSupportRequiredError`, reason `EXTENSION_SUPPORT_REQUIRED`, message `proof_required: missing` |
| Proof for another audience | `JsonRpcRequestMalformedError`, reason `INVALID_PARAMS`, message `proof_invalid: audience_mismatch` |

Typed errors with a stable `reason`, so a client can branch on them. Both are `Error` instances.

## B. Persistence and owner reads

- The **request proof stays in the stored message history** (nonce, JWS and all).
- The **response proof is not stored** on the task; each response carries a fresh one.
- **Gap:** the owner cannot read its own task. `GetTask` carries no proof, so the `userBuilder` treats
  the caller as anonymous and the task is invisible (`-32001`). Every task-addressed method
  (`GetTask`, `ListTasks`, `CancelTask`, subscribe, push-notification config) needs an identity, and
  these methods have no `message.metadata` to carry a proof.

## C. REST transport

Same `userBuilder` and wrapper. The card must declare an `HTTP+JSON` interface. A proofed
`POST /message:send` returned 200 with a response proof; an unproofed one was rejected with
**HTTP 400** (`FAILED_PRECONDITION`, `proof_required: missing`), so unlike JSON-RPC (HTTP 200) the
rejection is visible at the HTTP layer, though not as a 401.

## D. Agent Card signature with a DID-backed resolver

The resolver ignores `jku`, pins the DID the caller expects, and resolves `kid` from DID documents.

| Case | Result |
|---|---|
| Signed by the server key | Accepted |
| Same, with an attacker `jku` header | Accepted; the `jku` was never used |
| Attacker key claiming the server's `kid` | Rejected |
| Attacker signing as itself | Rejected |
| Card changed after signing | Rejected |
| No signature | Rejected |
| Two signatures, one valid | **Accepted** (the SDK accepts a card if any signature verifies) |
| Extension `params` changed, added to, or emptied | **Rejected: params are covered** |
| Extension `description` changed | Rejected |
| Unknown top-level field added | **Accepted: not covered** |

The SDK verifies "any signature verifies against the key the callback returns" and binds nothing to
an identity, so the callback must pin the expected DID itself.

## E. Resolver traffic from junk proofs

200 junk proofs (wrong audience, expired, or bad signature): **200 key resolutions** without cheap
pre-checks, **66** with them (audience and time window checked before resolving). The remainder are
proofs that pass the cheap checks and fail only on the signature, which needs caching and rate
limiting to bound. `verifyCardProof` resolves the key regardless of the other checks.
