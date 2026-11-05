# Sample

Run after a build: `node sample/run.mjs` (from `packages/a2a/`).

A runnable walkthrough of the gate and `CallInterceptor` composed with the DID-backed Agent
Card key resolver and the cheqd-specific identity checks, against a real `@a2a-js/sdk`
client/server. Six sections, run in order:

1. **JSON-RPC transport** — real client, real Express server, a proofed `SendMessage` round
   trip through the reusable gate (`createVerifyingUserBuilder` + `withAgentIdentity`) and
   interceptor (`createProofInterceptor`). Replay protection is `FileNonceCacheProvider`
   (`@cheqd/agent-identity`), a persistent, file-backed replay cache — not the SDK's dev-only
   in-memory ones — shared by sections 1-3 over one temp directory for the run.
2. **REST transport** — the same gate, no new code (`restHandler`'s method-from-route
   convention).
3. **gRPC transport** — `createVerifyingGrpcUserBuilder`, a different `UserBuilder` seam. This
   exercises the covered-form fix: the gate canonicalises `call.request` via
   `SendMessageRequest.toJSON` before hashing, matching what the client signs.
4. **Live cheqd testnet DID resolution** — a **real network call** to the public
   `resolver.cheqd.net`, resolving `did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede`
   through `createDidCheqdResolver` wired into `createRetrievePublicKey`'s opt-in slot. This DID
   publishes the legacy `Ed25519VerificationKey2018`/`publicKeyBase58` format, not the newer
   `publicKeyMultibase`/`publicKeyJwk` — found by running this sample against live data, fixed
   in `retrieve-public-key.ts`.
5. **Ledger-anchored status check** — a **synthetic fixture**, not live. No
   `BitstringStatusListCredential` has been found on cheqd testnet yet (see
   `evidence/status-list/README.md`); this section fabricates a resolver response in the exact
   shape `resolver.cheqd.net` returns (captured 13 October 2026), the same approach
   `packages/core/test/ledger-anchored.test.mjs` uses.
6. **Trust extension checks** — `verifyTrustExtension`/`createTrustExtensionCache` composing
   reciprocal linkage, DLR manifest resolution and status into one per-DID check. Linkage and
   the manifest are **synthetic fixtures** (no real reciprocal `alsoKnownAs` link or DLR exists
   for this sample's identities). The status half uses `createCheqdStatusChecker` against
   `fixtures/bitstring-status-list-eddsa-jcs-2022.json` — a `BitstringStatusListCredential`
   signed with the **real** (not reimplemented) `signEddsaJcs2022` from
   `cheqd/did-provider-cheqd`'s not-yet-merged `#658` branch, so the proof-checking path is
   exercised against genuine signer output, not a hand-rolled approximation of it.

## What's real and what isn't

Sections 1–3 sign and verify real A2A proofs end to end, using two `did:web` identities
generated locally (the sample holds both private keys), with a persistent replay cache. Section
4 is a real resolution against live cheqd testnet data, but resolution only — the sample does
not hold the resolved DID's private key, so it cannot sign or verify a genuine A2A proof as that
identity. Section 5 is entirely synthetic, clearly logged as such at runtime, not silently
presented as live. Section 6's linkage and manifest fixtures are synthetic; its status fixture
is synthetic data signed with real, unmodified `#658` branch code and verified with real,
unmodified `@kya-os/mcp` code — the cryptography is real, only the on-chain resource it stands
in for is not.

DRAFT — early exploration, not reviewed or stable. See the [repository README](../README.md).

SPDX-License-Identifier: Apache-2.0
