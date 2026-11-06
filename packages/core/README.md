# @cheqd/agent-identity

> **DRAFT — early exploration, not reviewed or stable.** The public API may change completely. Do not depend on it.

Shared identity core. See the [repository README](../../README.md) for how the packages relate.

## What's here

- `src/status/ledger-anchored.ts` — ledger-anchored revocation checking for cheqd Bitstring
  status lists, without relying on a signed credential proof (cheqd's current
  `BitstringStatusListCredential` resources are signed before `encodedList` is attached, so the
  proof does not cover the bits — see
  [`docs/research/a2a-trust-binding-findings-2026-11.md`](../../docs/research/a2a-trust-binding-findings-2026-11.md)
  §8). Instead it treats the ledger itself as the source of truth: fetches the resource, checks
  the resolver's own checksum against the bytes returned, and optionally requires several
  resolvers to agree. Fails closed on every unreadable, stale, inconsistent or unsupported case.
  29 tests in `test/ledger-anchored.test.mjs`, against a fake resolver built to mimic the real
  one's response shapes.
- `src/agent-card/retrieve-public-key.ts` — a DID-backed `retrievePublicKey` callback for
  `@a2a-js/sdk`'s `verifyAgentCardSignature`. Resolves `did:web` (a real HTTPS fetch, injected)
  and `did:key` (Ed25519, pure computation) for real; `did:cheqd` is opt-in via an injected
  resolver. Never reads the signer-supplied `jku` header - see the module's own doc comment for
  why that matters (CWE-863). 12 tests in `test/retrieve-public-key.test.mjs`; see
  `packages/a2a/smoke-test-agent-card.mjs` for it wired into the real SDK function.
- `src/status/status-list-resolver.ts` — adapts `verifyLedgerAnchoredStatus` to `@kya-os/mcp`'s
  `StatusListResolver` seam, so delegation chain verification can use it directly. 4 tests.
- `src/linkage/reciprocal-linkage.ts` — reciprocal `alsoKnownAs` linkage between two DID
  documents (e.g. `did:cheqd` and `did:web`). A one-directional claim proves nothing; each side
  must name the other. 7 tests.
- `src/dlr/resolve-manifest.ts` — resolves a `TrustConfigManifest`/`CapabilityManifest`/
  `ConformanceManifest` DID-Linked Resource with the same trust model as `ledger-anchored.ts`
  (resolver checksum, multi-resolver agreement, fail-closed), plus `createManifestCache` for the
  per-kind TTL the spec requires. 11 tests.
- `src/replay/file-nonce-cache.ts` — a persistent (file-backed) replay cache implementing
  `@kya-os/mcp`'s `NonceCacheProvider`, so a consumed nonce survives a process restart (their own
  `InMemoryNonceCache`/`MemoryNonceCacheProvider` are explicitly single-process/dev-only).
  Atomic via `fs.open(path, 'wx')`. 12 tests, including 20-way concurrent `consume()`.
- `src/did-cheqd/resolve.ts` — a `did:cheqd` resolver for the Agent Card resolver's opt-in slot.
  Confirmed against the real public `resolver.cheqd.net`, not just a fake one. 9 tests.
- `src/status/eddsa-jcs-status.ts` — `createCheqdStatusChecker`: the proof-checked alternative
  to `ledger-anchored.ts`'s checksum-only trust, wiring `@kya-os/mcp`'s generic
  `createStatusListProofVerifier`/`createRevocationChecker` to this package's `did:cheqd`
  resolver. `did-provider-cheqd` does not yet produce a `BitstringStatusListCredential` whose
  proof covers `encodedList` (cheqd/did-provider-cheqd#657); this module is written against the
  format its open, unmerged fix (#658) produces, confirmed directly against that branch's own
  signer. 4 tests in `test/eddsa-jcs-status.test.mjs`, against a fixture signed with #658's real
  code (`test/fixtures/bitstring-status-list-eddsa-jcs-2022.json` — see that file's generating
  script, `evidence/status-list/mint-fixture.mjs`, in the `a2a-drafts` working repo). Once #658
  ships a real signed list on-chain, swap the fixture for live data; the verifier is unchanged.
- `src/proof/eddsa-jcs-2022.ts` — `verifyEddsaJcs2022`: a generic `DataIntegrityProof`/
  `eddsa-jcs-2022` verifier for an arbitrary document (not status-list-specific), the same W3C
  Data Integrity construction `@kya-os/mcp/card`'s status-list verifier checks, generalised.
  Used by `@cheqd/agent-identity-ap2`'s Agent Payment Key Credential verification, so that
  construction is implemented once, not twice.

## License

[Apache 2.0](../../LICENSE)
