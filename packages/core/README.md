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

## License

[Apache 2.0](../../LICENSE)
