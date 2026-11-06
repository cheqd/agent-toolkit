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

## License

[Apache 2.0](../../LICENSE)
