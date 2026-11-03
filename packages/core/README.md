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

## License

[Apache 2.0](../../LICENSE)
