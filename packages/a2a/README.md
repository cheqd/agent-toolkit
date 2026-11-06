# @cheqd/agent-identity-a2a

> **DRAFT — early exploration, not reviewed or stable.** The public API is not designed and may
> change completely. Do not depend on it. See
> [`docs/research/a2a-trust-binding-findings-2026-11.md`](../../docs/research/a2a-trust-binding-findings-2026-11.md)
> for the research behind this and [`evidence/`](./evidence) for the scripts that produced it.

A2A binding: a request/response proof gate for `@a2a-js/sdk`, and the matching client-side
`CallInterceptor`. See the [repository README](../../README.md) for how the packages relate.

## What's here

- `src/covered-request.ts` — the canonical request/response shape a proof is computed over.
- `src/user-builder.ts` + `src/wrapper.ts` — the gate: a verifying `userBuilder` plus an
  enforcing request-handler wrapper (see the findings doc §2 for why this shape, not an
  `AgentExecutor` decorator or Express middleware).
- `src/client.ts` — the client-side `CallInterceptor`.
- `evidence/` — the research scripts behind all of this, runnable against real
  `@a2a-js/sdk` and `@kya-os/mcp`.
- `smoke-test-agent-card.mjs` — DID-backed Agent Card key resolution
  (`@cheqd/agent-identity`'s `createRetrievePublicKey`) wired into the real SDK function.
  `did:web` and `did:key` work for real; `did:cheqd` is opt-in (not wired up here yet).

## What's not here yet

DID-Linked Resource policy, status-list checks wired into the gate (the check itself,
`verifyLedgerAnchoredStatus`, exists in `@cheqd/agent-identity` but isn't called from here yet),
a persistent replay cache, REST/gRPC/streaming forms beyond what's smoke-tested in `evidence/`,
`did:cheqd` resolution for the Agent Card resolver, and a runnable sample against cheqd testnet.

## License

[Apache 2.0](../../LICENSE)
