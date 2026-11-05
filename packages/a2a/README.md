# @cheqd/agent-identity-a2a

> **DRAFT — early exploration, not reviewed or stable.** The public API is not designed and may
> change completely. Do not depend on it. See
> [`docs/research/a2a-trust-binding-findings-2026-11.md`](../../docs/research/a2a-trust-binding-findings-2026-11.md)
> for the research behind this and [`evidence/`](./evidence) for the scripts that produced it.

A2A binding: a request/response proof gate for `@a2a-js/sdk`, and the matching client-side
`CallInterceptor`. See the [repository README](../../README.md) for how the packages relate.

## What's here

- `src/covered-request.ts` — the canonical request/response shape a proof is computed over.
- `src/user-builder.ts` — the verifying `userBuilder` for JSON-RPC AND REST (`@a2a-js/sdk/server/
  express`'s `jsonRpcHandler` and `restHandler` share this one seam; REST carries the method in
  the route instead of the body, handled here).
- `src/grpc-user-builder.ts` — the gRPC form. A genuinely different seam (reads `call.request`,
  discriminates the RPC via `call.path`, not an HTTP body) - see the caveat below.
- `src/wrapper.ts` — the enforcing request-handler wrapper, transport-agnostic (see the findings
  doc §2 for why this shape, not an `AgentExecutor` decorator or Express middleware). Optionally
  takes a `TrustExtensionGate` (see below) and rejects a verified caller whose cached
  trust-extension checks are not `ok`, alongside its existing proof enforcement.
- `src/trust-extension.ts` — the `https://cheqd.io/a2a/ext/trust/v1` extension's per-DID checks
  (spec §5.2 steps 5-7: reciprocal `alsoKnownAs` linkage, DLR manifest resolution, status),
  composed from `@cheqd/agent-identity`'s building blocks, TTL-cached per DID (spec §5.5: never
  per call) via `createTrustExtensionCache`. Pass its result as `withAgentIdentity`'s third
  argument to wire it into the gate; see `smoke-test-trust-extension.mjs` for both outcomes
  (accepted when checks pass, rejected with the executor never running when they don't) and
  `test/trust-extension.test.mjs` for the module in isolation.
- `src/client.ts` — the client-side `CallInterceptor`.
- `evidence/` — the research scripts behind all of this, runnable against real
  `@a2a-js/sdk` and `@kya-os/mcp`.
- `smoke-test.mjs`, `smoke-test-rest.mjs`, `smoke-test-grpc.mjs`, `smoke-test-agent-card.mjs`,
  `smoke-test-trust-extension.mjs` — real client/server round trips for JSON-RPC, REST, gRPC,
  Agent Card signature verification, and the trust-extension gate.
- `sample/` — a runnable walkthrough of all three transports plus the cheqd-specific checks,
  including one real network call against the public cheqd testnet resolver. See
  [`sample/README.md`](./sample/README.md) for what's real and what's a labelled synthetic
  fixture.

## gRPC proofs: fixed

`smoke-test-grpc.mjs` shows both halves passing. The gate itself (`call.path` method detection,
enforcement, typed-error mapping) works correctly over gRPC: an unproofed call is rejected with
the executor never running. A *correctly proofed* call previously failed:
`client.ts`'s `createProofInterceptor` computes the covered request from
`SendMessageRequest.toJSON(params)` - protobuf's canonical-JSON mapping (default fields omitted,
enums as strings, `oneof`s flattened) - but `grpc-user-builder.ts` was hashing `call.request`
directly, the SDK's *deserialised* protobuf object (defaults present, enums numeric, `oneof`s as
`{content: {$case: "text", value: "hi"}}`) - a structurally different shape, confirmed by
diffing both directly. Fixed by running `call.request` through that same `SendMessageRequest.
toJSON` before building the covered form (`SendMessageRequest` is a root `@a2a-js/sdk` export,
not `server/grpc`-specific) - reusing the SDK's own canonical-JSON converter on both sides rather
than inventing a gRPC-specific covered-form definition or binding to raw protobuf bytes.

## Trust extension, DLR policy and replay cache: wired, opt-in

`src/trust-extension.ts` composes `@cheqd/agent-identity`'s reciprocal-linkage, DLR-manifest and
status-check building blocks into one gate-ready check, and `withAgentIdentity`'s optional third
argument wires it into enforcement (see above). It is opt-in, not a default: the trust extension
itself is optional per the Agent Card (spec §5.1), so `withAgentIdentity` runs exactly as before
when no `TrustExtensionGate` is passed. `sample/run.mjs` demonstrates both the module on its own
and wired into a real gate; `smoke-test-trust-extension.mjs` is the gate-level proof.

A persistent (file-backed) replay cache (`FileNonceCacheProvider`, in `@cheqd/agent-identity`)
is likewise opt-in via `consumeNonceIfFresh` — `sample/run.mjs` uses it in place of
`@kya-os/mcp`'s dev-only `InMemoryNonceCache`/`MemoryNonceCacheProvider` for all three transports.

## What's not here yet

Status-list integrity has two paths now: `verifyLedgerAnchoredStatus` (checksum/ledger-anchoring
only) and `createCheqdStatusChecker` (proof-checked, per decision 6's final recommendation) are
both available, but no real cheqd-issued `BitstringStatusListCredential` whose proof covers
`encodedList` exists yet — that needs `cheqd/did-provider-cheqd#657`/`#658` (open, unmerged) to
ship. `sample/run.mjs`'s trust-extension section uses a fixture signed with #658's own branch
code in the meantime; see `packages/core/README.md`'s `eddsa-jcs-status.ts` entry.

## License

[Apache 2.0](../../LICENSE)
