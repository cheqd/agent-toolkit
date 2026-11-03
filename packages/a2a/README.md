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
  doc §2 for why this shape, not an `AgentExecutor` decorator or Express middleware).
- `src/client.ts` — the client-side `CallInterceptor`.
- `evidence/` — the research scripts behind all of this, runnable against real
  `@a2a-js/sdk` and `@kya-os/mcp`.
- `smoke-test.mjs`, `smoke-test-rest.mjs`, `smoke-test-grpc.mjs`, `smoke-test-agent-card.mjs` —
  real client/server round trips for JSON-RPC, REST, gRPC and Agent Card signature verification.

## A known gap: gRPC proofs don't work yet, and the gate's rejection does

`smoke-test-grpc.mjs` shows both halves. The gate itself (`call.path` method detection,
enforcement, typed-error mapping) works correctly over gRPC: an unproofed call is rejected with
the executor never running. A *correctly proofed* call currently fails, and that failure is the
finding, not a test bug: `client.ts`'s `createProofInterceptor` computes the covered request
from `SendMessageRequest.toJSON(params)` - the JSON-RPC wire shape (default fields omitted,
enums as strings, `oneof`s flattened). gRPC's `call.request` on the server is the SDK's
deserialised protobuf object instead (defaults present, enums numeric, `oneof`s as `{content:
{$case: "text", value: "hi"}}`). Confirmed by diffing both shapes directly. There is no JSON
wire form for gRPC to canonicalise against in the first place - the real wire form is binary
protobuf - so this isn't a bug to patch so much as an open design question: does gRPC need its
own covered-form definition, should the proof bind to raw protobuf bytes if the SDK exposes them
pre-decode, or does a proof simply never cross transports? Not decided here.

## What's not here yet

DID-Linked Resource policy (resolution exists in `@cheqd/agent-identity`'s `resolveManifest` and
`createManifestCache`, not wired in here), `did:cheqd` resolution for the Agent Card resolver
(exists as `createDidCheqdResolver`, not wired in here), the gRPC proof covered-form gap above,
and a runnable sample against cheqd testnet. Status-list checks and a persistent replay cache
now exist in `@cheqd/agent-identity` (`createLedgerAnchoredStatusListResolver`,
`FileNonceCacheProvider`) but aren't called from this package yet either.

## License

[Apache 2.0](../../LICENSE)
