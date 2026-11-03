# gRPC gate and the streaming response-proof boundary (3 November 2026)

Run: `npm install` then `node grpc-gate.mjs` (Node 26, real `@grpc/grpc-js` server and
`@a2a-js/sdk` 1.3.0 gRPC client, in-process, no stubs).

## gRPC gate (`grpc-gate.mjs`)

gRPC's `UserBuilder` is a **different seam** from the Express/JSON-RPC one tested in
`../gate-order/gate-userbuilder.mjs`: it is
`(call: grpc.ServerUnaryCall | grpc.ServerWritableStream) => Promise<User>`, reading the
already-deserialized protobuf request off `call.request.message.metadata`, not an HTTP
`req.body`. A gate written for the Express seam does not port as-is — each transport binding
needs its own small adapter over its own request shape, even though both ultimately feed the
same `A2ARequestHandler`.

| Scenario | Result |
|---|---|
| Proofed call, real gRPC client → real gRPC server round trip | Task created; executor ran once |
| Unproofed call, gate throws `ExtensionSupportRequiredError` (`@a2a-js/sdk/errors`) | Client receives a typed `GrpcExtensionSupportRequiredError`; executor never ran |
| Unproofed call, gate throws a plain `Error` | Client receives an opaque `GrpcA2AErrorImpl` wrapping gRPC status 2 (`UNKNOWN`) with the message text embedded |

Same pattern as spike A (`../spikes/`, JSON-RPC): the SDK maps a typed A2A error thrown
from the gate to a typed, named error class on the client, across both transports. A plain
`Error` still rejects correctly (the gate itself does not depend on the error type — the
executor never ran either way) but hands the client an undifferentiated gRPC `UNKNOWN`, not a
structured reason a caller can branch on. Implementers should throw a typed A2A error from
every transport's gate, not a bare `Error`.

Not covered: gRPC streaming calls (`sendMessageStream`/`SubscribeToTask`, `responseStream: true`
on the service definition), gRPC metadata/headers as an alternative proof carrier to the
protobuf body, and TLS / real channel credentials (`createInsecure()` only).

## Streaming and the response proof (confirmed by reading, not re-run)

Streaming is out of scope for the current design: a final-only proof must never be presented as
covering earlier streamed events. `../gate-order/slice-userbuilder-wrapper.mjs`
already demonstrates why this holds by construction, not just by convention: its request-handler
wrapper's `Proxy` (`withAgentIdentity`) intercepts `sendMessageStream` only to call `enforce(ctx)`
(the gate) — it never calls `respGen.generateProof(...)`, which is wired into the `sendMessage`
branch alone. So the chosen design cannot accidentally attach a response proof to a streamed
result; the MUST NOT is enforced by the shape of the wrapper, and a reviewer checking a future
change only needs to check that `generateProof` stays absent from the `sendMessageStream` branch.
The gate itself (`enforce(ctx)`) does run identically for both branches, confirmed in that file's
"unproofed `SendStreamingMessage` to a live task" case.

Not covered: a hash-chain or per-event proof scheme (deferred to v2 per spec), and gRPC server-
streaming specifically (`sendStreamingMessage`'s `responseStream: true` path above).
