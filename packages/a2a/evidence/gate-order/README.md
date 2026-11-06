# Gate-ordering test (13 October 2026)

Run: `npm i @a2a-js/sdk@1.3.0 && node gate-order.mjs` (Node 26).

Uses the public API only, an in-memory task store, and a stub proof check (presence of the
`org.kya-os/request-proof` metadata key). It does not exercise Express, real proof verification,
`userBuilder` or gRPC.

Result against `@a2a-js/sdk` 1.3.0:

| Scenario | Unproofed follow-up to a live task |
|---|---|
| Gate inside `AgentExecutor` | Call returned a FAILED task (no error). Task state FAILED; history 1 -> 3; injected message present |
| Gate in front of `sendMessage`, call via `sendMessage` | Threw before the SDK ran. State and history unchanged |
| Same gate, call via `sendMessageStream` | Injected message persisted (history 1 -> 2). Stream error text came from the test's inner executor |
| Gate in front of both methods | Threw. State and history unchanged |
| Executor gate, different user | "Task not found". Nothing changed (owner scoping) |

## userBuilder and Express middleware (`gate-userbuilder.mjs`)

Real HTTP through `jsonRpcHandler` (Express 5.3.0), SDK 1.3.0, executor with no verification.

| Step | Result |
|---|---|
| Proofed create as agent A | HTTP 200, task created. The raw request body (225 bytes) was available to `userBuilder` via `express.json({ verify })` |
| Unproofed follow-up, gate in `userBuilder` | HTTP 500, JSON-RPC `-32603` "proof_missing", logged as an unhandled error. Task unchanged (history 1) |
| Unproofed `SendStreamingMessage` | Same: rejected, task unchanged |
| Proofed follow-up as a different agent B | `-32001` Task not found. A's task unchanged: tasks are scoped to the verified DID |
| Proofed follow-up as A (control) | HTTP 200, history 2 |
| Same gate as Express middleware ahead of the handler | HTTP 401 with `WWW-Authenticate`, task unchanged |

## Response-proof placement (`response-proof.mjs`)

SDK 1.3.0, real HTTP, hash = SHA-256 over JCS of the task JSON with the proof key removed. The
executor-made proof comes from an executor that reconstructs the final task itself (it replicates
the SDK's metadata merge by hand).

| Proof made | Client asks | Client recomputes same hash |
|---|---|---|
| In the executor | full history | Yes |
| In the executor | `historyLength: 1` | **No** (executor believed history 4, client received 1) |
| Request-handler decorator, over the final result | full history | Yes |
| Request-handler decorator, over the final result | `historyLength: 1` | Yes |

Not covered: streaming, non-blocking (`returnImmediately`) calls, whether the proof key persists in
the task store, executors that publish further events after the proof, extension filtering.

## Vertical slice (`slice-both.mjs`)

Real `@a2a-js/sdk` 1.3.0 client + Express server, `@kya-os/mcp` 1.20.0, `did:web` keys in memory.

| Step | Result |
|---|---|
| Round trip through the real client with a `CallInterceptor` minting `buildCardProof` | Verified on the server (`L3-minus`); `A2A-Extensions` header arrived |
| Response proof verified by the client's `after` hook | Valid |
| Response altered after proving | Rejected (response hash mismatch) |
| Response proof presented for a different request | Rejected (request hash mismatch) |
| Follow-up with `historyLength: 1` | Response proof valid |
| Replay | 401 `nonce_replayed` |
| Altered message part / altered `contextId` | 401 `request_hash_mismatch` |
| Proof for another audience | 401 `audience_mismatch` |
| Signature by a key not in the DID | 401 `invalid_signature` |
| No proof | 401; executor never ran in any rejected case |

Not covered: ES256, `cnf` fusion (L3), real `did:web`/`did:cheqd` resolution, streaming, REST,
Message (non-Task) results, persistence of the proof key.

## ES256, alg/key mismatch, and cnf fusion (`alg-cnf.mjs`)

Direct calls to `buildCardProof` / `verifyCardProof` (no A2A SDK, no HTTP — the wire plumbing is
covered above; this isolates the proof layer itself). `@kya-os/mcp` 1.20.0.

| Check | Result |
|---|---|
| ES256 proof minted with a P-256 key, resolved as an EC/P-256 key | `ok=true`, `level=L3-minus` (no token `cnf.jkt` supplied) |
| `alg: ES256` but `resolveKey`/`resolveDidKeys` return an Ed25519 (OKP) key | `ok=false`, `alg_key_mismatch` + `cnf_key_mismatch` |
| `cnf` present, verifier's `tokenCnfJkt` matches the proof's `cnf.jkt` | `ok=true`, `level=L3` |
| `cnf` present, verifier given no `tokenCnfJkt` | `ok=true`, `level=L3-minus`, non-fatal warning `cnf_present_but_token_unfused` |
| `cnf` present, verifier's `tokenCnfJkt` differs (downgrade/substitution attempt) | `ok=false`, `cnf_token_mismatch` |
| `BuildProofContext.cnfJkt` overridden to an arbitrary value instead of the signer's own thumbprint | `ok=false`, `cnf_key_mismatch` |

The last row matters for implementers: `cnfJkt` looks like a free override point for binding to
an external RFC 9449 DPoP token, but `verifyCardProof` independently recomputes
`thumbprint(resolve(kid))` and requires it to equal `cnf.jkt`. So the
override only ever validates when the DPoP token's proof-of-possession key **is the same keypair**
as the DID signing key — it cannot bind to a different AS-issued key. Full `L3` therefore requires
the agent's OAuth client and its DID both using one key; two independent keys cap out at
`L3-minus` with a `cnf_present_but_token_unfused` warning, not a silent partial bind. Worth a note
for implementers wiring an OAuth AS into the proof.

Not covered: RFC 9421 `httpSig` verification path for ES256, a real OAuth/DPoP token flow (this
used a synthetic `tokenCnfJkt` string), and ES256 on the response-proof side (ruled out by design
— §4.5 notes the response generator is EdDSA-only).

## Delegation chain enforcement (`delegation-chain.mjs`)

`validateDelegationChain` (`@kya-os/mcp/delegation`) called directly against synthetic 2-hop
chains (`wrapDelegationAsVC`), stub per-credential verifier (structural checks only — real
Ed25519 VC-proof verification is the card-proof tests above, not this module), stub revocation
checker. `@kya-os/mcp` 1.20.0.

| Scenario | Result |
|---|---|
| Valid 2-hop chain, scopes narrowed `read+write` → `read` | `valid=true` |
| Child claims a scope (`admin`) the parent never granted | `valid=false`, "widens scopes beyond parent" |
| `maxChainLength: 1` on a 2-credential chain | `valid=false`, "exceeds the maximum of 1" |
| Leaf's `constraints.audience` excludes the verifying server's DID | `valid=false`, "audience does not include server DID" |
| Parent cycle (root's `parentId` points back to the child) | `valid=false`, "must end with the leaf credential" |
| Ancestor revoked via the injected `revocationChecker`, leaf's own status bit untouched | `valid=false`, "is revoked via ancestor" — confirms the E3.1 fix (chain-enforcement.d.ts) actually catches what a leaf-only status check would miss |
| `trustedRootIssuers` set, root signed by a DID not on the list | `valid=false`, "not a trusted root issuer" |
| Originating principal (`userDid` on the root credential) | Reachable unchanged on the resolved ancestor after a valid validation |
| `statusListConfigured: false`, leaf carries a `credentialStatus` anyway | `valid=false`, fails closed rather than skipping the check |

All nine matched the module's own doc comments exactly; no surprises, no spec changes needed.
Not covered: real Ed25519 VC-proof verification (per-credential `verifier` was stubbed), CRISP
scope matchers (only flat scopes tested), and `resolveDelegationChain` returning a chain longer
than the leaf's `parentId` depth implies.

## Re-running

`npm install` in this folder installs the pinned versions, then `node gate-order.mjs`,
`node gate-userbuilder.mjs`, `node response-proof.mjs`, `node slice-both.mjs`,
`node wire-fidelity.mjs`, `node slice-userbuilder-wrapper.mjs`, `node alg-cnf.mjs` or
`node delegation-chain.mjs`. The scripts
are exploratory: stub proof checks in the first two, in-memory DIDs elsewhere, no network.
Re-run them on every SDK or `@kya-os/mcp` bump before trusting the results in the spec.

## Wire fidelity: wrapper vs middleware (`wire-fidelity.mjs`)

The client hashes exactly the JSON it sends. The middleware verifies the parsed wire body; the
wrapper verifies params re-serialised from the SDK's typed form. SDK 1.3.0, `@kya-os/mcp` 1.20.0.
The SDK itself accepted every payload below.

| Payload | Middleware | Wrapper |
|---|---|---|
| baseline | accepted | accepted |
| unknown field on the message | accepted | **rejected** (`request_hash_mismatch`) |
| unknown field on a part | accepted | **rejected** |
| unknown field on params | accepted | **rejected** |
| unknown field in configuration | accepted | **rejected** |
| enum sent as a number (`role: 1`) | accepted | **rejected** |
| explicit default values (empty ids, empty arrays) | accepted | **rejected** |
| snake_case field name (`message_id`) | accepted | **rejected** |
| nested metadata (floats, null, arrays) | accepted | accepted |
| part with `mediaType` and `filename` | accepted | accepted |

## Hybrid: verifying `userBuilder` + enforcing wrapper (`slice-userbuilder-wrapper.mjs`)

No Express middleware. A `userBuilder` reads the wire body, verifies the proof and sets the
identity (it never throws; a failure becomes an unauthenticated user carrying a reason). A
request-handler wrapper enforces, delegates, and makes the response proof. SDK 1.3.0,
`@kya-os/mcp` 1.20.0, real HTTP.

| Check | Result |
|---|---|
| Nine wire payloads (unknown fields, numeric enum, explicit defaults, snake_case, nested metadata) | All accepted |
| Replay, altered part, no proof, wrong audience, key not in the DID | All rejected; executor never ran |
| Unproofed `SendStreamingMessage` to a live task | Rejected; task history unchanged |
| Another verified agent writing to the first agent's task | "Task not found"; tasks scoped to the verified DID |
| Response proof, normal and with `historyLength: 1` | Valid in both |
| Verifying `userBuilder` not installed | Every proofed request rejected (fails closed) |
| Anonymous `GetTask` on the owner's task | Not visible |

Failures are JSON-RPC errors under HTTP 200 (`-32008` when a proof is missing, `-32602` when invalid).
Not covered: REST and gRPC, ES256, the real SDK client path, streaming responses.
