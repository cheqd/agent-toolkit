# A2A trust binding: findings and design decisions — November 2026

> **Research notes, not a specification.** Compiled 13 October – 3 November 2026 by reading and
> exercising `@a2a-js/sdk` 1.3.0 and `@kya-os/mcp` 1.21.2 directly — real client/server round
> trips, real HTTP/gRPC transports, real Ed25519/ES256 cryptography. Scripts are in
> `packages/a2a/evidence/`; re-run them on every SDK or `@kya-os/mcp` bump before relying on any
> finding here.

## 1. Summary

- A request-proof gate for `@a2a-js/sdk` is unsafe as an `AgentExecutor` decorator: the SDK
  mutates task state before the executor runs, so an unverified caller's message is written into
  task history even when the executor later throws. The gate that works is a verifying
  `userBuilder` plus a request-handler wrapper (§2).
- The response proof must be made over the SDK's JSON-serialised result (`Task.toJSON(...)`),
  never the SDK's in-memory typed object — the latter carries explicit `undefined` fields that
  break JCS canonicalisation, and `historyLength` trimming happens after the executor runs, so a
  proof made inside the executor can diverge from what the client actually receives (§3).
- `verifyAgentCardSignature`'s key-resolution callback must ignore the signer-supplied `jku`
  header and pin the DID the caller expects; the SDK accepts a card if *any one* of several
  signatures verifies and binds the result to no identity (§4).
- ES256 and `cnf` (RFC 7949-style sender-constraint) fusion work as specified, with one sharp
  edge: a proof's `cnf.jkt` can only ever equal the signing key's own thumbprint, so achieving
  full assurance requires the OAuth client and the DID signer to share one keypair (§5).
- Delegation chain enforcement (`maxChainLength`, scope attenuation, cascading revocation,
  trusted root issuers) matches its own documentation exactly against synthetic chains (§6).
- The gate, the response proof and delegation enforcement all work unmodified over gRPC, given a
  transport-specific adapter for the `UserBuilder` seam — gRPC's `UserBuilder` reads the
  deserialised protobuf request, not an HTTP body, so a JSON-RPC gate does not port as-is (§7).
- `@kya-os/mcp` ships **two incompatible "ledger-anchored status list" verifiers** inside one
  package, with different wire formats, and neither type-checks against the other (§8).
- A cheqd-specific status-list check that doesn't need either of those verifiers, or any signed
  credential proof, is now in `packages/core` (`verifyLedgerAnchoredStatus`): it treats the
  ledger itself as the trust anchor, checks the resolver's own checksum, and optionally requires
  several resolvers to agree before trusting a result (§9). This is the recommended approach for
  checking a cheqd-anchored credential's status today, since it works against live resources now
  rather than waiting on a signing change.

## 2. Where the request-proof gate has to sit

Tested against `@a2a-js/sdk` 1.3.0, stub proof checks, in-memory task store
(`evidence/gate-order/gate-order.mjs`, `gate-userbuilder.mjs`).

| Option | Finding |
|---|---|
| `AgentExecutor` decorator | **Unsafe.** `DefaultRequestHandler` appends an incoming message to a live task's history and saves it *before* the executor runs. A throwing executor publishes a synthetic `FAILED` task rather than raising an error. An unproofed follow-up to an existing task is written into history either way |
| Request-handler wrapper only, re-deriving the covered form from the SDK's typed params | Rejects every attack and makes a correct response proof, but re-serialising the SDK's typed object instead of reading the wire JSON falsely rejected 7 of 10 valid payloads (unknown fields, a numeric enum, explicit defaults, `snake_case`) — exactly the kind of payload a different-language client produces |
| Express middleware (verify, set identity, intercept `res.json` to sign) | Works, and gives a real HTTP 401, at the cost of an ordering hazard (installed in the wrong place, it fails open), fragile response interception, and per-transport duplication |
| **Verifying `userBuilder` + enforcing wrapper (chosen)** | The `userBuilder` reads the wire JSON-RPC body, verifies the proof, and returns the verified DID as the SDK's user — or an unauthenticated user carrying the rejection reason; it never throws (a throwing `userBuilder` surfaces as an opaque HTTP 500). The wrapper rejects any write without a verified identity, delegates, and makes the response proof over the final result. This accepted all nine wire-payload variants tried, rejected every attack with the executor never running, scoped tasks to the verified DID, and failed closed when the `userBuilder` was not installed |
| Reverse proxy / sidecar | Not tested. Language-agnostic and independent of SDK internals; kept as a later deployment mode reusing the same verification logic |

Consequence of the chosen design: failures surface as JSON-RPC errors under HTTP 200
(`-32008` for a missing proof, `-32602` for an invalid one), because the SDK has no
authentication-specific error code and a throwing `userBuilder` becomes an HTTP 500. HTTP-level
monitoring alone will not see a rejection.

## 3. The response proof

Tested against `@a2a-js/sdk` 1.3.0 with real HTTP (`evidence/gate-order/response-proof.mjs`,
`slice-both.mjs`).

- The result a client receives from `SendMessage` is assembled by the SDK from the executor's
  events and then trimmed by `historyLength` *after* the executor has run. A proof made inside
  the executor matched the client's hash with the default `historyLength`, and **did not match**
  when the client asked for `historyLength: 1` (the executor signed 4 history entries, the client
  received 1). A proof made by a wrapper over the *final* result matched in both cases.
- Making the proof over the SDK's raw JavaScript result object throws mid-canonicalisation,
  because that object carries explicit `undefined` values on optional fields (for example
  `part.metadata: undefined`) that RFC 8785 JSON canonicalisation cannot handle. Calling the
  SDK's own `Task.toJSON(...)` first, and proving over *that*, works. This was found by running
  the proof end to end, not by reading the types.
- Reusing `@kya-os/mcp`'s session-based `ProofGenerator`/`ProofVerifier` for the response side
  works, with three constraints: the generator signs Ed25519 only (an ES256 agent cannot mint a
  response proof through it, even though the request-proof path supports ES256); the verifier
  takes a public JWK directly with no DID-membership check, so the client must resolve and pin
  the server's key itself; and the public JWK passed to the verifier must carry a `kid`, or
  verification fails with an opaque "Key ID mismatch".
- Streaming is out of scope for the current design: the chosen wrapper only attaches a response
  proof on the non-streaming `SendMessage` branch, so a streamed result cannot carry one by
  construction, not merely by convention.

## 4. Agent Card discovery and signature coverage

Tested against `@a2a-js/sdk` 1.3.0's `generateAgentCardSignature`/`verifyAgentCardSignature`
(`evidence/spikes/spike-card-signature.mjs`).

| Case | Result |
|---|---|
| Card signed by the expected key | Accepted |
| Same card, with an attacker-controlled `jku` header | Accepted — and the `jku` is never fetched, when the resolver callback ignores it and resolves by DID instead |
| An attacker's own key, claiming the server's `kid` | Rejected, once the resolver checks DID-document membership rather than trusting the `kid` string alone |
| Two signatures on one card, only one valid | **Accepted.** The SDK's rule is "any one signature verifies" |
| Extension `params` changed, added to or emptied after signing | **Rejected — `params` are covered by the signature** |
| An unknown top-level field added after signing | **Accepted — not covered** |

A resolver callback that ignores `jku` and pins the DID the caller expects closes the main risk
here (a signer nominating its own trust root); the "any one signature verifies" behaviour and the
uncovered top-level fields are both worth knowing about before trusting anything outside the
extension block.

## 5. ES256 and `cnf` sender-constraint fusion

Tested directly against `@kya-os/mcp` 1.21.2's `buildCardProof`/`verifyCardProof`
(`evidence/gate-order/alg-cnf.mjs`).

- An ES256 (P-256) proof round-trips correctly end to end.
- `alg: ES256` with a resolved key that is actually Ed25519 is rejected (`alg_key_mismatch` and
  `cnf_key_mismatch` both fire).
- `cnf` fusion reaches full assurance only when the verifier is given a `tokenCnfJkt` that matches
  the proof's own `cnf.jkt`; without one, verification still succeeds but at a lower assurance
  level, with a non-fatal warning rather than a silent downgrade.
- The one sharp edge: the verifier independently recomputes the signing key's own thumbprint and
  requires it to equal `cnf.jkt`. An attempt to bind the proof to a *different*, externally issued
  key (for example an OAuth DPoP token's key) is rejected outright. Full assurance therefore
  requires the OAuth client and the DID signer to use the same keypair — it cannot bridge two
  independently issued keys.

## 6. Delegation chain enforcement

Tested directly against `@kya-os/mcp` 1.21.2's `validateDelegationChain`
(`evidence/gate-order/delegation-chain.mjs`) with synthetic two-hop chains and a stubbed
per-credential verifier (the stub covers structural checks only; real VC-proof verification is
exercised separately in §4/§5).

All nine scenarios tried matched the module's own documentation exactly: scope narrowing is
accepted and scope escalation rejected; a chain longer than `maxChainLength` is rejected; a leaf
whose audience excludes the verifying server is rejected; a parent-cycle is rejected; an ancestor
revoked through the injected revocation checker invalidates a leaf whose own status bit is
untouched; a root not signed by an allow-listed issuer is rejected; a credential carrying
`credentialStatus` with no status resolver configured fails closed rather than skipping the
check; and the originating principal is reachable, unchanged, on the resolved ancestor after a
valid chain validates.

## 7. Transports

- **REST:** the same `userBuilder` plus wrapper design works unchanged — a proofed
  `POST /message:send` returns 200 with a response proof, an unproofed one is rejected with
  HTTP 400 (visible at the HTTP layer, unlike JSON-RPC's HTTP 200).
- **gRPC:** has its own `UserBuilder` seam entirely —
  `(call: grpc.ServerUnaryCall | grpc.ServerWritableStream) => Promise<User>`, reading the
  already-deserialised protobuf request off `call.request`, not an HTTP body
  (`evidence/transports/grpc-gate.mjs`, a real `@grpc/grpc-js` server and client). A gate written
  for JSON-RPC does not port to gRPC as-is; each transport binding needs its own adapter. A typed
  SDK error thrown from the gRPC gate reaches the client as a named error class, the same pattern
  as JSON-RPC; a plain `Error` only surfaces as gRPC status `UNKNOWN`.
- **Streaming:** confirmed by reading the chosen wrapper's code, not a separate script — its
  `sendMessageStream` branch enforces the gate identically to `sendMessage`, but never attaches a
  response proof, so the "no response proof over a partial stream" rule holds by the shape of the
  code rather than needing a separate guard.

## 8. `@kya-os/mcp` ships two incompatible "ledger-anchored status list" verifiers

Tested against a real cheqd testnet DID-Linked Resource and `@kya-os/mcp` 1.21.2
(`evidence/status-list/`).

`@kya-os/mcp` has two different functions, in two different modules of the same package, both
described as verifying a status list's integrity before trusting its revocation bits:

- `createStatusListProofVerifier` (generic, `@kya-os/mcp/card`): expects a `DataIntegrityProof` /
  `eddsa-jcs-2022` proof — two separate JCS (RFC 8785) hashes, one over the proof options and one
  over the document, concatenated and signed; `proofValue` is `z` + base58btc multibase.
- `createCheqdStatusListResolver` (cheqd-specific, `@kya-os/mcp/cheqd`): expects a different
  construction entirely, read from its own source — **one** JCS hash over the whole credential
  minus `proof`, signed directly, with `proofValue` as plain base64url and **no** multibase
  prefix — despite the proof being labelled `Ed25519Signature2020`, which is neither this
  construction nor the real W3C `Ed25519Signature2020` specification's RDF/URDNA2015
  canonicalisation. `createCheqdStatusListResolver`'s own shape/signature checks do not inspect
  `proof.type` or `cryptosuite` at all, so a `DataIntegrityProof`/`eddsa-jcs-2022` credential is
  not rejected for the right reason; it simply fails to parse as the base64url the cheqd-specific
  function expects.

A credential signed for the generic verifier therefore throws against the cheqd-specific one, and
vice versa — confirmed in both directions, against real testnet `encodedList` bits with a
synthetic signature matching each construction. Once a cheqd status list is actually signed,
anything building on cheqd `did:cheqd`-anchored status lists should use the generic
`createStatusListProofVerifier` + `createRevocationChecker` pair, not
`createCheqdStatusListResolver`, until this is reconciled upstream. Until then — see §9 — neither
verifier is needed at all.

## 9. A cheqd-specific alternative that needs no signed proof

§8's whole premise is that a status list's proof should be checked before trusting its
revocation bits, per W3C Bitstring Status List v1.0. cheqd's current on-chain resources have no
proof worth checking at all: `BitstringStatusListCredential` is signed before `encodedList` is
attached, so even a correct verifier only confirms the credential shell, not the bits a caller
actually reads.

`packages/core/src/status/ledger-anchored.ts`'s `verifyLedgerAnchoredStatus` takes a different
foundation: the DID-Linked Resource mechanism itself, not the credential's proof, is the trust
anchor. It:

- fetches the resource's metadata and data from one or more resolver URLs the *caller* supplies
  (never a URL taken from the credential);
- checks the resolver's own SHA-256 checksum against the bytes it actually returned;
- requires the resource to belong to the expected issuer's own collection, be the latest version,
  and (optionally) requires `minAgreement` independent resolvers to agree before trusting a
  result — the direct mitigation for the resolver's checksum being self-reported, not
  independently verifiable, which §8's generic/cheqd-specific verifiers don't address either;
- fails closed on everything unreadable, stale, inconsistent, encrypted, oversized, or using
  cheqd's default two-bits-per-entry encoding (whose bit order is not specified precisely enough
  to read safely) — 29 cases, all tested against a fake resolver built to mimic the real one's
  response shapes.

This works against cheqd's status lists **today**, with no dependency on a signing change
landing anywhere. The trade-off is it is cheqd-resolver-shaped specifically, not a general W3C
Bitstring Status List verifier portable to another DID method — unlike the generic KYA-OS
verifier path in §8, which becomes usable once a list is properly signed. **Recommendation:** use
`verifyLedgerAnchoredStatus` for cheqd-anchored status checks now; revisit the generic verifier
path once signed lists exist.

## 10. Not done

- No OAuth/DPoP token flow was exercised for `cnf` fusion (§5 used a synthetic thumbprint).
- CRISP scope matchers in delegation chains were not tested (only flat scopes).
- gRPC *streaming* calls specifically (`sendStreamingMessage`'s server-streaming RPC) were not
  tested; only gRPC unary calls were.
- Real Ed25519 VC-proof verification inside the delegation-chain tests was stubbed to structural
  checks only; it is exercised separately (and for real) in the card-proof tests.
- `did:cheqd` discovery end to end — Entity Card fetch, reciprocal `alsoKnownAs` linkage,
  `TrustConfigManifest`/`CapabilityManifest`/`ConformanceManifest` resolution — was not tested.
- No `BitstringStatusListCredential` signed for cheqd's testnet resolver was found to test
  against; §8's cheqd-specific resolver was exercised with a synthetic credential and key instead
  of a real on-chain one.
- §9's `verifyLedgerAnchoredStatus` is tested against a fake resolver matching the real one's
  response shapes, not a live call — `evidence/status-list/probe.sh` and
  `verify-ledger-anchored.mjs` exercise the real resolver directly but don't yet call into this
  module. It also has no integration with `packages/a2a` yet.
