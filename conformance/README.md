# Conformance

Shared vectors for the identity core and the protocol bindings.

## `vectors/a2a-gate.json`

The minimum negative-vector set `v1/spec.md` §8 requires an implementation to reject
(wrong audience, expired proof, replayed nonce, altered message part/`contextId`/`taskId`, key
substitution, `alg`/key mismatch, downgraded `cnf`, revoked credential, stale policy), plus
`VEC-A2A-RESP-1` (the response proof binds to the result as received) and `VEC-A2A-GATE-1` (a
rejected call leaves the task store byte-identical, for both a new task and a follow-up to an
existing one).

Vectors are authored as language-neutral JSON (id + description); each language runner
implements every id exactly once. **`run-a2a-gate-vectors.mjs`** is the Node/TypeScript runner:
it exercises the real `@cheqd/agent-identity-a2a` gate over real HTTP with real Ed25519 proofs —
tampering happens on the wire, after signing, the way an attacker would actually have to do it,
not by calling internal functions directly. Run after `npm run build`:

```sh
node conformance/run-a2a-gate-vectors.mjs
```

Exits non-zero if any vector fails or if the runner is missing a vector declared in the JSON -
negative vectors are normative (spec §8): an implementation that accepts one does not conform,
regardless of its positive-path behaviour.

Proof-layer vectors (the `org.kya-os/proof.v1` profile itself) would be reused unchanged from
`@kya-os/mcp`, fetched from GitHub at a pinned ref — the npm tarball does not ship
`conformance/`. Not yet pulled in here.

## `fuzz-proof-parsing.mjs`

Focused fuzzing over every untrusted-input entry point this programme owns: the JSON-RPC/REST
and gRPC `userBuilder`s, `coveredRequest`, the generic `eddsa-jcs-2022` verifier, the proof-
checked status checker, `CheckoutMandateChain.verify`, and the AP2 presentation/transaction-
data-binding functions. Generates structurally-malformed, type-confused and prototype-pollution-
shaped input (bounded to the realistic wire-level space: JSON-safe values, since every target
receives its input after `express.json()`, a protobuf-to-JSON mapping, or `JSON.parse` - a
`Symbol` or a function can never actually arrive this way) and asserts the one property that
matters for all of them: fail closed, never throw past the function's own documented boundary,
never hang. A deterministic seed makes any failure reproducible:

```sh
node conformance/fuzz-proof-parsing.mjs
# or, to replay a specific run:
FUZZ_SEED=20261105 FUZZ_ITERATIONS=800 node conformance/fuzz-proof-parsing.mjs
```

**Found two real issues on its first run** (5 November 2026), both fixed:

- `createVerifyingUserBuilder`/`createVerifyingGrpcUserBuilder` threw instead of rejecting when
  the whole `req`/`call` argument was itself `null`/`undefined`, rather than just a malformed
  body - exactly the "a throwing userBuilder surfaces as an opaque HTTP 500" failure mode these
  functions' own doc comments say to avoid. Fixed in `user-builder.ts`/`grpc-user-builder.ts`.
- `verifyTransactionDataBinding` threw instead of returning `false` when the closed-mandate
  content couldn't be hashed at all. Fixed in `sd-jwt-presentation.ts`.

Clean across 5 seeds × 800 iterations (32,000+ calls) after the fixes.
