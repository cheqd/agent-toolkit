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
