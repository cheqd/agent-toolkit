# Operator runbook

> **DRAFT — early exploration, not reviewed or stable.** Covers `packages/core`, `packages/a2a`
> and `packages/ap2` as implemented so far (stacked PRs #16-#21). Written for whoever operates a
> server agent built on these packages, not for this repository's own contributors.

## Before you deploy

1. **Pin exactly, don't range-pin, `@a2a-js/sdk` and `@kya-os/mcp`.** See
   `docs/security/dependency-review.md`. A minor release of either changes gate or proof
   behaviour under you silently.
2. **Decide your key storage now, not after an incident.** Every signer seam
   (`ProofSigner` client-side, `ProofGenerator`'s `CryptoKey` server-side) accepts a
   non-extractable or KMS/HSM-backed key - nothing forces an in-process extractable key. If you
   need this proven against your specific KMS before relying on it, see
   `cheqd/agent-toolkit#19` (open, not yet done by this programme).
3. **Decide where your persistent replay cache and mandate-consumption store live.**
   `FileNonceCacheProvider` and `mandate-consumption-store.ts` are both file-backed and correct
   for one process on one filesystem. A multi-instance deployment needs a shared backing store
   (a database, not these two modules as shipped) - see each module's own doc comment for the
   exact boundary of what they do and don't guarantee across processes.
4. **Run the conformance suite and the fuzzer against your own build**, not just this
   repository's CI: `node conformance/run-a2a-gate-vectors.mjs` and
   `node conformance/fuzz-proof-parsing.mjs`. They exercise the packages as shipped; they do not
   know about any wrapping, middleware, or configuration you add on top.
5. **Read `docs/security/threat-model.md`'s "Known gaps" section before you decide what's out of
   scope for your own deployment** - several things (KMS proof, real on-chain status lists,
   junk-proof load protection, task-addressed-method identity) are not yet done anywhere in this
   programme, not just undocumented.

## Rotating the server's signing key

1. Generate the new keypair and publish it under the agent's DID document (or, for an
   authorised secondary payment key under WS5, issue a new Agent Payment Key Credential naming
   it - see `payment-key-authorization.ts`).
2. Before switching `withAgentIdentity`'s `privateKey`/`publicKey` to the new key, confirm the
   new key resolves correctly: run `createRetrievePublicKey` (or your deployment's resolver)
   against the updated DID document and confirm it returns the new JWK.
3. Switch the live key. There is no overlap window built into this programme - a request signed
   by the client against the OLD server key, arriving after the switch, verifies against
   whatever the resolver NOW returns, so a response-proof mismatch during the cutover window is
   expected if your resolver's cache (e.g. `createManifestCache`, or your own DID-document cache)
   has not also refreshed. Size your resolver cache TTLs with this in mind.
4. Do not reuse a nonce-cache directory across a key rotation if the old key's identity is being
   retired entirely - a stale consumed-nonce record naming an identity nobody can sign as
   anymore is harmless clutter, not a security issue, but clean it up if you want to reclaim the
   disk.

## Responding to a suspected key compromise

1. **Revoke first, rotate second.** If the compromised key is an authorised secondary payment
   key (WS5), revoke its Agent Payment Key Credential via your status-list issuer immediately -
   `verifyAgentPaymentKeyCredential` fails closed on `revoked: true` on the NEXT verification, so
   this is the fastest stop. If it's the agent's primary key, revocation isn't available the same
   way (the primary key signs the DID document itself); updating the DID document to remove the
   verification method is the equivalent action, and takes effect only once resolvers' caches
   expire - see the cutover-window note above.
2. **Check `mandate-consumption-store.ts` for the compromised identity's recent activity**
   (`getContext(mandateId)`) to scope the blast radius for budget/recurrence-constrained AP2
   mandates - this tells you how much was spent under the compromised key before revocation took
   effect, not just whether it was used at all.
3. **Do not assume a `cnf`-fused proof proves authorisation to transact**, per threat T8 in the
   threat model - `cnf` fusion proves key continuity, not that the party holding the key actually
   intended a specific transaction. If the compromise scenario involves the key itself being used
   correctly by an attacker (not a forged signature), fusion checks will not help you detect it;
   you need an out-of-band signal (unexpected transaction pattern, user report).
4. File the incident against whichever vector in `conformance/vectors/a2a-gate.json` is closest
   to what actually happened, and consider whether it needs a NEW vector - negative vectors in
   this programme are meant to be grown from real incidents, not just the spec's minimum list.

## Interpreting a rejection

Every gate rejection carries a reason string (`proof_required: <reason>`,
`proof_invalid: <reason>`, `trust_extension_failed: <reasons>`). These are intentionally terse
and machine-stable (see `wrapper.ts`/`user-builder.ts`'s own doc comments) - do not try to show
them to an end user directly; map them to your own user-facing message. A few that commonly
indicate a MISCONFIGURATION on your own side, not an attack:

- `no_verifier_installed` - the gate is wired up without a `userBuilder`, or in a transport
  binding that doesn't support one. Fails closed, but almost certainly means the deployment is
  broken, not under attack.
- `status_check_unavailable` / `manifest_resource_unavailable` - a trust-extension dependency
  (a resolver, a status-list endpoint) is unreachable from the server. Check your own network
  egress and the resolver's health before assuming the caller is the problem.
- `did_cheqd_resolution_not_configured` - `did:cheqd` support wasn't opted into
  (`createRetrievePublicKey`'s `resolveDidCheqd` option) even though a caller is presenting a
  `did:cheqd` identity. Decide whether to opt in or reject that caller class deliberately.

## Where to look when something doesn't verify that you expected to

1. Re-run the exact request through `conformance/run-a2a-gate-vectors.mjs`'s pattern (sign over
   the real wire body, never the SDK's typed object - see `v1/spec.md` §4.6.1 for why those two
   differ) to confirm whether your own client is producing a wire-faithful covered form.
2. Check whether the transport is one this programme has verified end to end
   (`packages/a2a/smoke-test*.mjs`) - a NEW transport binding needs the same covered-form
   verification the gRPC fix in #18 needed; do not assume it is a drop-in port of the Express
   gate.
3. Check TTLs: a proof's own skew/expiry, the trust-extension cache's TTL, and the manifest
   cache's TTL are all independent clocks. "It worked five minutes ago" is consistent with any
   one of them having just expired.

## License

[Apache 2.0](../../LICENSE)
