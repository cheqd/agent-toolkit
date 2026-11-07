# cheqd agent toolkit

> ## ⚠️ DRAFT — scaffolding only
>
> **Nothing is implemented.** This repository currently contains build configuration and empty package boundaries. There is no functionality and the public API is not designed.
>
> **Do not depend on this.** No package here is published, and all are marked private to prevent accidental release. Nothing has been security reviewed.
>
> This is an early exploration, not a cheqd product.

DID-anchored identity, delegation and per-request proof for agentic protocols.

## Packages

| Package | Responsibility | Status |
|---|---|---|
| [`@cheqd/agent-identity`](./packages/core) | DID resolution, reciprocal `did:web` ↔ `did:cheqd` linkage, DID-Linked Resource policy, credential status, key resolution | Not started |
| [`@cheqd/agent-identity-a2a`](./packages/a2a) | A2A binding: client interceptor, server executor gate, canonical request shape | Not started |
| [`@cheqd/agent-identity-ap2`](./packages/ap2) | AP2 binding: `cnf` key continuity, authorised-secondary-key tier, open/closed mandate chain verification | Single-hop case built, draft |
| [`conformance/`](./conformance) | Shared vectors | Not started |

The two bindings both depend on the core and not on each other, so an AP2 consumer never installs the A2A SDK.

## Python port

[`python/packages/`](./python/packages) ports the TypeScript packages above, package boundary for package boundary, using Poetry/Ruff/pytest (matching `cheqd/acapy-plugins`' convention, not invented here). It is **partial**, not parity:

| Package | Status |
|---|---|
| [`cheqd-agent-identity`](./python/packages/core) | Fully ported, except the two modules that adapt to `@kya-os/mcp`'s provider seams (no Python equivalent exists) — see `docs/design-decisions.md` D10. |
| [`cheqd-agent-identity-ap2`](./python/packages/ap2) | Fully ported, using PyPI's `sd-jwt` for the SD-JWT-VC/KB-JWT crypto layer in place of `@sd-jwt/core` — see D11. |
| [`cheqd-agent-identity-a2a`](./python/packages/a2a) | **Partial.** Only the canonical request shape and the trust extension are ported — the actual holder-of-key proof verification gate is built entirely on `@kya-os/mcp`, which has no Python equivalent — see D12. |

## What this builds on

No new cryptography is proposed. The proof profile, its canonicalisation and its conformance vectors already exist upstream and would be reused unchanged:

- **[`@kya-os/mcp`](https://github.com/decentralized-identity/kya-os-mcp)** — the [DIF TAAWG](https://identity.foundation/working-groups/trusted-agents.html) reference implementation of the `org.kya-os/proof.v1` holder-of-key profile: RFC 8785 (JCS) canonicalisation, SHA-256 request binding, detached JWS alongside an RFC 9421 HTTP Message Signature, RFC 7638 `cnf` thumbprint fusion, and a published conformance vector suite with an independent Python verifier.
- **[`@a2a-js/sdk`](https://github.com/a2aproject/a2a-js)** — `CallInterceptor` on the client, the `AgentExecutor` decorator on the server, `A2A-Extensions` header negotiation, and a pluggable key-resolution seam on `verifyAgentCardSignature`.

Neither would be forked. Both would be pinned.

## Related

- [`cheqd/agent-identity-a2a`](https://github.com/cheqd/agent-identity-a2a) — the A2A extension specification and reference sample, kept separate so it stays contributable to the A2A project without carrying AP2 work or build tooling.

## Development

```bash
npm install
npm run build
npm run lint      # ESLint, also run in CI via Super Linter
npm run format    # Prettier --check; `format:write` to fix - not CI-gated yet, see .prettierrc.json
```

## Contributing

This project uses a [Developer Certificate of Origin](./DCO). Sign off your commits with `git commit -s` — see [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[Apache 2.0](./LICENSE)
