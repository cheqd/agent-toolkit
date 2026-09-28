# cheqd agent trust

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
| [`@cheqd/agent-trust`](./packages/trust-core) | DID resolution, reciprocal `did:web` ↔ `did:cheqd` linkage, DID-Linked Resource policy, credential status, key resolution | Not started |
| [`@cheqd/a2a-trust`](./packages/a2a) | A2A binding: client interceptor, server executor gate, canonical request shape | Not started |
| [`@cheqd/ap2-trust`](./packages/ap2) | AP2 binding: `cnf` key continuity, mandate verification | Not started |
| [`conformance/`](./conformance) | Shared vectors | Not started |

`a2a` and `ap2` both depend on `trust-core` and not on each other, so an AP2 consumer never installs the A2A SDK.

## What this builds on

No new cryptography is proposed. The proof profile, its canonicalisation and its conformance vectors already exist upstream and would be reused unchanged:

- **[`@kya-os/mcp`](https://github.com/decentralized-identity/kya-os-mcp)** — the [DIF TAAWG](https://identity.foundation/working-groups/trusted-agents.html) reference implementation of the `org.kya-os/proof.v1` holder-of-key profile: RFC 8785 (JCS) canonicalisation, SHA-256 request binding, detached JWS alongside an RFC 9421 HTTP Message Signature, RFC 7638 `cnf` thumbprint fusion, and a published conformance vector suite with an independent Python verifier.
- **[`@a2a-js/sdk`](https://github.com/a2aproject/a2a-js)** — `CallInterceptor` on the client, the `AgentExecutor` decorator on the server, `A2A-Extensions` header negotiation, and a pluggable key-resolution seam on `verifyAgentCardSignature`.

Neither would be forked. Both would be pinned.

## Related

- [`cheqd/a2a-ext-cheqd-trust`](https://github.com/cheqd/a2a-ext-cheqd-trust) — the A2A extension specification and reference sample, kept separate so it stays contributable to the A2A project without carrying AP2 work or build tooling.

## Development

```bash
npm install
npm run build
```

## Contributing

This project uses a [Developer Certificate of Origin](./DCO). Sign off your commits with `git commit -s` — see [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[Apache 2.0](./LICENSE)
