# Test harnesses across related repositories — October 2026

> **Research notes, not a specification.** Compiled on 5 October 2026 by reading public repositories. **Nothing here was executed.** Re-verify before relying on any detail.

## 1. Summary

- The [A2A TCK](https://github.com/a2aproject/a2a-tck) is the only conformance harness aimed at A2A itself. Its requirement categories cover the agent card, auth, core operations, streaming, push notifications and transport bindings. None of the files read covers extensions or request proofs.
- The [`kya-os-mcp` conformance suite](https://github.com/decentralized-identity/kya-os-mcp/tree/main/conformance) is the closest existing model for binding vectors: language-neutral JSON vectors, a pluggable adapter and a hash manifest.
- AP2 has no conformance suite or vectors, only SDK unit tests.
- The planned `conformance/` directory in this repository follows the `kya-os-mcp` shape (see its README).

## 2. Harnesses

| Repository | Harness | How it is run | Notes |
|---|---|---|---|
| [`a2aproject/a2a-tck`](https://github.com/a2aproject/a2a-tck) | Python and pytest. Requirements are tagged by RFC 2119 level: MUST fails hard, SHOULD is an expected failure, MAY is skipped when the capability is not declared | `./run_tck.py --sut-host <url>` against a running agent; `--transport` and `--level` filters | `main` is version 1.0.0. Transports (gRPC, JSON-RPC, HTTP+JSON) come from the agent card's `supportedInterfaces`. Reports: JSON, HTML, pytest-html and JUnit XML. A code generator produces system-under-test projects from Gherkin scenarios for a2a-java, a2a-python and a2a-jakarta, but not for JavaScript. Tags: `0.3.0.beta5`, `1.0.0.alpha1`, `1.0.0.alpha2` |
| [`a2aproject/a2a-js`](https://github.com/a2aproject/a2a-js) | vitest, with separate configs for unit, `test:integration`, `test:edge` and `test:db`; `test:package` smoke test; esbuild bundle checks for workers, gRPC, Express and database | `npm test`, `npm run lint:ci` | Relevant specs: `test/signature.spec.ts` (Agent Card signing with `jose`, ES256), `test/extensions.spec.ts`, `test/server/express/extensions_echo.spec.ts`. Has a `tck/compat-agent` system under test, started with `npm run tck:compat-sut-agent` from `tck/` |
| [`decentralized-identity/kya-os-mcp`](https://github.com/decentralized-identity/kya-os-mcp) | 48 JSON vectors across 9 files (audit integrity, card proof, delegation chain, `did:key` and `did:web` resolution, entity card, negotiation, signed proof, status list). A runner that feeds vectors to a `ConformanceAdapter` and never imports the package. A standalone, stdlib-only `verify.py`. `SUITE-MANIFEST.json` with a vector-set hash | `npm run conformance`, `conformance:verify:crosslang`, `test:e2e:cheqd:testnet` | A negative vector passes the suite only when the implementation rejects it. The manifest pins `@kya-os/mcp` **1.14.2**, whereas npm is on 1.16.2. The cheqd testnet test is a live test |
| [`google-agentic-commerce/AP2`](https://github.com/google-agentic-commerce/AP2) | pytest under `code/sdk/python/ap2/tests/`; one Go test; Android sample tests | `uv run python -m pytest code/sdk/python/ap2/tests/` | No conformance suite or vectors. The tests README is a virtual-environment repair recipe |
| [`a2aproject/experimental-ext-oid4vp-auth`](https://github.com/a2aproject/experimental-ext-oid4vp-auth) | None | Manual sample CLI | Precedent for repository layout only |
| [`cheqd/did-resolver`](https://github.com/cheqd/did-resolver) | Go: about 74 integration and 40 unit test files | `test.yml` workflow | Possible source of DID resolution fixtures |
| [`cheqd/studio`](https://github.com/cheqd/studio) | Jest unit tests and Playwright end-to-end tests | `npm run test:unit`, `npm run test:e2e` | Little relevance |

## 3. Findings

1. **No harness covers A2A extensions.** Binding vectors for the request-proof envelope and DID-backed key resolution would be authored here, either as standalone vectors or as a TCK contribution.
2. **The JS SDK's own CI does not use the current TCK.** Its `run-tck-compat.yaml` pins TCK `0.3.0.beta5`, uses `--sut-url` with `--category mandatory` and `--category capabilities`, and patches out one test with `sed`. TCK `main` (1.0.0) uses `--sut-host` and `--level`. The two CLIs differ.
3. **The compat agent speaks v0.3.** It is built on the v1.0 SDK with a v0.3 compatibility layer, and its README says the TCK drives it unchanged in v0.3 shape. Whether it passes the 1.0.0 TCK is unknown.
4. **The kya-os suite is pinned behind npm.** Check the vector-set hash against the version we pin before reusing it.
5. **The TCK needs a live agent.** Our sample agent would have to be the system under test, and the TCK's agent-card-driven discovery would need to see our extension.

## 4. Not done

- The TCK was **not run** against the a2a-js compat agent. Running it requires installing and executing third-party code.
- The TCK requirement list was only partly read (the agent-card file).
- The test changes between `@a2a-js/sdk` 1.2.0 and 1.3.0 were not reviewed.
