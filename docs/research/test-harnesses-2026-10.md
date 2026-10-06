# Test harnesses across related repositories — October 2026

> **Research notes, not a specification.** Compiled on 5 and 6 October 2026 by reading public repositories. Section 4 records one run of the TCK; nothing else here was executed. Re-verify before relying on any detail.

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
5. **The TCK needs a live agent, and its extension coverage is thin.** Our sample agent would have to be the system under test. The only extension-related tests found check that the `A2A-Extensions` header is accepted on JSON-RPC and HTTP+JSON without error, using made-up `example.com` URIs. They do not test activation, `AgentCard.capabilities.extensions` or extension behaviour. The `CARD-EXT-001` and `CARD-EXT-002` requirements are about the *extended agent card*, not extensions.

## 4. TCK run

Run on 6 October 2026: TCK `main` at `263b9cf` (1.0.0, 1 Sep 2026) against the `a2a-js` `tck/compat-agent` at `af1b5a8` (5 Oct 2026), both cloned fresh and run on a laptop. Command: `./run_tck.py --sut-host http://localhost:41241`. Wall time 6 minutes 20 seconds.

**Result: 127 passed, 43 failed, 93 skipped, 2 expected failures.** The TCK report's own summary gives 43.0% overall and 45.5% for MUST requirements.

| Transport | Total | Passed | Failed | Skipped |
|---|---|---|---|---|
| Agent card | 10 | 9 | 1 | 0 |
| JSON-RPC | 92 | 71 | 6 | 15 |
| HTTP+JSON | 86 | 62 | 10 | 14 |
| gRPC | 39 | 3 | 23 | 13 |

How to read this:

- **gRPC (25 of 43 failures) is a connection problem.** The agent card advertises gRPC as `http://localhost:41242`, and the TCK's gRPC client fails with `Misformatted domain name`. These failures say nothing about gRPC behaviour. They show how the TCK treats an `http://` gRPC URL, and they are not investigated further.
- **Artifact tests (10) fail because the sample agent returns no artifacts** ("Response contains no artifacts"). This is a limit of the sample agent, which is built for the v0.3 suite.
- **Subscribe-to-terminal-state (2) and some content-type checks (about 4) fail.** For example, the HTTP+JSON error `Content-Type` is `application/a2a+json`, and the TCK expects `application/json`.
- **I did not triage the failures further**, and I do not know which are SUT limitations and which are TCK defects. The SDK's own CI runs the older `0.3.0.beta5` suite, so these results are not comparable with it.

What it shows for our work: the TCK is easy to run against a JavaScript agent and its reports are usable, but a pass rate this low on a reference agent means the TCK cannot yet serve as our gate on its own.

## 5. Not done

- The TCK requirement list was only partly read (the agent-card file and an extension search).
- The test changes between `@a2a-js/sdk` 1.2.0 and 1.3.0 were not reviewed.
- The failures were not triaged individually, and no run was made against the `0.3.0.beta5` suite.
