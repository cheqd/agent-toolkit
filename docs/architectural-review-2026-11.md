# Architectural review — November 2026

> **Status report, not a specification.** Written for an external architect reviewing this
> programme ahead of its next release. It complements, not replaces,
> [`design-decisions.md`](design-decisions.md) (the per-decision D1–D20 log, Context/Decision/
> Why/Consequences/Revisit-if, written as the code was built) and the research notes under
> `docs/research/`. This document is the layer above those: what the system is, what research and
> decisions got it here, and — new since `design-decisions.md` was last written — what two rounds
> of internal security review found across both repositories in this programme, and what is still
> open.
>
> Scope: `cheqd/agent-toolkit` (this repository — Core, A2A, AP2, TypeScript and Python). The
> companion security review of `cheqd/credo-ts`'s `packages/cheqd` lives in that repository —
> [`packages/cheqd/docs/architectural-review-2026-11.md`](https://github.com/cheqd/credo-ts/blob/cheqd/packages/cheqd/docs/architectural-review-2026-11.md)
> — and is referenced, not repeated, below. KYA-OS is a third-party dependency (`@kya-os/mcp`)
> this programme builds on and tracks for breaking changes (see
> [D13](design-decisions.md#d13-a-from-spec-python-orgkya-osproofv1-engine-read-directly-from-kya-osmcps-source)–[D17](design-decisions.md#d17-response-proof-nonce-cache-ttl-was-floored-too-low---third-bug-found-by-an-independent-gap-audit));
> it is not a repository this programme owns or reviews, so it isn't covered as a review subject
> below.

## 1. What this programme is

Three packages, each in TypeScript and Python, give an autonomous agent **trust binding**: proof
that a request or a payment really came from the agent identity it claims, bound to a
cheqd-anchored DID.

- **Core** (`packages/core`, `python/packages/core`) — Agent Card signature verification against
  DID-resolved keys (never the signer-supplied `jku`), status/revocation checking, DID-Linked
  Resource manifest resolution, a persistent single-call replay cache.
- **A2A** (`packages/a2a`, `python/packages/a2a`) — binds Core's primitives into Google's A2A
  protocol: a request-proof gate (`userBuilder`/`gate.py`), a response-proof wrapper, and
  `trust-extension.ts`'s reciprocal-linkage + manifest + status composition.
- **AP2** (`packages/ap2`, `python/packages/ap2`) — binds Core's primitives into Google's Agent
  Payments Protocol: SD-JWT-VC mandate presentation and verification, the full 10-constraint
  mandate chain (`PaymentMandateChain`, `CheckoutMandateChain`), the authorised-secondary-key
  trust tier, and a dedicated mandate-consumption store.

`cheqd/credo-ts`'s `packages/cheqd` is a separate codebase (cheqd's plugin for the Credo
agent framework) that overlaps this programme's subject matter — DID resolution, revocation
status lists, agent-card signing — but is architecturally independent; it was brought into this
review because the same reviewers and the same review method (described in §3) were pointed at
it.

Everything in both repositories is pre-release. Nothing here has shipped to a production
consumer yet.

## 2. Design decisions and research — summary

The full design-decision log is [`design-decisions.md`](design-decisions.md) (D1–D20); the
research that preceded and ran alongside it is under `docs/research/`. Read those directly for
detail — this section is an index, not a restatement.

**Research** (`docs/research/`):

- [`landscape-2026-10.md`](research/landscape-2026-10.md) — upstream baseline versions (A2A,
  `@a2a-js/sdk`, `@kya-os/mcp`, AP2) as of October 2026.
- [`protocol-stack-2026-10.md`](research/protocol-stack-2026-10.md) — a five-layer capability map
  of the agentic-protocol landscape (discovery/transport, identity/delegation, payment authority,
  payment wire, trust anchor), placing this programme's choices in context.
- [`pap-2026-10.md`](research/pap-2026-10.md) — a read of the (then-draft) Personal Agent
  Protocol, a business-facing protocol this programme doesn't implement but tracks.
- [`test-harnesses-2026-10.md`](research/test-harnesses-2026-10.md) — a survey of conformance
  harnesses in related repositories, which shaped this repository's own `conformance/` layout.
- [`a2a-trust-binding-findings-2026-11.md`](research/a2a-trust-binding-findings-2026-11.md) — the
  evidence base (real client/server round trips against `@a2a-js/sdk` and `@kya-os/mcp`) that
  [D1](design-decisions.md#d1-where-request-verification-runs-on-the-a2a-server) and
  [D2](design-decisions.md#d2-agent-card-key-resolution-trusts-kid-never-jku) are built on.

**Design decisions** (`design-decisions.md`), grouped by theme:

| Theme | Decisions |
|---|---|
| Where/how A2A verification hooks into the SDK | D1 (userBuilder, not an executor decorator), D2 (`kid`-only key resolution, never `jku`) |
| Status, revocation, replay | D3 (fail-closed against a fixture pending an on-chain list), D4 (persistent short-TTL replay cache, scoped to one call) |
| AP2's own trust model | D5 (shared key-fusion primitive), D6 (authorised-secondary-key credential tier), D7 (single-hop mandate presentation, multi-hop explicitly out of scope), D8 (separate mandate-consumption store), D9 (full 10-constraint chain built now, not a minimal `cnf`-only slice) |
| The Python port | D10 (status-list modules ported once a concrete need existed), D11 (two real defects found and patched around in the `sd-jwt` reference library, both reported upstream), D12–D15 (the A2A proof gate: initially partial, then a from-spec `org.kya-os/proof.v1` + response-proof engine built by reading `@kya-os/mcp`'s TypeScript source directly, then wired into the real `a2a-sdk` via `proto_bridge.py`) |
| Cross-language conformance | D16 (first real TS↔Python mint/verify run on both proof engines — two bugs found and fixed), D17 (a nonce-cache TTL bug found only by a line-by-line audit, not by running the conformance pair), D18 (wiring-layer conformance at the real SDK/proto boundary — zero new bugs, now a permanent CI job), D19 (AP2 cross-language conformance — one real bug found: non-canonical JSON hashing diverged between languages) |
| Test depth | D20 (trust-extension's three checks proven together with real building blocks, not only individually mocked) |

The throughline worth calling out to an architect: **every cross-language or cross-library
boundary in this programme has, so far, hidden at least one real bug** that same-language,
same-codebase testing could not have found (D11, D16, D17, D19). That is why the conformance
scripts for the wiring layer (D18) were kept as permanent CI jobs rather than one-off scripts —
this programme now treats "the two sides still agree" as a thing that regresses, not a thing
proven once.

## 3. Review history

Beyond the design/build work in `design-decisions.md`, this programme has gone through four
distinct review passes. The first two are already documented in `design-decisions.md`/
`docs/security/`; the second two are new since that document was last written and are summarised
here because nothing else currently records them.

### 3.1 WS6 — original negative-vector suite and threat model (documented elsewhere)

The original security work alongside the first PR stack (`#16`→`#21`):
[`docs/security/threat-model.md`](security/threat-model.md) (trust boundaries, attacker model,
known gaps), a negative-vector conformance suite (`conformance/vectors/a2a-gate.json`,
`conformance/run-a2a-gate-vectors.mjs`), a fuzzing pass over mandate-chain parsing
(`conformance/fuzz-proof-parsing.mjs`), and [`docs/security/dependency-review.md`](security/dependency-review.md).
Not re-summarised here — read those documents directly.

### 3.2 First internal Opus-effort review pass — `agent-toolkit`

A security-focused review pass across Core, A2A and AP2 (TS and Python), the specs, and the
cross-language conformance work. Findings were fixed directly (not held as a backlog) across
PRs `#32`–`#43`, each a self-contained fix with its own regression test:

| PR | Finding |
|---|---|
| [#32](https://github.com/cheqd/agent-toolkit/pull/32) | REST route confusion; missing `assertionMethod` check |
| [#33](https://github.com/cheqd/agent-toolkit/pull/33) | AP2 constraint type-confusion bypass; unknown constraint type fail-open |
| [#34](https://github.com/cheqd/agent-toolkit/pull/34) | Check-then-record race in the mandate consumption store |
| [#35](https://github.com/cheqd/agent-toolkit/pull/35) | Nonce-cache reclaim race (TS and Python) |
| [#36](https://github.com/cheqd/agent-toolkit/pull/36) | Unbounded trust-extension verdict cache |
| [#38](https://github.com/cheqd/agent-toolkit/pull/38) | Legacy proof key wrongly excluded from the covered/signed request |
| [#39](https://github.com/cheqd/agent-toolkit/pull/39) | A2A client didn't fail closed on response-proof failure; covered request not scoped per call |
| [#40](https://github.com/cheqd/agent-toolkit/pull/40) | Python status-list checker not bound to the credential's issuer; `statusSize` unenforced |
| [#42](https://github.com/cheqd/agent-toolkit/pull/42) | `did:web` SSRF via decoded URL-structuring characters; unbounded fetch (TS+Python) |
| [#43](https://github.com/cheqd/agent-toolkit/pull/43) | `ledger-anchored` `validUntil` NaN fail-open; `resolveManifest` collection binding missing |

### 3.3 Second internal Opus-effort review pass — `agent-toolkit` (Core, A2A, AP2, specs)

A second, deeper pass over the same scope. 18 findings, each fixed with
its own regression test and merged individually (`#45`–`#62`); two merge-time complications are
worth recording for an architect reading the PR list cold:

- **#51 superseded #32.** #32's REST route-confusion fix turned out to be incomplete; #51 closed
  the remaining bypass window the same finding had left open.
- **#46 and #61 both touched the SD-JWT presentation test files** (vct-literal check vs. KB-JWT
  max-age), and **#57 and #60 both touched the A2A Python client** (fail-closed-on-failure vs.
  the streaming gate). Both pairs were rebased and reconciled by hand rather than merged in a way
  that would have silently dropped either fix.

| PR | Finding |
|---|---|
| [#45](https://github.com/cheqd/agent-toolkit/pull/45) | `resolveManifest` collection binding not ported to Python; manifest caches unbounded |
| [#46](https://github.com/cheqd/agent-toolkit/pull/46) | AP2 presentation verifiers didn't check the mandate's `vct` claim |
| [#47](https://github.com/cheqd/agent-toolkit/pull/47) | `CheckoutMandateChain.verify()` didn't bind `checkout_hash` to `checkout_jwt` — also reported upstream, see §3.5 |
| [#48](https://github.com/cheqd/agent-toolkit/pull/48) | `execution_date` type confusion; preset-amount bool/int confusion |
| [#49](https://github.com/cheqd/agent-toolkit/pull/49) | Python status-list gzip-bomb; list id not bound to its URL |
| [#50](https://github.com/cheqd/agent-toolkit/pull/50) | AP2 payment-key authorisation derived from the wrong value; NaN dates not fail-closed |
| [#51](https://github.com/cheqd/agent-toolkit/pull/51) | A2A REST route-confusion bypass, left open by #32 |
| [#52](https://github.com/cheqd/agent-toolkit/pull/52) | `retrievePublicKey` DoS; `did:web` SSRF hardening |
| [#53](https://github.com/cheqd/agent-toolkit/pull/53) | Trust-extension resolution not bound to the requested DID; unbounded Python cache |
| [#54](https://github.com/cheqd/agent-toolkit/pull/54) | `eddsa-jcs-2022` didn't enforce `document.id === did`; `proof.expires`/`created` unvalidated |
| [#55](https://github.com/cheqd/agent-toolkit/pull/55) | Max-flow line-item wildcard and quantity bypasses |
| [#56](https://github.com/cheqd/agent-toolkit/pull/56) | Consumption-store amounts unvalidated; corrupt totals not fail-closed; lock maps unbounded |
| [#57](https://github.com/cheqd/agent-toolkit/pull/57) | Python A2A client fail-open on response-proof failure; shared covered-request state across calls |
| [#58](https://github.com/cheqd/agent-toolkit/pull/58) | Nonce-cache per-key maps unbounded; `cleanup()` not serialised against `consume()` |
| [#59](https://github.com/cheqd/agent-toolkit/pull/59) | `did:cheqd` resolvers accepted non-canonical DID strings (dot-segment/path-traversal confusion) |
| [#60](https://github.com/cheqd/agent-toolkit/pull/60) | Python A2A streaming ungated; non-`Task` responses not proven on either side |
| [#61](https://github.com/cheqd/agent-toolkit/pull/61) | KB-JWT max-age/skew unenforced; missing `iat` not fail-closed |
| [#62](https://github.com/cheqd/agent-toolkit/pull/62) | A2A proof-parity and defense-in-depth gaps (grouped finding, 7a–7e) |

All 18 are merged to `main`. Both GitHub Actions CI (including cross-language conformance,
D18/D19) and CodeQL have run clean on `main` after the merge.

### 3.4 Security review pass — `cheqd/credo-ts`'s `packages/cheqd`

The same review method, applied to cheqd's Credo plugin, run alongside §3.3. Findings, fixes and
current status are recorded in that repository, next to the code they describe, rather than
here: [`packages/cheqd/docs/architectural-review-2026-11.md`](https://github.com/cheqd/credo-ts/blob/cheqd/packages/cheqd/docs/architectural-review-2026-11.md)
(working branch `cheqd`, not `main`, which is a stale, unmaintained mirror of upstream Credo).
In short: four PRs (`#50`–`#53`), each green on CI, covering agent-card DID verification,
DID-util/registrar correctness, AnonCreds revocation-status binding, and the legacy
StatusList2021/Bitstring implementation — all blocked on a human reviewer who isn't the PR
author, not on remaining code work.

### 3.5 Upstream disclosure

One finding from §3.3 (#47, `CheckoutMandateChain.verify()`'s missing `checkout_hash` binding) is
also a defect in Google's own `google-agentic-commerce/AP2` reference implementation, not just in
this programme's port of it. Reported via Google's Bug Hunters programme, which judged it
out of scope for its VRP; raised instead as a public issue and fix against the upstream repository:
[google-agentic-commerce/AP2#399](https://github.com/google-agentic-commerce/AP2/issues/399) /
[#400](https://github.com/google-agentic-commerce/AP2/pull/400).

## 4. Current state by area

| Area | State |
|---|---|
| `agent-toolkit` / Core, A2A, AP2 (TS+Python) | All 18 second-pass fixes merged to `main`; CI (incl. cross-language conformance) and CodeQL both green. As far along as this programme can take it without an external architectural review — see §5. |
| `credo-ts` / `packages/cheqd` | 4 fix PRs (#50–53) code-complete and green on CI, blocked only on a human reviewer who isn't the PR author — see that repository's own [review doc](https://github.com/cheqd/credo-ts/blob/cheqd/packages/cheqd/docs/architectural-review-2026-11.md). |
| KYA-OS (`@kya-os/mcp`) | Third-party dependency, not reviewed as part of this programme (see the scope note at the top of this document). Tracked for breaking changes against this programme's two proof engines — see D13–D17's "Revisit-if" clauses. |

## 5. What's open

- **The external architectural review this document exists to support.** Per the existing
  governance note on this programme: no further releases are cut on `agent-toolkit`/
  `agent-identity-a2a` until an external architect has reviewed it. `design-decisions.md` and
  this document together are the intended input to that review.
- **The four `credo-ts` PRs need a reviewer who isn't their author** (§3.4) — the only remaining
  action item that isn't itself a review.
- **Known, already-documented gaps that remain gaps, not regressions:** KMS/HSM signing unproven
  end-to-end, a real on-chain signed status list pending `did-provider-cheqd#657`/`#658`,
  AP2 multi-hop delegation explicitly out of scope (D7), streaming/push A2A out of scope. See
  `docs/security/threat-model.md`'s "Known gaps" for the full list — none of the four review
  passes in §3 found a reason to revise it.

## License

[Apache 2.0](../LICENSE)
