# Landscape and prior art — October 2026

> **Research notes, not a specification.** Compiled on 5 October 2026 from public sources. Claims marked *unverified* come from abstracts or automated page summaries and have not been checked against the full text. Re-verify before citing.

## 1. Upstream baseline

| Project | State on 5 Oct 2026 |
|---|---|
| [A2A protocol](https://github.com/a2aproject/A2A) | v1.0.1 (28 May 2026) |
| [`@a2a-js/sdk`](https://github.com/a2aproject/a2a-js) | 1.3.0 (29 Sep 2026); 1.2.0 on 18 Sep, 1.2.1 on 24 Sep. Changes since 1.2.0 to `CallInterceptor`, `AgentExecutor` and `verifyAgentCardSignature` have **not** been reviewed |
| [`@kya-os/mcp`](https://github.com/decentralized-identity/kya-os-mcp) | 1.16.2 on npm; latest GitHub release is v1.14.2 (25 Aug), tags run to v1.16.2 |
| [AP2](https://github.com/google-agentic-commerce/AP2) | v0.2.0 (28 Apr 2026); last commit 29 Apr 2026 |
| [`experimental-ext-oid4vp-auth`](https://github.com/a2aproject/experimental-ext-oid4vp-auth) | Only existing `experimental-ext-*` precedent in `a2aproject`; no releases |
| [`a2a-tck`](https://github.com/a2aproject/a2a-tck) | Conformance kit; no releases |

No `a2aproject` repository for a DID- or cheqd-based extension exists.

## 2. Papers

### 2.1 A2ABreak — most relevant

[Lotfi, Rahman, Karim, Bertino. *A2ABreak: Systematic Security Analysis of the A2A Protocol*](https://arxiv.org/abs/2609.10871), arXiv 2609.10871, 9 Sep 2026, accepted at ACSAC '26. Code: [`arlotfi79/A2ABreak`](https://github.com/arlotfi79/A2ABreak).

Formal-model analysis of the A2A specification. Reports 11 vulnerabilities exploitable by a specification-compliant adversary (Table 3 of the paper; verified against the PDF):

| # | Finding | Relevance here |
|---|---|---|
| 1 | Unattested Skill Claims | Agent Card signing authenticates the publisher, not the truthfulness of advertised skills |
| 2 | JWS Key Trust Model Gap (§8.4) | The SDK has no default key resolver; a DID-backed resolver is the seam |
| 3 | Cross-Client Context Injection | `contextId` is unprotected; a request-proof envelope should cover `contextId` and `taskId` |
| 4 | SSE Post-Revocation Leakage | Out of scope for synchronous v1 |
| 5 | Artifact Chunk Integrity Gap | Out of scope for v1 |
| 6 | Concurrent Access TOCTOU | Out of scope for v1 |
| 7 | Unverified Webhook URL | Out of scope for v1 |
| 8 | Auth Scope Amplification | Delegation scope checks |
| 9 | Multi-Hop Identity Loss | No principal or chain-of-custody field in A2A delegation |
| 10 | Circular Delegation Deadlock | Out of scope |
| 11 | No Timeout from Interrupted States | Out of scope |

Findings 1, 2, 3, 8 and 9 map directly onto the problem this work addresses. The paper's mitigations have not yet been read in full or mapped onto a design.

### 2.2 Whisper attacks on AP2

[*Signing the Transaction but Not the Decision: Whisper Attacks and a Binding Defense for AP2*](https://arxiv.org/abs/2609.11757), arXiv 2609.11757, Sep 2026. Defence code: [`yedidel/avip_defense`](https://github.com/yedidel/avip_defense). Benchmark: [`ap2-whisperbench`](https://huggingface.co/datasets/anonymos-2321135/ap2-whisperbench).

*Unverified (summary of the HTML page).* AP2 signs the transaction but not the decision that produced it. Merchant-controlled text can manipulate a shopping agent without a protocol violation. Reported success rates: credential extraction 90%, cart corruption 56%, product-selection influence 73.3%. The proposed defence treats the signed Intent as a capability grant. **Implication:** binding an agent key to a mandate (`cnf` continuity) does not by itself address these attacks. An AP2 threat model must say so explicitly.

### 2.3 Others

| Paper | Note |
|---|---|
| [AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A](https://arxiv.org/abs/2603.24775) (Mar 2026) | Competing approach: invocation-bound capability tokens (JWT, or Biscuit chains for multi-hop). Not DID-centred. No repository found. *Unverified.* |
| [AgentDID](https://arxiv.org/abs/2604.25189) (Apr 2026) | DID/VC authentication for agents. Not read. |
| [AI Identity: Standards, Gaps, and Research Directions for AI Agents](https://arxiv.org/abs/2604.23280) (Apr 2026) | Survey. Not read. |
| [AgentFacts: Universal KYA Standard](https://arxiv.org/abs/2506.13794) (Jun 2025) | Agent metadata disclosure. Not read. |
| [Secure Use of AP2 (Cloud Security Alliance)](https://cloudsecurityalliance.org/blog/2025/10/06/secure-use-of-the-agent-payments-protocol-ap2-a-framework-for-trustworthy-ai-driven-transactions) | Practitioner guidance. Not read. |

## 3. Know Your Agent (KYA) efforts

"KYA" is used by several unrelated projects. They should not be conflated with the DIF TAAWG `kya-os` work this repository builds on.

| Project | Notes |
|---|---|
| [KYAPay](https://kyapay.org/overview/the-agentic-protocol-stack) | Describes a stack of MCP, A2A, MCP-I, AGNTCY, x402/h402, AP2 and Agent Commerce Kit, and a `kya` / `pay` / `kya-pay` JWT trio. Operator not stated on the page fetched (a link label mentions Skyfire). The page does not mention cheqd or Baselayer. Specification and whitepaper links were not followed |
| Baselayer KYA | Commercial product from a US bank fraud-risk vendor, announced with a $35M Series A ([Crunchbase](https://news.crunchbase.com/ai/verifying-ai-agents-baselayer-35m-raise/)). Stated aim: establish who deployed an agent, whom it represents and what it may do. Named partners: FIS, Prove, Socure. No specification, repository, credential format or standards references found. The `baselayer` GitHub organisation contains only an unrelated 2015 fork |
| [`open-kya/kya-standard`](https://github.com/open-kya/kya-standard) | Governance-disclosure framework; 7 stars |
| [`fotescodev/kya-protocol`](https://github.com/fotescodev/kya-protocol) | On-chain identity on EAS; no stars |
| [`techblaze-au/idprova-hero-demo`](https://github.com/techblaze-au/idprova-hero-demo) | LangChain/LangGraph demo of scoped, revocable KYA credentials |

GitHub searches for A2A + DID and AP2 + `cnf` + DID returned no repositories.

## 4. Open follow-ups

1. Review `@a2a-js/sdk` 1.3.0 against the interfaces the design depends on.
2. Read the A2ABreak mitigations and map findings 1, 2, 3, 8 and 9 onto the request-proof envelope.
3. Verify the AP2 whisper-attack claims against the full paper.
4. Follow the KYAPay specification and whitepaper links.
5. Read AIP, AgentDID and the AI Identity survey for related-work coverage.

## Method and limits

Web search is US-only. Page summaries were produced by an automated summariser; only the A2ABreak findings table was checked against the PDF text.
