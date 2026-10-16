# Protocols tracked

Every protocol that appears in the capability map ([`generate.py`](./generate.py)), with who stewards it, where it is documented and how firm the ratings are. Ratings are the author's assessment (October 2026).

**Adoption columns** are as of 16 Oct 2026. Stars and last-push dates come from the GitHub API. Adopter lists and usage figures come from search results, mostly vendor announcements and secondary blogs, and none were checked against primary sources. A named partner is not a deployment: read "design partner" and "launch partner" as intent, not production use.

**Rating basis:** *Spec* means the specification was read. *Secondary* means rated from announcements, blog posts or press. Protocols whose ratings are provisional would render with dashed chips; none are at present.

| Protocol | Steward | What it does | Status | Documentation | Rating basis | Signs of adoption | Evidence quality |
|---|---|---|---|---|---|---|---|
| A2A | Linux Foundation project (`a2aproject` on GitHub) | Agent Card discovery, messages, tasks, extensions | v1.0.1 (28 May 2026) | [github.com/a2aproject/A2A](https://github.com/a2aproject/A2A) | Spec | Linux Foundation reports 150+ supporting organisations (April 2026), integrations on Google, Microsoft and AWS platforms and production use in supply chain, financial services, insurance and IT operations | Foundation-reported, plus very high SDK downloads; no independent deployment list found |
| MCP | Anthropic-originated open standard | Tool and data access for agents | Released | [modelcontextprotocol.io](https://modelcontextprotocol.io) | Secondary | Named as a compatibility target by ACP (2026-04-17 release) and PAP. Broader MCP adoption was not researched here | Strong package use; adopters not researched |
| KYA-OS | Decentralized Identity Foundation | Entity Card, `proof.v1`, delegation credentials, `cnf` binding | `@kya-os/mcp` 1.16.2 | [github.com/decentralized-identity/kya-os-mcp](https://github.com/decentralized-identity/kya-os-mcp) | Spec | Spec v1.0.0 released 29 Jul 2026 (Vouched and DIF). cheqd's June 2026 blog reports about 27,000 MCP servers and agents registered under the knowthat.ai DID method. Checkpoint is Vouched's implementation | Vendor-reported; no independent analysis found |
| KYAPay | Skyfire (GitHub `skyfire-xyz`) | `kya`, `pay` and `kya-pay` JWTs | Not recorded | [kyapay.org](https://kyapay.org/overview/the-agentic-protocol-stack) | Secondary | None found. Not researched beyond the overview page | None found |
| Baselayer KYA | Baselayer (commercial) | Who deployed an agent, whom it represents, what it may do | Closed, no public spec found | [Crunchbase coverage](https://news.crunchbase.com/ai/verifying-ai-agents-baselayer-35m-raise/) | Secondary | Named partners FIS, Prove and Socure; $35M Series A | Vendor-reported; closed product |
| ANS | Independent submission (authors from GoDaddy, OWASP, DistributedApps.ai, Cisco) | DNS-anchored agent names, identity certificates, transparency log, assurance tiers | Internet-Draft `draft-narajala-courtney-ansv2-01`, expired | [datatracker.ietf.org](https://datatracker.ietf.org/doc/draft-narajala-courtney-ansv2/) | Spec | No deployments found. Independent submission with no working group; the draft expires 15 Oct 2026 unless renewed. A Go reference implementation exists ([agentnameservice/ans](https://github.com/agentnameservice/ans)); its operator is not confirmed. No GoDaddy product tied to the draft was found | None found |
| Web Bot Auth | IETF working group | RFC 9421 request signatures, `Signature-Agent`, JWKS key directory | Internet-Draft `draft-ietf-webbotauth-httpsig-protocol-00` | [datatracker.ietf.org](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) | Spec | Reported: OpenAI signs ChatGPT agent requests; Cloudflare verifies signed agents; AWS WAF, Akamai and Vercel named as verifiers; Google is testing it, with Google-Agent signing and Googlebot not. TAP is built on it | Secondary blogs; not checked against OpenAI, Google or Cloudflare documentation |
| **PAP (Poppy)** | Published by Sierra (announcement credits Bret Taylor and Clay Bavor) with Meta. The spec and repo name no authors or editors; [`personal-agent-protocol`](https://github.com/personal-agent-protocol/personal-agent-protocol) is a GitHub organisation created 13 Oct 2026 | Personal agent works with a company for one user: `/.well-known/poppy.json` discovery, sessions bound to an agent-held key with DPoP, OAuth sign-in with `poppy:read` and `poppy:write` scopes, APIs, web browsing, conversations with the company's agent | Draft 0.1 (spec text commit 15 Oct 2026), Apache-2.0; 35 design partners | [Spec](https://personalagentprotocol.org/docs/spec), [site](https://personalagentprotocol.org/), [repo](https://github.com/personal-agent-protocol/personal-agent-protocol), [Sierra announcement](https://sierra.ai/blog/poppy) | Spec | 43 partners listed on the spec site (Sierra's post says 35 were added with the draft), including OpenAI, Meta, Visa, Mastercard, Walmart, Bank of America and Cloudflare. One live demo (Meta's Muse and Rocket). None of 18 partner and project domains checked served a `poppy.json` on 16 Oct. Community SDKs and validators appeared within a day (3 stars or fewer). No official reference implementation yet. See [pap-2026-10.md](../../pap-2026-10.md) | Vendor-announced; no live deployment found |
| **x401** | Proof (Notarize, Inc.). Editors Daniel Buchner (Proof) and Bhushit Agarwal (Circle). Reviewers from Lightspark, MATTR, Okta, OpenAI, Proof and Visa. No standards body named in the spec | HTTP Proof Requirement Protocol: a route returns 401 with a Verifier-authored Digital Credentials request (OpenID4VP over the DC API, DCQL); the agent retries with the result. Agent binding is optional | Standard Draft 0.2.0, Apache-2.0 | [Spec](https://x401.proof.com/spec/latest/), [x401.id](https://x401.id), [repo](https://github.com/proof/x401), [Proof launch post](https://www.proof.com/blog/introducing-x401) | Spec (key sections) | Spec contributors from Circle, Lightspark, MATTR, Okta, OpenAI and Visa. Proof says its Digital ID is the first live implementation, and ships a Node SDK (`@proof.com/x401-node`, 744 downloads a month). No independent adopters found | Vendor-reported |
| AP2 | Google | Intent, checkout and payment mandates, `cnf` key binding | v0.2.0 (28 Apr 2026) | [github.com/google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2) | Spec | 60+ launch partners (Sep 2025), later claimed as 100+. Reported as contributed to the FIDO Alliance in April 2026. Production deployments are claimed by some sources and denied by others. No commits in 90 days and no published package found | Partner list documented; production use unconfirmed |
| UCP | Google | Business capability manifest, checkout and order semantics | Not recorded | Google developer blog (link not recorded) | Secondary | Launched 11 Jan 2026 with Shopify, Etsy, Wayfair, Target and Walmart. An independent tracker (UCP Checker) counted 8,000+ verified stores by mid-June 2026, about 99% on Shopify. Live in the US and Australia | Independent tracker, but Shopify-dominated |
| ACP | OpenAI | Checkout in ChatGPT | Not recorded | Link not recorded | Secondary | Stripe and PayPal as payment providers. Instant Checkout reported retired or deprioritised in March 2026 after about a dozen Shopify merchants shipped it; sources conflict | Secondary; conflicting |
| TAP | Visa | Card-network agent payments | Not recorded | Link not recorded | Secondary | Launch partners Adyen, Checkout.com, Fiserv, Microsoft, Nuvei and Shopify (Oct 2025). No 2026 adoption found | Launch announcements only |
| x402 | x402 Foundation (GitHub `x402-foundation`; reported as a Linux Foundation project) | HTTP 402 payment request, stablecoin settlement | Not recorded | [x402.org](https://x402.org), [repo](https://github.com/x402-foundation/x402) | Secondary | Coinbase counts about 165M cumulative transactions and about $50M volume by April 2026. Independent analyses estimate roughly half was testing or bot farming. Reported under a Linux Foundation x402 Foundation with Stripe and Cloudflare; dates conflict. Heavy package use (see metrics) | Vendor figures, unaudited; independent estimates disagree |
| MPP | Stripe and Tempo | Session and streaming payments, multiple payment methods | Not recorded | Link not recorded | Secondary | Launched 18 Mar 2026 by Stripe and Tempo. 100+ integrated services claimed. Core submitted to the IETF as an individual draft (`draft-ryan-httpauth-payment`) | Vendor-reported; no independent usage data |
| L402 | Not recorded | HTTP 402 with Lightning and macaroons | Not recorded | Link not recorded | Secondary | `lightning-agent-tools` launched Feb 2026. A Feb 2026 newsletter reported zero production endpoints; nothing newer found | Thin |
| cheqd | cheqd | `did:cheqd`, DID-Linked Resources, status lists, trust registries | Live network | [docs.cheqd.io](https://docs.cheqd.io) | Spec | Not researched here | Not researched |

## Adoption metrics

Collected 16 Oct 2026 from the GitHub API and the npm and PyPI download APIs. "Commits (90d)" counts commits to the default branch since 18 Jul 2026.

| Protocol | Main repo | Stars | Forks | Contributors | Commits (90d) | Latest release | Package downloads (last 4 weeks, per registry the top package) |
|---|---|---|---|---|---|---|---|
| A2A | [a2aproject/A2A](https://github.com/a2aproject/A2A) | 26,175 | 2,675 | 176 | 64 | v1.0.1, 28 May 2026 | `@a2a-js/sdk` 14.4M (npm); `a2a-sdk` 11.1M (PyPI); `a2a-lf` 55K (crates.io) |
| MCP | [modelcontextprotocol/modelcontextprotocol](https://github.com/modelcontextprotocol/modelcontextprotocol) | 9,458 | 1,870 | 372 | 390 | 28 Jul 2026 | `@modelcontextprotocol/sdk` 256.4M (npm); `mcp` 229.2M (PyPI); `rmcp` 8.5M (crates.io) |
| x402 | [x402-foundation/x402](https://github.com/x402-foundation/x402) | 6,723 | 2,192 | 334 | 267 | no GitHub releases | `x402` 1.9M (npm); `x402` 223K (PyPI) |
| UCP | [Universal-Commerce-Protocol/ucp](https://github.com/Universal-Commerce-Protocol/ucp) | 3,429 | 479 | 64 | 98 | v2026-08-25 | `@ucp-js/sdk` 50K (npm); `ucp-sdk` 7.2K (PyPI); `ucp-schema` 829 (crates.io) |
| AP2 | [google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2) | 3,230 | 512 | 19 | 0 | v0.2.0, 28 Apr 2026 | None found on npm, PyPI or crates.io |
| ACP | [agentic-commerce-protocol/agentic-commerce-protocol](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol) | 1,574 | 255 | 26 | 0 | no GitHub releases | `agentic-commerce-protocol` 47 (npm); `agentic-commerce-protocol` 50 (PyPI) |
| TAP | [visa/trusted-agent-protocol](https://github.com/visa/trusted-agent-protocol) | 213 | 45 | 2 | 0 | no GitHub releases | None found on npm, PyPI or crates.io |
| MPP | [wevm/mppx](https://github.com/wevm/mppx) (TypeScript SDK) and [tempoxyz/mpp-specs](https://github.com/tempoxyz/mpp-specs) | 186 and 95 | 71 and 71 | 31 and 23 | 262 and 41 | `mppx@0.13.5`, 15 Oct 2026 (122 releases) | `mppx` 977K (npm); `pympp` 2.0M (PyPI) |
| L402 | [lightninglabs/aperture](https://github.com/lightninglabs/aperture) and [lightninglabs/L402](https://github.com/lightninglabs/L402) | 271 and 91 | 82 and 19 | 27 and 8 | 106 and 0 | aperture v0.5.0, 25 Mar 2026 | `@lightninglabs/l402` 104 (npm); `l402` 24 (PyPI, community) |
| Web Bot Auth | [cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth) | 170 | 43 | 17 | 35 | no GitHub releases | `web-bot-auth` 689K (npm); `web-bot-auth` 82K (crates.io) |
| x401 | [proof/x401](https://github.com/proof/x401) | 42 | 5 | 4 | 3 | no GitHub releases | `@proof.com/x401-node` 729 (npm) |
| ANS | [agentnameservice/ans](https://github.com/agentnameservice/ans) (reference implementation) | 43 | 6 | 9 | 29 | v0.1.6, 26 Jun 2026 | None found on npm, PyPI or crates.io |
| KYA-OS | [decentralized-identity/kya-os-mcp](https://github.com/decentralized-identity/kya-os-mcp) | 31 | 13 | 6 | 178 | v1.20.0, 13 Oct 2026 | `@kya-os/mcp` 54K (npm) |
| PAP (Poppy) | [personal-agent-protocol/personal-agent-protocol](https://github.com/personal-agent-protocol/personal-agent-protocol) (spec and site, created 14 Oct 2026) | 20 | 1 | 1 | 3 | no GitHub releases | `@datalayer/personal-agent-protocol` 2.0K (npm, community); `personal-agent-protocol` 1.4K (PyPI, community) |
| KYAPay | [skyfire-xyz/kyapay](https://github.com/skyfire-xyz/kyapay) | 13 | 0 | 8 | 1 | no GitHub releases | `@skyfire-xyz/skyfire-seller-sdk-node` 52 (npm) |
| cheqd | [cheqd/did-resolver](https://github.com/cheqd/did-resolver) | 12 | 7 | 17 | 3 | v3.8.5, 3 Sep 2026 | `@cheqd/sdk` 3.4k, `@cheqd/did-provider-cheqd` 864 (npm) |
| Baselayer KYA | No public repo | n/a | n/a | n/a | n/a | n/a | n/a |

### Other GitHub signals

- **A2A has a full SDK set:** Python (2,203 stars), JavaScript (643), Java (505), Go (487) and .NET (267), each with a release in the last three weeks.
- **x402 has the most open issues** (727) and the second-most forks after A2A (2,192 against 2,675), which suggests heavy experimentation.
- **UCP has a conformance suite and Python and JavaScript SDKs** in its GitHub organisation.
- **x402 has working groups** for identity, tax and domain discovery under its GitHub organisation. The identity group repo has 4 stars and its last push was 17 Aug 2026.
- **Repos quiet for 90 days or more:** AP2 (last push 17 Jun 2026), ACP (18 Jul 2026), L402 spec (9 Jun 2026) and TAP (28 Oct 2025).
- **GitHub topics (repos tagged):** `model-context-protocol` 37,653; `x402` 3,827; `a2a-protocol` 604; `l402` 110; `universal-commerce-protocol` 66; `web-bot-auth` 41; `agentic-commerce-protocol` 27; `agent-payments-protocol` 19. Topic counts are noisy and include unrelated and spam repos.

### Read with care

- Download counts include CI, mirrors and bots. Treat them as relative reach, not users. A2A and MCP counts are inflated by transitive installs from agent frameworks.
- Stars measure attention more than use. The x401 and PAP repos are days or weeks old.
- The MPP and L402 rows cover two repos each because the specification and the reference code live apart.
- `coinbase/x402` is a fork of `x402-foundation/x402` with 168 stars. The canonical repo is the foundation's.
- Packages were matched to protocols by the repository URL in their registry metadata. `pympp` and `pytempo` are published by Tempo, `agentic-commerce-protocol` by Svix and `l402` by Fewsats, and I did not verify that these publishers are authorised by the protocol owners. The `ap2` package on PyPI belongs to an unrelated project and is not counted.

## Traction charts

Four charts, drawn from the data in the metrics table. cheqd is not charted. They follow the system light or dark setting, and hovering a point in a browser gives the exact value. Each ends with a "Not covered by this chart" box.

![Weekly commits to each protocol, added across its repositories](./traction/commit-activity.svg)

**Development activity.** Commits are added across each protocol's repositories, including SDKs and samples, so a protocol is not judged by its specification repository alone. MCP leads (4,070 commits across 6 repositories in the last year), then A2A (2,050 across 8), MPP, x402 and UCP. AP2, ACP and TAP are flat. Protocols with several repositories carry a repository count, and the box lists every repository added.

PAP's 179 commits come mostly from a community SDK. [`datalayer/personal-agent-protocol`](https://github.com/datalayer/personal-agent-protocol) is a Python and TypeScript SDK by Datalayer, Inc. (BSD-3-Clause, created 10 Oct 2026, 162 commits in its first days, nearly all by one author, with releases 0.21 to 0.24 between 13 and 14 Oct). It is a third-party implementation of the draft, not Sierra's or Meta's. The protocol's own repository, `personal-agent-protocol/personal-agent-protocol`, holds the spec and website and has 3 commits. Community repositories are marked with a dagger in the box.

![Weekly package downloads for each protocol across npm, PyPI and crates.io](./traction/downloads-all-registries.svg)

**Downloads, all registries.** The same 12 weeks for every protocol, with npm, PyPI and crates.io added together. Per registry the most downloaded package is counted, so a package and its dependencies are not counted twice. MCP is far ahead (129M a week), then A2A (6.9M), MPP (1.5M, more from `pympp` on PyPI than from `mppx` on npm), x402 (542K) and Web Bot Auth (181K). PAP, L402, ACP and KYAPay have small series from community or vendor packages. AP2, TAP, ANS and Baselayer KYA have none: no package was found for AP2 (the `ap2` package on PyPI belongs to an unrelated project), TAP or ANS on npm, PyPI or crates.io, and Baselayer is closed.

![Weekly npm downloads of each protocol's main SDK, log scale](./traction/npm-downloads.svg)

**npm history.** Eight protocols on one log scale since April 2025, the longest history any registry gives. MCP is two orders of magnitude ahead and still rising. A2A's JavaScript SDK went from about 100 to 4.1M a week in 16 months. MPP's SDK went from 317 downloads in its first week to 336K. UCP and KYA-OS are two to three orders of magnitude smaller, and x401's SDK is under 300 a week. The palette allows eight series, so the other protocols with npm packages are listed in the box and shown in the all-registries chart.

![GitHub stars on each protocol's main repository, log scale](./traction/github-stars.svg)

**Stars.** A2A leads, then MCP, x402, UCP and AP2. AP2 and ACP hold thousands of stars with no recent commits. Hollow dots mark repositories with no commits in the last 13 weeks. Only one repository per protocol is charted, and others can be larger: the MCP Python and TypeScript SDKs hold more stars than the specification repository (24,593 and 13,590 against 9,458).

### Gaps marked on the charts

- **No data is marked, not hidden.** Dashed boxes and panels show where a protocol has nothing to plot, with the reason.
- **No repository or package yet.** Dashed shading marks weeks before a repository existed (commits chart) or before a package had downloads (all-registries chart), so a flat line means no activity rather than no project.
- **Counting choices.** Commits use the default branch only. Downloads cover npm, PyPI and crates.io. Maven, NuGet, Go modules and container pulls are not measured, and downloads include CI and mirrors.
- **Star history over time** is not shown. GitHub's stargazer endpoints returned nothing in this environment, so stars are a snapshot.

The repositories and packages counted are set in `OTHERS` and `PACKAGES` in `traction/fetch.py`. Refresh with `python3 traction/fetch.py` (needs `gh` logged in), then `python3 traction/render.py`. The data behind the charts is in [`traction/data.json`](./traction/data.json).

## Notes

- **PAP and Poppy are the same protocol.** Poppy is the nickname; PAP is the formal name. Meta's Muse agent was the live-demo agent at Sierra Summit (6 Oct 2026). It is not a separate protocol.
- **PAP authorship.** The only authorship statement found is Sierra's announcement post, which credits Bret Taylor and Clay Bavor. The spec, site and repo name no authors. The repo's one visible committer is Arya Asemanfar; the GitHub organisation has no public members.
- **PAP as read from the spec.** The agent is identified by an HTTPS `client_id` pointing at a metadata document with a `jwks_uri` (the OAuth Client ID Metadata Document draft that MCP also uses). Session tokens are DPoP-bound (RFC 9449) with per-request proofs (`jti`, `htm`, `htu`, `iat`, `ath`, optional server nonce); Bearer tokens are allowed only on MCP APIs. Sign-in is OAuth with an account token (refresh token) revocable at an RFC 7009 endpoint. Conversations carry a `sender` field saying whether a human or an AI wrote each message. It defines no credential or DID-based agent identity, and no payment (payments are named as a possible extension).
- **x401 authorship.** Proof is the steward and the repo owner. [`proof/x401`](https://github.com/proof/x401) has Apache-2.0 licence and its CODEOWNERS is the Proof product team. Press coverage names Circle, OpenAI, Okta and Google as contributors; the spec lists Circle as co-editor and OpenAI and Okta as reviewers, and does not list Google. Proof has said it will submit x401 to the FIDO Alliance. That is Proof's claim and the spec names no standards body.
- **x401 proves attributes of a credential holder, not the agent.** The result is bound to the verifier, and agent binding (Web Bot Auth, mTLS, DPoP, SPIFFE) is optional and left to deployments. Delegation, payment sequencing with x402, AP2, ACP and UCP, and when agent binding becomes mandatory are all listed as open questions in the spec. Proof's launch post describes a user-signed spend mandate. The spec does not define one, so the map does not rate x401 on spend limits and rates human-to-agent authority as partial.
- **Not read in full.** For x401, the design goals, binding, agent identification, security and open-questions sections and the changelog were read, not all 1,685 lines. For PAP, sections 1, 4.1 to 4.4, 4.9 and 7.8 were read, not the web browsing, API and conversation detail.
- **Unchecked links:** the datatracker, x402.org, modelcontextprotocol.io and docs.cheqd.io links were written from the usual URL patterns and not opened. Check them before relying on them.
