# Personal Agent Protocol (PAP, "Poppy"): research note

Researched 16 Oct 2026. Draft 0.1 of the specification was read in the [source repository](https://github.com/personal-agent-protocol/personal-agent-protocol) (commit of 15 Oct 2026): sections 1 to 6, 7.1 to 7.2 and 7.8 to 7.9 in detail, plus the path-to-1.0, extensions, operations and guides pages. Conversation message formats (7.3 to 7.7, 7.10 to 7.13) were skimmed, not reviewed.

## What it is

A protocol for a **personal agent acting for one user** to work with **a company** (a business that implements it). It is business-facing: it covers how an agent finds a company, identifies itself, gets the user's permission and then uses the company's website, APIs or its own agent. It is not an agent-to-agent protocol like A2A, and it does not define payments.

| Part | What the draft says |
|---|---|
| Discovery | The company publishes `/.well-known/poppy.json` over HTTPS. The `organization.domain` must match the host requested. It lists sign-in types, APIs (OpenAPI or MCP), a company agent, and a web browser-session endpoint |
| Company identity | The company's OAuth issuer, checked against `poppy_domains` in its RFC 8414 metadata. This stops one domain claiming another company's issuer |
| Agent identity | The agent's `client_id` is an HTTPS URL returning a metadata document (the OAuth Client ID Metadata Document draft, also used by MCP) with a `jwks_uri` and redirect URIs. Companies may require registration, allowlist or block by `client_id`, and rate-limit by it. Registration is out of scope |
| User identity | A per-company opaque **User ID** chosen by the agent, so a company recognises a returning user while signed out but companies cannot link users. It must not derive from personal information |
| Sessions | One user, one company, one agent. Starts signed out via an RFC 7523 JWT bearer assertion. Session tokens are short-lived and **DPoP-bound** (RFC 9449) on every API and conversation request; Bearer tokens are allowed only for MCP |
| Sign-in | Direct (OAuth in the user's browser), Device (RFC 8628 code) or **Mediated** (the agent sends the user's credentials to the company). Scopes `poppy:read` and `poppy:write`, plus company-defined scopes. The long-lived **Account Token** is an OAuth refresh token, revocable at an RFC 7009 endpoint |
| Web browsing | The agent's browser posts a signed `poppy-browser+jwt` assertion and the company sets its own cookie for the same session |
| Conversations | Messages to the company's agent over HTTPS with a `sender` field saying whether a human or an AI wrote each message; handoff to a person; Direct Conversations where the user talks to the company |
| Extensions | Named extensions advertised in `poppy.json` and in the agent's metadata. One is defined: **operations** (propose, approve exact terms, confirm, track; at-most-once) |

Standards reused: OAuth 2.0 and its RFCs, JWT, DPoP, OpenAPI 3.1, MCP 2025-06-18, RFC 9728. It defines almost no new cryptography of its own.

## Who is behind it

- **Sierra** (announcement credits Bret Taylor and Clay Bavor) and **Meta**, announced 6 Oct 2026 at Sierra Summit, [draft 0.1 published 9 Oct](https://sierra.ai/blog/poppy). The specification, site and repository name no authors or editors.
- The GitHub organisation was created on 13 Oct 2026, has no public members, and the repository's only commit history visible to me was from one committer. Licence is Apache-2.0 and contributions fall under separate terms on the site (not read).
- **No standards body or governance structure is named** anywhere I found. [Constellation Research](https://www.constellationr.com/insights/news/meta-sierra-pitch-personal-agent-protocol-govern-how-personal-ai-agents-deal-business) also notes this. Contrast: A2A is a Linux Foundation project, x402 is under a foundation, AP2 was reported donated to the FIDO Alliance.
- Stated motive, from Sierra and Meta: businesses currently either block agents or let them do anything the user can; PAP gives a middle path. Meta's Muse agent was the live-demo agent (with Rocket) at Sierra Summit.

## Design partners

The [path-to-1.0 page](https://personalagentprotocol.org/docs/path-to-1) lists 43 partners that agreed to be listed. Sierra's post says 35 were added with the draft on top of those announced earlier, so the totals differ by source.

- **Personal agents (3):** Instinct, Meta, OpenAI.
- **Companies (21):** Bank of America, BBVA, Chime, Cigna, Comcast, DIRECTV, FOX, Gap Inc., GEICO, Hertz, Insurify, Liberty Mutual, Nordstrom, PayPal/Venmo, Rocket, SiriusXM, Synchrony, Target, United Airlines, Walmart, Wells Fargo.
- **Technology providers (19):** 1Password, Adyen, Atomic, Cloudflare, ElevenLabs, Genesys, Klaviyo, Mastercard, NiCE, Notion, Okta, OneSignal, Plaid, Shopify, Sierra, Stripe, Visa, Zapier, Zendesk.

Notable absences: Anthropic and Google are not listed (one source says Anthropic is absent). JPMorgan is not listed. Reported on 15 Oct, [JPMorgan's Jamie Dimon said the bank blocks outside AI agents from accounts](https://finance.yahoo.com/technology/ai/articles/don-t-want-rogue-agents-181013092.html) ("You don't want rogue agents"), and Meta pointed to Poppy as its answer. Amazon was reportedly blocking Muse in September (single source).

## Adoption evidence (all within days of publication)

| Signal | Finding |
|---|---|
| Live `poppy.json` files | I requested `/.well-known/poppy.json` on 18 partner and project domains on 16 Oct. **None returned a poppy.json document.** Twelve returned 404, three (Rocket, GEICO, Chime) returned 403 so are unknown, one redirected, one was unreachable, one returned an unrelated HTML page. Even the protocol's own domains had none |
| Official reference implementation | None yet. Promised "over the next month". The site has no JSON Schema or conformance suite (per a third-party README) |
| Community implementations | All created 9 to 10 Oct: [datalayer/personal-agent-protocol](https://github.com/datalayer/personal-agent-protocol) (Python and TypeScript SDK, 3 stars), [pi-poppy](https://github.com/richardanaya/pi-poppy) (1), [poppyseed](https://github.com/akshay5995/poppyseed) (Next.js, with a conformance checker, 0 stars, self-described as unaffiliated), plus experimental pull requests in an auth framework and an agent harness, and several zero-star validators |
| Spec repo | 20 stars, 1 fork, 10 issues and 1 pull request in the first two days, mostly review feedback |
| Production use | None found. One live demo (Muse and Rocket mortgage pre-approval) |

Reading: heavy launch-week interest from the ecosystem, a large announced partner list, and no evidence yet of any company actually publishing a file or a personal agent shipping against it.

## Review findings already filed against the draft

Ten issues were open within two days. Five are security reports from one reviewer. I read the summaries of #2 to #5 and #8:

- The draft has **no Security Considerations section**. The reviewer's first example is prompt injection between agents: everything a company returns goes into the personal agent's model, which holds the user's context and other open sessions (#4).
- **Mediated Sign-In** gives the agent the user's raw password, and its endpoint comes only from `poppy.json`, which can be served through a redirect, not from the issuer-checked OAuth metadata (#5).
- A hosting provider using one issuer for many companies merges them into one "company" and links users across them (#3; a pull request on company isolation is open).
- Possible replay of a client assertion at another company if `aud` is unspecified for client assertions (#2; section 4.2 does fix `aud` for the session assertion, so this concerns the client assertion only).
- Contradictory rules about whether a signed-out session can sign in to a different account (#8).

These are one reviewer's claims against a day-old draft. I checked that the draft has no Security Considerations section and that Mediated Sign-In works as described. I did not verify the other findings.

## Where it overlaps and differs in the capability map

- **Agent identity is thin by design.** An agent is a URL with keys. There is no credential, no attestation of who operates it, no registry, and no trust or reputation signal. Companies decide who to allow themselves, by `client_id`.
- **Strong on per-request proof.** DPoP gives holder-of-key binding, per-request proof and replay protection with `jti` and optional server nonce. This is more than most protocols in the map specify.
- **Delegation is coarse.** The user grants account scopes and the agent holds a refresh token. There is no signed, constrained delegation credential. The operations extension adds approval of exact terms per action; I did not read how that approval is recorded or whether it is signed.
- **Payments are explicitly out of scope** (an open topic). It could sit above x402, AP2 or UCP rather than compete with them. UCP overlaps on business capability discovery.
- **Agent-to-agent conversation uses its own `poppy` protocol.** A2A is not a listed conversation type in 0.1, though the list is extensible.

## Not checked

- Conversation message formats and error handling in full, and the operations extension beyond its overview.
- The site's contribution terms and any governance statement beyond the pages read.
- Whether the 403 and redirect responses from partner domains hide a real file.
- Claims in secondary coverage that I could not trace to Sierra or Meta (Amazon blocking Muse; Anthropic absent from the partner list).
