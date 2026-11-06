# Status-list probes against the public cheqd resolver (13 October 2026)

Read-only. Re-run with `./probe.sh`. Target: a real testnet resource from Studio's e2e fixtures,
`did:cheqd:testnet:0c3581f0-…` / `cheqd-employee-credentials-unencrypted` (`StatusList2021Revocation`,
created 2023).

## Findings

| Question | Answer |
|---|---|
| Does the resolver return a checksum and version metadata? | Yes: `?resourceMetadata=true` returns `linkedResourceMetadata` with `resourceId`, `resourceCollectionId`, `resourceName`, `resourceType`, `mediaType`, `resourceVersion`, `created`, `checksum`, `previousVersionId`, `nextVersionId` |
| What is the checksum? | SHA-256 (hex) of the raw bytes the resolver returns for the resource. Verified: `sha256(body)` equals the metadata checksum |
| How do you get the latest version? | Name + type lookup returns the latest (`nextVersionId` is `null`). A lookup by resource id returns the same bytes. `resourceVersionTime` filters by time (404 before creation) |
| Is there a per-resource metadata endpoint? | Yes: `/{did}/resources/{id}/metadata` |
| Is the checksum independent of the resolver? | No. It comes from the same resolver, so it proves the body matches the metadata, not that the resolver is honest |
| Is there a second source (node REST)? | Not found. `api.cheqd.network` is up but returns `501 Not Implemented` for every resource-module path tried (v1 and v2). gRPC was not tried |
| What does an old list look like? | `{"StatusList2021": {statusPurpose, encodedList, validFrom}, "metadata": {...}}`. It is a plain data record, **not a credential, and has no proof at all**. Integrity rests entirely on the chain |

## Not tested

- A live `BitstringStatusListCredential` (none found).
- A resource with more than one version (the version links exist, but none was exercised).
- Encrypted lists, mainnet, and gRPC access to the node.

## Testing the ledger-anchored `verifyStatusList` (3 November 2026, `verify-ledger-anchored.mjs`)

KYA-OS 1.20.0 already ships a ready-made ledger-anchored resolver for this —
`createCheqdStatusListResolver` (`@kya-os/mcp/cheqd`): pinned issuer DID, Ed25519Signature2020
proof checked against the issuer's on-chain DID document via `createDidCheqdResolver`. If this
works off the shelf, no custom adapter is needed for status-list integrity.

It does not work against the resource above, or any cheqd status-list resource in its current
on-chain shape:

| Scenario | Result |
|---|---|
| Real resource, index 0 | Threw `Fetched resource is not a StatusList2021Credential` |
| Wrong pinned issuer | Same throw (shape check runs before the issuer check) |
| Out-of-range index | Same throw |
| Non-https resource URL | Threw `credentialStatus.statusListCredential must be an https URL` (checked before fetch) |

Cause, read from `assertShape` in `statuslist-resolver.js`: the resolver requires a VC envelope —
top-level `type` including `StatusList2021Credential` and `credentialSubject.type ===
'StatusList2021'` with `credentialSubject.encodedList`. cheqd's on-chain resource is the bare
record from the first probe (`{StatusList2021: {...}, metadata: {...}}`, no `@context`, `type`,
`issuer`, or `proof`) — not VC-wrapped at all, so `assertShape` rejects it before the issuer pin
or the Ed25519 signature check ever run.

## Prototyping the did-provider-cheqd#657 fix (3 November 2026, `eddsa-jcs-prototype.mjs`)

Proof-of-concept for the `signedProof` flag proposed on #657: an independent `DataIntegrityProof`
/ `eddsa-jcs-2022` **signer**, built by reading `@kya-os/mcp`'s verifier (`status-list-proof.js`)
rather than any signer it ships — it ships none for this cryptosuite, confirming the issue's
"needs custom code" claim. Signs real `encodedList` bits pulled live from the testnet resource
above, using a throwaway test key (not cheqd's real issuer key — this proves interoperability,
not a deployment).

| Scenario | Result |
|---|---|
| Our signed VC, verified by KYA-OS's unmodified `createStatusListProofVerifier` | `true` |
| `encodedList` tampered after signing | `false` |
| `issuer` swapped after signing | `false` |
| Signed by a key not published in the resolved DID document (same claimed `kid`) | `false` |
| Full pipeline (`createRevocationChecker`: fetch → verify proof → inflate → read bit) | `{"revoked":false,"fresh":true}` |
| Same pipeline with no `verifyStatusList` wired (today's optional default) | Same result — nothing checked the proof, the bit was just trusted |
| A tampered credential (bits flipped, so the proof is now invalid): unchecked vs. checked | Unchecked reads whatever bit the host now serves and trusts it (`fresh:true`); checked fails closed on the broken signature (`revoked:true, fresh:false`) regardless of what the bit says |

Confirms the construction described in #657's proposal round-trips against KYA-OS's real,
unmodified verifier on the first attempt — the algorithm as read from their verifier code
(proof options without `proofValue`, folding in the document's `@context`; document without
`proof`; each JCS-canonicalized and SHA-256 hashed; Ed25519 over the concatenation; `proofValue`
= `z` + base58btc) is correct and implementable independently, with only `node:crypto` and
`json-canonicalize` — no new dependency needed beyond what KYA-OS already uses. This de-risks
the engineering estimate given for #657: the remaining work is wiring this into
`did-provider-cheqd`'s create/update paths behind the proposed flag, not research.

Not covered: signing with cheqd's real on-chain issuer key (KMS-backed, not a local Ed25519
keypair), serving the signed VC over a real HTTPS DID-Linked Resource URL (tested here via a
stub `fetch`, not `createCheqdStatusListResolver`'s own HTTPS-enforcing path), and the re-signing
cadence for high-churn revocation lists.

## Using the real #658 branch, and a second finding (3 Nov, `verify-branch-signed-credential.mjs`)

While `cheqd/did-provider-cheqd#658` is open (not merged), linked here via a local `file:`
dependency (`package.json`: `"@cheqd/did-provider-cheqd": "file:../../../did-provider-cheqd"`)
so this evidence trail uses the actual branch code rather than a reimplementation. This only
resolves on a machine with a sibling `did-provider-cheqd` checkout on that branch — `npm install`
fails standalone. Once #658 merges and ships a release, switch this to the published npm version.
No funded cheqd testnet account was available (checked; the old `testnet-faucet.cheqd.io` is
retired, the current path is Studio's own faucet behind an account), so this signs with a
throwaway test key and stubs only the one fetch call that would otherwise need a resource
actually broadcast on-chain — DID resolution still goes over the real `resolver.cheqd.net`.

| Scenario | Result |
|---|---|
| The branch's real `signEddsaJcs2022`, on real testnet `encodedList` bits, verified by KYA-OS's real `createStatusListProofVerifier` | `true` |
| Tampered `encodedList` after signing | `false` |
| Full generic card-layer pipeline (`createRevocationChecker`) | Works, reads the bit |
| The same branch-signed credential, through `createCheqdStatusListResolver` (the **cheqd-specific** resolver) | **Throws** — `Invalid character` |
| The same credential, signed with the construction `createCheqdStatusListResolver` actually expects | Passes |

**Finding: `@kya-os/mcp` ships two incompatible "ledger-anchored status list" verifiers.** The
generic card-layer one (`createStatusListProofVerifier`, tested throughout this file and in
`eddsa-jcs-prototype.mjs`) implements `DataIntegrityProof` / `eddsa-jcs-2022`: two JCS hashes
(proof options, document) concatenated and signed, `proofValue` as `z` + base58btc multibase.
The **cheqd-specific** one, `createCheqdStatusListResolver` (`@kya-os/mcp/cheqd`), is a different
construction entirely, read from its `assertSignature` (`statuslist-resolver.js`): one JCS hash
over the whole credential minus `proof`, signed directly, `proofValue` as **plain base64url** —
no multibase prefix, despite the proof being labeled `Ed25519Signature2020` (which is neither
this construction nor the real W3C `Ed25519Signature2020` spec's RDF/URDNA2015 canonicalization —
a third, distinct scheme). `assertShape`/`assertSignature` don't even check `proof.type` or
`cryptosuite`, so a `DataIntegrityProof`/`eddsa-jcs-2022` credential isn't rejected for the right
reason — it just fails to parse as the base64url it expects.

**Consequence:** `did-provider-cheqd#658` (and the `eddsa-jcs-2022` construction proposed on
`did-provider-cheqd#657`) interoperates with the *generic* card-layer verifier, which is
everything a status-list integrity check needs (pinned issuer via a custom DID resolver, proof
verification, bit reading — all demonstrated above and in the original
`verify-ledger-anchored.mjs`/`eddsa-jcs-prototype.mjs`). It does **not** interoperate with
`createCheqdStatusListResolver` specifically. Recommendation: build on the generic
`createStatusListProofVerifier` + `createRevocationChecker` pair for status-list integrity
against cheqd-anchored lists, not `createCheqdStatusListResolver` — the latter's bespoke,
undocumented wire format looks like a KYA-OS-side inconsistency between two of its own modules,
worth raising with that project separately.

**Conclusion:** the upstream ledger-anchored resolver is real and fail-closes correctly on shape,
but it is unusable against today's cheqd status lists. It needs the platform change tracked in
`did-provider-cheqd#657` (wrap and sign the list as a proper `StatusList2021Credential`) before
it can do anything against a live cheqd resource. Until that lands, there is nothing a
cheqd-anchored status list can ship against `createCheqdStatusListResolver` specifically — use
the generic pair instead, which already works today.

## Findings from reading the provider and KYA-OS code (13 October 2026)

- **cheqd's default is two bits per entry** (`DefaultBitstringStatusSize = 2`, messages `0x0 issued`,
  `0x1 revoked`, `0x2 suspended`), and entries carry `statusSize`. Multi-bit values are read
  least-significant-bit first (`bit << i`). The W3C specification text I read does not specify the bit
  order inside a multi-bit value, so I did not claim a discrepancy.
- **KYA-OS's Entity Card `revocation` entry is strict** (`statusListCredential` and `statusListIndex`
  only) and reads one bit at `statusListIndex`. A cheqd entry with `statusSize: 2` has extra keys and,
  if accepted, would be read at the wrong bit. Lists used for Entity Card revocation must use
  `statusSize: 1`.
- The verifier therefore supports unencrypted, one-bit lists only, and rejects two-bit lists.
