/**
 * The decision-6 status-list path: `@kya-os/mcp`'s generic card-layer status checker
 * (`createRevocationChecker` + `createStatusListProofVerifier`), wired to this package's own
 * `did:cheqd` resolver so a `BitstringStatusListCredential`'s `DataIntegrityProof`/
 * `eddsa-jcs-2022` proof is checked against the issuer's on-chain key before any bit is read -
 * never the ledger-anchoring-only path `verifyLedgerAnchoredStatus` takes (see that module's doc
 * comment; the two are for different list-integrity evidence, not alternatives for the same one).
 *
 * `did-provider-cheqd` does not yet produce a list this verifier accepts: 4.8.0 signs the
 * credential before `credentialSubject.encodedList` is attached, so the proof does not cover the
 * bits (cheqd/did-provider-cheqd#657). `cheqd/did-provider-cheqd#658` (open, unmerged) fixes
 * that with an opt-in `eddsa-jcs-2022` proof; this module is written against the format #658
 * produces (confirmed directly against that branch's own signer - see
 * `test/fixtures/bitstring-status-list-eddsa-jcs-2022.json` and its generating script,
 * `evidence/status-list/mint-fixture.mjs` in the a2a-drafts working repo) so there is nothing
 * left to change here once #658 ships: swap a synthetic fixture for a real on-chain resource,
 * same verifier.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createStatusListProofVerifier } from '@kya-os/mcp/card';
import { createRevocationChecker } from '@kya-os/mcp/card';
import type { BitstringRevocationChecker, Decompress } from '@kya-os/mcp/card';
import type { MinimalDidDocument } from '../agent-card/retrieve-public-key.js';

export interface CheqdStatusCheckerOptions {
	/** Resolves the status list issuer's `did:cheqd` document, e.g. `createDidCheqdResolver`'s result. */
	readonly resolveDidCheqd: (did: string) => Promise<MinimalDidDocument | null>;
	/** Fetches the `statusListCredential` URL. Injected so no runtime `fetch` dependency is assumed. */
	readonly fetch: (url: string) => Promise<{ readonly ok: boolean; readonly status: number; json(): Promise<unknown> }>;
	/** Epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
	/** Overrides the default Node `gunzip`-based inflation (e.g. for a non-Node runtime). */
	readonly decompress?: Decompress;
}

/**
 * Build a {@link BitstringRevocationChecker} that fails closed unless the fetched status list's
 * `eddsa-jcs-2022` proof verifies against the pinned issuer's resolved `did:cheqd` key - per
 * spec §5.6 option 2, the proof-based alternative to ledger-anchoring-only trust.
 *
 * `@kya-os/mcp` 1.23.0+: because `verifyStatusList` is always set here, the returned checker
 * MUST be called with a second argument naming the checked credential's issuer -
 * `checker(entry, { credentialIssuer })` - so it can decide that issuer is the keeper of the
 * entry's `statusListCredential` URL (the default, rule-4 case of "status lists held to their
 * credential"). A plain JSON `entry` carries no issuer of its own; omitting the second argument
 * fails closed with a `configuration_error` reason, not a revoked/clear verdict. See
 * `@kya-os/mcp`'s UPGRADING.md, "Status lists held to their credential".
 */
export function createCheqdStatusChecker(options: CheqdStatusCheckerOptions): BitstringRevocationChecker {
	const verifyStatusList = createStatusListProofVerifier({
		// The verifier only reads `.id`, `.assertionMethod` and the public-key fields off each
		// verification method (confirmed by reading `status-list-proof.js`) - never `.type`/
		// `.controller`, which `MinimalDidDocument` doesn't carry. The declared `DIDResolver` type
		// wants them anyway; this cast reflects that the runtime contract is narrower than the
		// published type. @kya-os/mcp 1.23.0+ verifies only a key `assertionMethod` lists - a
		// document that omits it entirely is treated as listing none, so every resolver this
		// option is given MUST state `assertionMethod` for its signing key(s).
		didResolver: { resolve: (did: string) => options.resolveDidCheqd(did) } as never,
	});
	return createRevocationChecker({
		fetch: options.fetch,
		verifyStatusList,
		...(options.now ? { now: options.now } : {}),
		...(options.decompress ? { decompress: options.decompress } : {}),
	});
}
