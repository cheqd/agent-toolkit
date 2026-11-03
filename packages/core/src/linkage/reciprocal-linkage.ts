/**
 * Reciprocal `alsoKnownAs` linkage between two DID documents (e.g. a `did:cheqd` anchoring
 * identity and a `did:web` canonical identity, or any other pair).
 *
 * A one-directional claim - "my `did:cheqd` document's `alsoKnownAs` names this `did:web` DID" -
 * proves nothing on its own: anyone can list any DID in their own document's `alsoKnownAs`.
 * Linkage is only trustworthy when it is RECIPROCAL - each document names the other - because
 * that requires control of BOTH identities, not just the one making the claim.
 *
 * This module only checks the two documents it is given; resolving them is the caller's job
 * (this package's `createRetrievePublicKey` resolves `did:web` and `did:key`; a cheqd resolver is
 * the caller's own, injected elsewhere - consistent with this package's other modules taking
 * already-resolved input rather than owning resolution end to end).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** The subset of a DID document this module reads. */
export interface LinkageDidDocument {
	readonly id: string;
	readonly alsoKnownAs?: readonly string[];
}

export type ReciprocalLinkageResult =
	| { readonly ok: true }
	| { readonly ok: false; readonly reasons: readonly string[] };

/**
 * Check that `a` and `b` each name the other in their own `alsoKnownAs`. Order does not matter.
 * Fails closed: a missing or malformed `alsoKnownAs` on either side, or a one-directional claim,
 * is rejected with a reason - never silently treated as linked.
 */
export function verifyReciprocalLinkage(a: LinkageDidDocument, b: LinkageDidDocument): ReciprocalLinkageResult {
	const reasons: string[] = [];
	if (a.id === b.id) reasons.push('same_did');
	if (!namesDid(a.alsoKnownAs, b.id)) reasons.push('a_does_not_name_b');
	if (!namesDid(b.alsoKnownAs, a.id)) reasons.push('b_does_not_name_a');
	return reasons.length === 0 ? { ok: true } : { ok: false, reasons };
}

function namesDid(alsoKnownAs: readonly string[] | undefined, did: string): boolean {
	return Array.isArray(alsoKnownAs) && alsoKnownAs.includes(did);
}
