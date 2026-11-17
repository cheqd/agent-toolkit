/**
 * A generic `DataIntegrityProof`/`eddsa-jcs-2022` verifier for an arbitrary document - the same
 * W3C Data Integrity construction `@kya-os/mcp/card`'s `createStatusListProofVerifier` checks
 * (proof options without `proofValue`, carrying the document's `@context`, and the document
 * without `proof`, each JCS-canonicalized and SHA-256 hashed; Ed25519 over the concatenation;
 * `proofValue` base58btc multibase) and the one `cheqd/did-provider-cheqd#658`'s `signEddsaJcs2022`
 * produces - but generalised to any document carrying a `proof`, not status lists specifically.
 * Reused by `@cheqd/agent-identity-ap2`'s Agent Payment Key Credential verification, so that
 * module does not reimplement this construction a second time.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createHash } from 'node:crypto';
import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import {
	assertionMethodKeyFromDocument,
	type MinimalDidDocument,
} from '../agent-card/retrieve-public-key.js';

const MAX_PROOF_VALUE_BASE58_LEN = 100;
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(input: string, maxLen: number): Uint8Array {
	if (input.length > maxLen) throw new Error('base58_too_long');
	let num = 0n;
	for (const char of input) {
		const index = BASE58_ALPHABET.indexOf(char);
		if (index < 0) throw new Error('invalid_base58_character');
		num = num * 58n + BigInt(index);
	}
	const bytes: number[] = [];
	while (num > 0n) {
		bytes.unshift(Number(num % 256n));
		num /= 256n;
	}
	for (let i = 0; i < input.length && input[i] === '1'; i++) bytes.unshift(0);
	return new Uint8Array(bytes);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function issuerOf(document: Record<string, unknown>): string | undefined {
	const issuer = document['issuer'];
	if (typeof issuer === 'string') return issuer;
	if (isRecord(issuer) && typeof issuer['id'] === 'string') return issuer['id'];
	return undefined;
}

function contexts(value: unknown): unknown[] {
	if (Array.isArray(value)) return value;
	return value === undefined ? [] : [value];
}

export interface VerifyEddsaJcs2022Options {
	/** Injectable clock returning epoch milliseconds (deterministic tests; default `Date.now`).
	 * Used to validate `proof.expires`/`proof.created` when either is present. */
	readonly now?: () => number;
}

/**
 * Verify `document`'s `DataIntegrityProof`/`eddsa-jcs-2022` proof. `resolveDidDocument` resolves
 * the DID the proof's `verificationMethod` names - the caller decides which resolver(s) to trust
 * (e.g. `createDidCheqdResolver`, or an in-memory map for `did:web`). Fails closed: any
 * malformed, mismatched or unverifiable input returns `false`, never throws past this boundary.
 *
 * `proof.expires`/`proof.created` are optional on the underlying data model and are validated
 * only when present, against `options.now()`: an `expires` at or before now, or a `created` after
 * now, fails - as does either field being present but not a parseable date string. An unparseable
 * value fails CLOSED (treated as invalid), never open (treated as "not yet expired"/"not in the
 * future") - `Date.parse()` of a malformed string is `NaN`, and every comparison against `NaN` is
 * `false`, so a naive `Date.parse(x) <= now()` alone would silently accept it.
 */
export async function verifyEddsaJcs2022(
	document: unknown,
	resolveDidDocument: (did: string) => Promise<MinimalDidDocument | null>,
	options: VerifyEddsaJcs2022Options = {},
): Promise<boolean> {
	const now = options.now ?? Date.now;
	try {
		if (!isRecord(document)) return false;
		const proof = document['proof'];
		if (!isRecord(proof)) return false;
		if (proof['type'] !== 'DataIntegrityProof' || proof['cryptosuite'] !== 'eddsa-jcs-2022') return false;
		if (proof['proofPurpose'] !== 'assertionMethod') return false;
		const proofValue = proof['proofValue'];
		const verificationMethod = proof['verificationMethod'];
		if (typeof proofValue !== 'string' || !proofValue.startsWith('z')) return false;
		if (typeof verificationMethod !== 'string') return false;

		const expires = proof['expires'];
		if (expires !== undefined) {
			if (typeof expires !== 'string') return false;
			const expiresAt = Date.parse(expires);
			if (Number.isNaN(expiresAt) || expiresAt <= now()) return false;
		}
		const created = proof['created'];
		if (created !== undefined) {
			if (typeof created !== 'string') return false;
			const createdAt = Date.parse(created);
			if (Number.isNaN(createdAt) || createdAt > now()) return false;
		}

		const issuer = issuerOf(document);
		const did = verificationMethod.split('#')[0];
		if (issuer === undefined || did !== issuer) return false;

		const signature = base58Decode(proofValue.slice(1), MAX_PROOF_VALUE_BASE58_LEN);
		if (signature.length !== 64) return false;

		const didDocument = await resolveDidDocument(did);
		if (!didDocument) return false;
		// The injected resolver decides which DID(s) it trusts and how it resolves them, but
		// nothing about this module's own correctness may depend on it having already enforced
		// that the document it returns actually belongs to the DID it was asked to resolve. A lax
		// or buggy resolver (e.g. a simple in-memory map used in tests) could return a document for
		// a DIFFERENT DID than `did`, whose absolute-id assertionMethod entries would otherwise
		// incorrectly pass `assertionMethodKeyFromDocument`'s own controller === document.id check.
		if (didDocument.id !== did) return false;
		let jwk: Record<string, unknown>;
		try {
			// MUST be a key the document's own assertionMethod relationship publishes, with a
			// controller equal to the issuer - checking proof.proofPurpose === 'assertionMethod'
			// above says what the PROOF claims; it says nothing about whether the key the
			// proof names is actually authorized to make that claim. A key listed only under
			// verificationMethod (or another relationship such as authentication) MUST NOT
			// verify here, even though it would resolve via the generic Agent Card key lookup.
			jwk = assertionMethodKeyFromDocument(didDocument, verificationMethod);
		} catch {
			return false;
		}
		if (jwk['kty'] !== 'OKP' || jwk['crv'] !== 'Ed25519') return false;

		const unsecured: Record<string, unknown> = { ...document };
		delete unsecured['proof'];
		const options: Record<string, unknown> = { ...proof };
		delete options['proofValue'];
		if (options['@context'] !== undefined) {
			const documentContexts = contexts(document['@context']).map((c) => canonicalize(c));
			const optionsContexts = contexts(options['@context']).map((c) => canonicalize(c));
			if (optionsContexts.length > documentContexts.length) return false;
			if (!optionsContexts.every((c, i) => c === documentContexts[i])) return false;
			unsecured['@context'] = options['@context'];
		}
		if (unsecured['@context'] !== undefined) options['@context'] = unsecured['@context'];

		const proofHash = createHash('sha256').update(canonicalize(options)).digest();
		const documentHash = createHash('sha256').update(canonicalize(unsecured)).digest();
		const signingInput = Buffer.concat([proofHash, documentHash]);

		const publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
		return cryptoVerify(null, signingInput, publicKey, signature);
	} catch {
		return false;
	}
}
