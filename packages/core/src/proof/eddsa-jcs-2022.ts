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
import { keyFromDocument, type MinimalDidDocument } from '../agent-card/retrieve-public-key.js';

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

/**
 * Verify `document`'s `DataIntegrityProof`/`eddsa-jcs-2022` proof. `resolveDidDocument` resolves
 * the DID the proof's `verificationMethod` names - the caller decides which resolver(s) to trust
 * (e.g. `createDidCheqdResolver`, or an in-memory map for `did:web`). Fails closed: any
 * malformed, mismatched or unverifiable input returns `false`, never throws past this boundary.
 */
export async function verifyEddsaJcs2022(document: unknown, resolveDidDocument: (did: string) => Promise<MinimalDidDocument | null>): Promise<boolean> {
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

		const issuer = issuerOf(document);
		const did = verificationMethod.split('#')[0];
		if (issuer === undefined || did !== issuer) return false;

		const signature = base58Decode(proofValue.slice(1), MAX_PROOF_VALUE_BASE58_LEN);
		if (signature.length !== 64) return false;

		const didDocument = await resolveDidDocument(did);
		if (!didDocument) return false;
		let jwk: Record<string, unknown>;
		try {
			jwk = keyFromDocument(didDocument, verificationMethod);
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
