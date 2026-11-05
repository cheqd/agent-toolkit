/**
 * SD-JWT-VC + Key Binding JWT verification for an AP2 open mandate presentation, using
 * `@sd-jwt/core` (RFC 9901) for the SD-JWT/KB-JWT crypto layer. Deliberately does NOT port
 * AP2's own `~~`-joined multi-hop delegation-chain protocol (`mandate.py`/`chain.py`/
 * `kb_sd_jwt.py` - an unratified Google draft, not RFC 9901 itself); see README for why.
 *
 * Instead this covers the single-delegation-hop case documented directly in AP2's own
 * `models/mandate.py` (`PaymentMandate.user_authorization` docstring): the holder presents the
 * open mandate with a Key Binding JWT whose `transaction_data` claim carries secure hashes of
 * the specific closed mandate content (PaymentMandateContents / Checkout) being authorised.
 * That is exactly what an autonomous-payment agent needs for its OWN transaction; agent-to-
 * sub-agent re-delegation (the deeper `~~`-chain case) is out of scope here.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { SDJwtInstance } from '@sd-jwt/core';
import type { Hasher, KbVerifier, Verifier } from '@sd-jwt/core';
import type { OpenCheckoutMandate, OpenPaymentMandate } from './types.js';

/** SHA-256 hasher, the only algorithm this package verifies (matching the rest of this
 * monorepo's consistent SHA-256/Ed25519 posture). */
export const sha256Hasher: Hasher = (data, alg) => {
	if (alg.toLowerCase() !== 'sha-256') throw new Error(`unsupported_hash_alg: ${alg}`);
	const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
	return new Uint8Array(createHash('sha256').update(bytes).digest());
};

/** Verify a compact-JWT signing input against a pinned public JWK. Supports EdDSA (Ed25519) and
 * ES256 (P-256) - the two algorithms KYA-OS's own proof profile allows (spec §4.1's `alg`
 * allow-list), so AP2 verification stays consistent with the rest of this programme. */
export function jwkVerifier(jwk: Record<string, unknown>): Verifier {
	return (data, sig) => verifyCompactSignature(jwk, data, sig);
}

function verifyCompactSignature(jwk: Record<string, unknown>, data: string, sig: string): boolean {
	const kty = jwk['kty'];
	const key = createPublicKey({ key: jwk as never, format: 'jwk' });
	const dataBytes = Buffer.from(data, 'utf8');
	const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
	try {
		if (kty === 'OKP') return cryptoVerify(null, dataBytes, key, sigBytes);
		if (kty === 'EC') return cryptoVerify('sha256', dataBytes, { key, dsaEncoding: 'ieee-p1363' }, sigBytes);
		return false;
	} catch {
		return false;
	}
}

/** Verifies the Key Binding JWT's signature against the issuer-signed payload's own `cnf.jwk` -
 * the RFC 7800 key-continuity check. Does not itself compare against any externally-expected
 * key; see `cnf-fusion.ts` for the thumbprint comparison against the resolved agent key. */
export const cnfBoundKbVerifier: KbVerifier = (data, sig, payload) => {
	const cnf = payload['cnf'];
	if (typeof cnf !== 'object' || cnf === null) return false;
	const jwk = (cnf as Record<string, unknown>)['jwk'];
	if (typeof jwk !== 'object' || jwk === null) return false;
	return verifyCompactSignature(jwk as Record<string, unknown>, data, sig);
};

export interface VerifyOpenMandateOptions {
	readonly token: string;
	/** The issuer's (the user's) public JWK that signed the open mandate - resolved and pinned
	 * by the caller, never taken from the token itself. */
	readonly issuerPublicJwk: Record<string, unknown>;
	readonly expectedAudience: string;
	readonly expectedNonce: string;
	/** Clock-skew tolerance in seconds for iat/exp and KB-JWT max-age checks. Default 60. */
	readonly skewSeconds?: number;
	/** Current time override for deterministic tests. Epoch seconds. */
	readonly currentDate?: number;
}

export interface VerifiedOpenMandatePresentation<Payload> {
	readonly payload: Payload;
	/** The KB-JWT's own payload, including `transaction_data` if present. */
	readonly keyBinding: { readonly aud: string; readonly nonce: string; readonly iat: number; readonly transaction_data?: readonly string[] };
	/** The `cnf.jwk` the KB-JWT was bound to - feed this to `cnf-fusion.ts`. */
	readonly cnfJwk: Record<string, unknown>;
}

async function verifyOpenMandate<Payload extends { cnf: { jwk: Record<string, unknown> } }>(
	options: VerifyOpenMandateOptions,
): Promise<VerifiedOpenMandatePresentation<Payload>> {
	const instance = new SDJwtInstance<Record<string, unknown>>({
		hasher: sha256Hasher,
		verifier: jwkVerifier(options.issuerPublicJwk),
		kbVerifier: cnfBoundKbVerifier,
	});
	const result = await instance.verify(options.token, {
		keyBindingNonce: options.expectedNonce,
		expectedKeyBindingAudience: options.expectedAudience,
		skewSeconds: options.skewSeconds ?? 60,
		...(options.currentDate !== undefined ? { currentDate: options.currentDate } : {}),
	});
	const payload = result.payload as unknown as Payload;
	const kb = (result as { kb?: { payload: Record<string, unknown> } }).kb;
	if (!kb) throw new Error('missing_key_binding_jwt');
	if (kb.payload['aud'] !== options.expectedAudience) throw new Error('key_binding_audience_mismatch');
	const transactionData = kb.payload['transaction_data'];
	return {
		payload,
		keyBinding: {
			aud: kb.payload['aud'] as string,
			nonce: kb.payload['nonce'] as string,
			iat: kb.payload['iat'] as number,
			...(Array.isArray(transactionData) ? { transaction_data: transactionData as readonly string[] } : {}),
		},
		cnfJwk: payload.cnf.jwk,
	};
}

/** Verify a presented `OpenPaymentMandate` (SD-JWT-VC + KB-JWT). */
export function verifyOpenPaymentMandatePresentation(options: VerifyOpenMandateOptions): Promise<VerifiedOpenMandatePresentation<OpenPaymentMandate>> {
	return verifyOpenMandate<OpenPaymentMandate>(options);
}

/** Verify a presented `OpenCheckoutMandate` (SD-JWT-VC + KB-JWT). */
export function verifyOpenCheckoutMandatePresentation(options: VerifyOpenMandateOptions): Promise<VerifiedOpenMandatePresentation<OpenCheckoutMandate>> {
	return verifyOpenMandate<OpenCheckoutMandate>(options);
}

/** Secure hash of closed-mandate content for `transaction_data` binding: base64url(SHA-256(JSON)). */
export function transactionDataHash(closedMandateContent: unknown): string {
	return createHash('sha256').update(JSON.stringify(closedMandateContent), 'utf8').digest('base64url');
}

/** Checks that `transactionDataHash(content)` is one of the KB-JWT's declared `transaction_data`
 * hashes - the binding between the open mandate presentation and a specific closed mandate.
 * Fails closed (`false`) rather than throwing on content that cannot be hashed at all (found by
 * fuzzing: a function or `Symbol` value, neither of which `JSON.stringify` can serialize) -
 * `closedMandateContent` is `unknown` because this checks caller-supplied data, not because any
 * JS value is a meaningful input. */
export function verifyTransactionDataBinding(keyBinding: VerifiedOpenMandatePresentation<unknown>['keyBinding'], closedMandateContent: unknown): boolean {
	const declared = keyBinding.transaction_data ?? [];
	let hash: string;
	try {
		hash = transactionDataHash(closedMandateContent);
	} catch {
		return false;
	}
	return declared.includes(hash);
}
