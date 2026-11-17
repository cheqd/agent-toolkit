// SPDX-License-Identifier: Apache-2.0
// Tests verifyAgentPaymentKeyCredential and, via it, verifyCnfContinuity's authorised-secondary-
// key tier, against a REAL DataIntegrityProof/eddsa-jcs-2022-signed credential (same
// construction @cheqd/agent-identity's core eddsa-jcs-2022.ts verifies - signed here by hand,
// following status-list-proof.js's algorithm, since core only ships a verifier, not a signer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { generateKeyPair, exportJWK } from 'jose';
import { verifyAgentPaymentKeyCredential, verifyCnfContinuity } from '../dist/index.js';

const PRIMARY_DID = 'did:web:agent.example';
const PRIMARY_KID = `${PRIMARY_DID}#key-1`;

function base58Encode(bytes) {
	const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	if (bytes.length === 0) return '';
	let num = 0n;
	for (const byte of bytes) num = num * 256n + BigInt(byte);
	let out = '';
	while (num > 0n) {
		out = ALPHABET[Number(num % 58n)] + out;
		num /= 58n;
	}
	for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out;
	return out;
}

function signEddsaJcs2022(document, verificationMethod, privateKey) {
	const proofOptions = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: new Date().toISOString(), verificationMethod, proofPurpose: 'assertionMethod' };
	const unsecured = { ...document };
	const options = { ...proofOptions };
	if (unsecured['@context'] !== undefined) options['@context'] = unsecured['@context'];
	const proofHash = createHash('sha256').update(canonicalize(options)).digest();
	const documentHash = createHash('sha256').update(canonicalize(unsecured)).digest();
	const signature = cryptoSign(null, Buffer.concat([proofHash, documentHash]), privateKey);
	return { ...document, proof: { ...proofOptions, proofValue: `z${base58Encode(signature)}` } };
}

async function signedCredential({ primaryPublicKeyJwk, privateKey, paymentKeyJwk, validUntil, validFrom }) {
	const unsigned = {
		'@context': ['https://www.w3.org/ns/credentials/v2'],
		type: ['VerifiableCredential', 'AgentPaymentKeyCredential'],
		issuer: PRIMARY_DID,
		issuanceDate: new Date().toISOString(),
		...(validUntil ? { validUntil } : {}),
		...(validFrom ? { validFrom } : {}),
		credentialSubject: { id: PRIMARY_DID, paymentKeyJwk },
		credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListCredential: 'https://status.example/list', statusListIndex: '0' },
	};
	return { credential: signEddsaJcs2022(unsigned, PRIMARY_KID, privateKey), primaryPublicKeyJwk };
}

function depsFor(primaryPublicKeyJwk, { revoked = false, fresh = true } = {}) {
	return {
		resolveDidDocument: async (did) =>
			did === PRIMARY_DID
				? {
						id: PRIMARY_DID,
						verificationMethod: [{ id: PRIMARY_KID, type: 'JsonWebKey2020', controller: PRIMARY_DID, publicKeyJwk: primaryPublicKeyJwk }],
						assertionMethod: [PRIMARY_KID],
					}
				: null,
		checkRevoked: async () => ({ revoked, fresh }),
	};
}

test('a validly-signed, non-revoked payment key credential verifies', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk });
	const result = await verifyAgentPaymentKeyCredential(credential, PRIMARY_DID, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: true, tier: 'authorised-secondary-key', paymentKeyJwk });
});

test('a tampered credential (paymentKeyJwk swapped after signing) is rejected', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk });
	const tampered = { ...credential, credentialSubject: { ...credential.credentialSubject, paymentKeyJwk: await exportJWK((await generateKeyPair('EdDSA')).publicKey) } };
	const result = await verifyAgentPaymentKeyCredential(tampered, PRIMARY_DID, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: false, reason: 'proof_invalid' });
});

test('a revoked payment key credential is rejected', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk });
	const result = await verifyAgentPaymentKeyCredential(credential, PRIMARY_DID, depsFor(primaryPublicKeyJwk, { revoked: true }));
	assert.deepEqual(result, { ok: false, reason: 'payment_key_revoked' });
});

test('an expired payment key credential is rejected', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk, validUntil: '2020-01-01T00:00:00Z' });
	const result = await verifyAgentPaymentKeyCredential(credential, PRIMARY_DID, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: false, reason: 'credential_expired' });
});

// Regression (M3): Date.parse(validUntil) is NaN for an unparseable string, and every
// comparison against NaN is false - so the old `Date.parse(validUntil) <= now()` check alone
// failed OPEN (treated as not-yet-expired) for a malformed validUntil. Matches the fail-closed
// convention established in packages/core/src/status/ledger-anchored.ts (PR #43).
test('a validUntil that cannot be parsed is rejected, not treated as still valid', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk, validUntil: '31/12/2025' });
	const result = await verifyAgentPaymentKeyCredential(credential, PRIMARY_DID, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: false, reason: 'credential_expired' });
});

// Regression: validFrom was never checked at all, so a credential wasn't yet valid (its
// validity window hasn't started) still verified successfully.
test('a credential whose validFrom is in the future is rejected as not yet valid', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk, validFrom: '2999-01-01T00:00:00Z' });
	const result = await verifyAgentPaymentKeyCredential(credential, PRIMARY_DID, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: false, reason: 'credential_not_yet_valid' });
});

// Regression: a validFrom that cannot be parsed must fail closed too, matching M3's convention
// for validUntil.
test('a validFrom that cannot be parsed is rejected, not treated as already valid', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk, validFrom: '31/12/2025' });
	const result = await verifyAgentPaymentKeyCredential(credential, PRIMARY_DID, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: false, reason: 'credential_not_yet_valid' });
});

test('a credential with no credentialStatus is rejected (fail closed, never optional)', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const unsigned = {
		'@context': ['https://www.w3.org/ns/credentials/v2'],
		type: ['VerifiableCredential', 'AgentPaymentKeyCredential'],
		issuer: PRIMARY_DID,
		credentialSubject: { id: PRIMARY_DID, paymentKeyJwk },
	};
	const credential = signEddsaJcs2022(unsigned, PRIMARY_KID, privateKey);
	const result = await verifyAgentPaymentKeyCredential(credential, PRIMARY_DID, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: false, reason: 'missing_credential_status' });
});

test('verifyCnfContinuity promotes a mandate cnf bound to the authorised secondary key', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);
	const agentGeneralKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk });
	const result = await verifyCnfContinuity(paymentKeyJwk, agentGeneralKeyJwk, PRIMARY_DID, credential, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: true, tier: 'authorised-secondary-key' });
});

test('verifyCnfContinuity rejects a mandate cnf bound to neither the general key nor the authorised payment key', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const primaryPublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const paymentKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);
	const agentGeneralKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);
	const someOtherKeyJwk = await exportJWK((await generateKeyPair('EdDSA', { crv: 'Ed25519' })).publicKey);

	const { credential } = await signedCredential({ privateKey, paymentKeyJwk });
	const result = await verifyCnfContinuity(someOtherKeyJwk, agentGeneralKeyJwk, PRIMARY_DID, credential, depsFor(primaryPublicKeyJwk));
	assert.deepEqual(result, { ok: false, reason: 'cnf_jwk_not_the_authorised_payment_key' });
});
