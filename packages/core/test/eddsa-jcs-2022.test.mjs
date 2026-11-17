// SPDX-License-Identifier: Apache-2.0
// Tests verifyEddsaJcs2022 against a real, hand-signed DataIntegrityProof/eddsa-jcs-2022
// document (same construction as status-list-proof.js's, confirmed in
// evidence/status-list/eddsa-jcs-prototype.mjs; signed here, not imported, since this module is
// a verifier only).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { verifyEddsaJcs2022 } from '../dist/index.js';

const DID = 'did:web:issuer.example';
const KID = `${DID}#key-1`;

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

function sign(document, verificationMethod, privateKey) {
	const proofOptions = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: new Date().toISOString(), verificationMethod, proofPurpose: 'assertionMethod' };
	const proofHash = createHash('sha256').update(canonicalize(proofOptions)).digest();
	const documentHash = createHash('sha256').update(canonicalize(document)).digest();
	const signature = cryptoSign(null, Buffer.concat([proofHash, documentHash]), privateKey);
	return { ...document, proof: { ...proofOptions, proofValue: `z${base58Encode(signature)}` } };
}

function world() {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const resolveDidDocument = async (did) =>
		did === DID
			? {
					id: DID,
					verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: DID, publicKeyJwk }],
					assertionMethod: [KID],
				}
			: null;
	return { privateKey, resolveDidDocument };
}

test('a validly-signed document verifies', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), true);
});

test('a tampered document fails', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	const tampered = { ...document, value: 'tampered' };
	assert.equal(await verifyEddsaJcs2022(tampered, resolveDidDocument), false);
});

test('a verificationMethod belonging to a different DID than issuer fails', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: 'did:web:someone-else.example', value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

test('an unresolvable issuer DID fails', async () => {
	const { privateKey } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, async () => null), false);
});

test('a document with no proof fails', async () => {
	const { resolveDidDocument } = world();
	assert.equal(await verifyEddsaJcs2022({ issuer: DID, value: 'hello' }, resolveDidDocument), false);
});

test('signed by a key not published in the resolved DID document fails', async () => {
	const { privateKey: wrongKey } = generateKeyPairSync('ed25519');
	const { resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, wrongKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

// Regression: this verifier used to accept any key in verificationMethod, never checking that
// the key is actually listed under assertionMethod (W3C Controlled Identifiers v1.0 §3.3). A key
// published only under authentication - a login/session key, not one authorized to make
// assertions - used to verify here; it must not.
test('a key listed only under authentication, not assertionMethod, fails even though it is a valid verificationMethod entry', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const resolveDidDocument = async (did) =>
		did === DID
			? {
					id: DID,
					verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: DID, publicKeyJwk }],
					assertionMethod: [], // explicitly NOT listed here
					authentication: [KID],
				}
			: null;
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

test('a key whose controller is a different DID than the document fails, even if listed under assertionMethod', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const resolveDidDocument = async (did) =>
		did === DID
			? {
					id: DID,
					verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: 'did:web:someone-else.example', publicKeyJwk }],
					assertionMethod: [KID],
				}
			: null;
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

test('a document with no assertionMethod relationship at all fails, even with a matching verificationMethod', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const resolveDidDocument = async (did) =>
		did === DID ? { id: DID, verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: DID, publicKeyJwk }] } : null;
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});
