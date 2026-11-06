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
	const resolveDidDocument = async (did) => (did === DID ? { id: DID, verificationMethod: [{ id: KID, publicKeyJwk }] } : null);
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
