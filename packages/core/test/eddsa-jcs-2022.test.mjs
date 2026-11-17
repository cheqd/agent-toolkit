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

function sign(document, verificationMethod, privateKey, extraProofOptions = {}) {
	const proofOptions = {
		type: 'DataIntegrityProof',
		cryptosuite: 'eddsa-jcs-2022',
		created: new Date().toISOString(),
		verificationMethod,
		proofPurpose: 'assertionMethod',
		...extraProofOptions,
	};
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
					verificationMethod: [
						{ id: KID, type: 'JsonWebKey2020', controller: 'did:web:someone-else.example', publicKeyJwk },
					],
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
		did === DID
			? { id: DID, verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: DID, publicKeyJwk }] }
			: null;
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

// Regression: this verifier never checked that the resolved document's own `id` equals the DID
// it asked `resolveDidDocument` to resolve - it relied entirely on the INJECTED resolver already
// having enforced that. A lax/buggy resolver can return a document for a DIFFERENT DID than the
// one requested; if that document's `id` field equals its own (different) DID but it carries an
// absolute-id `assertionMethod` entry naming the REQUESTED did's kid with a `controller` equal to
// its own `id`, every existing check (controller === document.id, assertionMethod membership)
// passes even though the document resolved does not actually belong to the DID being verified.
test('a resolver returning a document for a different DID than requested fails, even if that document carries an absolute assertionMethod entry matching the requested kid', async () => {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: publicKey.export({ format: 'jwk' }).x };
	const OTHER_DID = 'did:web:other.example';
	// Buggy/lax resolver: asked to resolve DID, returns a document whose own id is OTHER_DID, but
	// which (maliciously or by misconfiguration) names the requested kid, absolutely, under its
	// assertionMethod relationship, with a verificationMethod entry whose id is also absolute
	// (so methodId() does not re-derive it from document.id) and whose controller is OTHER_DID.
	const resolveDidDocument = async (requestedDid) =>
		requestedDid === DID
			? {
					id: OTHER_DID,
					verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: OTHER_DID, publicKeyJwk }],
					assertionMethod: [KID],
				}
			: null;
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

// Regression: proof.expires was ignored entirely - an expired proof verified as if it were
// still valid. `expires` must be included in the SIGNED proof options (not spliced in
// afterwards), otherwise changing the proof after signing would merely break the signature
// rather than exercise the new expiry check.
test('a proof with an expires timestamp in the past fails even though the signature is valid', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey, {
		expires: '2000-01-01T00:00:00.000Z',
	});
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

// Regression: an unparseable proof.expires must fail CLOSED (treated as invalid/expired), not
// fail OPEN (treated as "not yet expired") - Date.parse() of a malformed string is NaN, and every
// comparison against NaN is false, so a naive `Date.parse(expires) <= now()` check alone would
// silently accept this. See PR #43 for the same class of bug in ledger-anchored.ts.
test('a proof with an unparseable expires fails closed, not open', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey, { expires: 'not-a-date' });
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

// Regression: proof.created was ignored entirely - a proof claiming to have been created in the
// future (clock skew abuse, or a forged timestamp) verified anyway.
test('a proof with a created timestamp in the future fails', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey, {
		created: '2999-01-01T00:00:00.000Z',
	});
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

// Regression: same fail-closed-on-NaN requirement as expires, for created.
test('a proof with an unparseable created fails closed, not open', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey, { created: 'not-a-date' });
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), false);
});

// A still-valid expires (in the future) must not break the existing happy path.
test('a proof with a future expires still verifies', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey, {
		expires: '2999-01-01T00:00:00.000Z',
	});
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument), true);
});

// An injected clock lets tests control "now" deterministically instead of racing the system clock.
// `created` is pinned to a fixed past instant (rather than the real wall-clock `sign()` would
// otherwise stamp it with) so both injected "now"s below sit after it, isolating the assertion to
// the `expires` check.
test('an injected now() is used to evaluate expires/created', async () => {
	const { privateKey, resolveDidDocument } = world();
	const document = sign({ issuer: DID, value: 'hello' }, KID, privateKey, {
		created: '2019-01-01T00:00:00.000Z',
		expires: '2020-06-01T00:00:00.000Z',
	});
	const beforeExpiry = () => Date.parse('2020-01-01T00:00:00.000Z');
	const afterExpiry = () => Date.parse('2020-12-01T00:00:00.000Z');
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument, { now: beforeExpiry }), true);
	assert.equal(await verifyEddsaJcs2022(document, resolveDidDocument, { now: afterExpiry }), false);
});
