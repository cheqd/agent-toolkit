// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDidCheqdResolver, createRetrievePublicKey } from '../dist/index.js';

const BASE = 'https://resolver.test/1.0/identifiers';
const DID = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
const KID = `${DID}#key-1`;

function jsonResponse(status, body) {
	return { status, async json() { return body; } };
}

test('resolves a Universal Resolver shaped response ({ didDocument })', async () => {
	const fetch = async (url) => {
		assert.equal(url, `${BASE}/${DID}`);
		return jsonResponse(200, { didDocument: { id: DID, verificationMethod: [{ id: KID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' } }] } });
	};
	const resolve = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	const doc = await resolve(DID);
	assert.equal(doc.id, DID);
	assert.equal(doc.verificationMethod[0].id, KID);
});

test('resolves a raw DID document (no wrapper)', async () => {
	const fetch = async () => jsonResponse(200, { id: DID, verificationMethod: [] });
	const resolve = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	const doc = await resolve(DID);
	assert.equal(doc.id, DID);
});

test('a non-200 response resolves to null, not a throw', async () => {
	const fetch = async () => jsonResponse(404, {});
	const resolve = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	assert.equal(await resolve(DID), null);
});

test('a document whose id does not match the requested DID resolves to null', async () => {
	const fetch = async () => jsonResponse(200, { id: 'did:cheqd:testnet:someone-else', verificationMethod: [] });
	const resolve = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	assert.equal(await resolve(DID), null);
});

test('invalid JSON resolves to null, not a throw', async () => {
	const fetch = async () => ({ status: 200, async json() { throw new SyntaxError('bad json'); } });
	const resolve = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	assert.equal(await resolve(DID), null);
});

test('a non-did:cheqd DID is rejected before any fetch', async () => {
	let called = false;
	const fetch = async () => { called = true; return jsonResponse(200, {}); };
	const resolve = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	assert.equal(await resolve('did:web:example.com'), null);
	assert.equal(called, false);
});

test('a network failure resolves to null, not a throw', async () => {
	const fetch = async () => { throw new Error('ECONNREFUSED'); };
	const resolve = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	assert.equal(await resolve(DID), null);
});

// --- wired into createRetrievePublicKey's opt-in slot ---------------------------------------

test('wired into createRetrievePublicKey: a did:cheqd kid resolves end to end', async () => {
	const fetch = async () => jsonResponse(200, { id: DID, verificationMethod: [{ id: KID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' } }] });
	const resolveDidCheqd = createDidCheqdResolver({ resolverUrl: BASE, fetch });
	const retrieve = createRetrievePublicKey({ resolveDidCheqd });
	const jwk = await retrieve(KID);
	assert.equal(jwk.x, 'abc');
});

test('wired into createRetrievePublicKey: a did:cheqd resolver failure is rejected, not silently skipped', async () => {
	const resolveDidCheqd = createDidCheqdResolver({ resolverUrl: BASE, fetch: async () => jsonResponse(404, {}) });
	const retrieve = createRetrievePublicKey({ resolveDidCheqd });
	await assert.rejects(() => retrieve(KID));
});
