// SPDX-License-Identifier: Apache-2.0
// Tests the StatusListResolver adapter over the same fake-resolver harness as
// ledger-anchored.test.mjs - only the adapter's own mapping (ok -> boolean, !ok -> throw) is new
// here; the underlying check is already covered there.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { createLedgerAnchoredStatusListResolver } from '../dist/index.js';

const NOW = Date.parse('2026-10-13T12:00:00Z');
const COLLECTION = '0c3581f0-011f-4263-b1ca-15ad70d54ede';
const DID = `did:cheqd:testnet:${COLLECTION}`;
const NAME = 'agent-revocations';
const RESOURCE_ID = '1a79a313-8fc3-421c-af3d-34730fa046d1';
const BASE = 'https://resolver.test/1.0/identifiers';
const STATUS = {
	statusListCredential: `${BASE}/${DID}?resourceName=${NAME}&resourceType=BitstringStatusListCredential#41260`,
	statusListIndex: '41260',
	statusPurpose: 'revocation',
};

const primitives = {
	sha256Hex: (bytes) => createHash('sha256').update(bytes).digest('hex'),
	gunzip: (bytes, maxBytes) => gunzipSync(bytes, { maxOutputLength: maxBytes }),
	decodeUtf8: (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
};

function encodeList(entries, setBits = []) {
	const bits = new Uint8Array(entries / 8);
	for (const index of setBits) bits[Math.floor(index / 8)] |= 0x80 >> index % 8;
	return gzipSync(bits).toString('base64url');
}

function world(setBits = []) {
	const credential = {
		'@context': ['https://www.w3.org/2018/credentials/v1'],
		type: ['VerifiableCredential', 'BitstringStatusListCredential'],
		issuer: DID,
		issuanceDate: '2026-10-01T00:00:00Z',
		credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: encodeList(131072, setBits) },
		proof: { type: 'JwtProof2020', jwt: 'header.payload.signature' },
	};
	const record = { bitstringStatusListCredential: credential, metadata: { encrypted: false, encoding: 'base64url', length: 131072, statusSize: 1 } };
	const bytes = Buffer.from(JSON.stringify(record));
	const checksum = createHash('sha256').update(bytes).digest('hex');
	const linked = {
		resourceURI: `${DID}/resources/${RESOURCE_ID}`, resourceCollectionId: COLLECTION, resourceId: RESOURCE_ID,
		resourceName: NAME, resourceType: 'BitstringStatusListCredential', mediaType: 'application/json',
		resourceVersion: '2026-10-01T00:00:00Z', created: '2026-10-01T00:00:00Z', checksum,
		previousVersionId: null, nextVersionId: null,
	};
	const meta = { dereferencingMetadata: { retrieved: new Date(NOW).toISOString() }, contentMetadata: { linkedResourceMetadata: [linked] } };
	return { meta, bytes };
}

function fetchFor(w) {
	return async (url) => {
		if (url.includes('resourceMetadata=true')) return { status: 200, body: Buffer.from(JSON.stringify(w.meta)) };
		if (url.includes('/resources/')) return { status: 200, body: w.bytes };
		return { status: 404, body: new Uint8Array() };
	};
}

test('checkStatus returns true when the bit is set', async () => {
	const resolver = createLedgerAnchoredStatusListResolver({
		expectedIssuerDid: DID, resolvers: [BASE], fetch: fetchFor(world([41260])), primitives, now: () => NOW,
	});
	assert.equal(await resolver.checkStatus(STATUS), true);
});

test('checkStatus returns false when the bit is clear', async () => {
	const resolver = createLedgerAnchoredStatusListResolver({
		expectedIssuerDid: DID, resolvers: [BASE], fetch: fetchFor(world([])), primitives, now: () => NOW,
	});
	assert.equal(await resolver.checkStatus(STATUS), false);
});

test('checkStatus throws (does not return false) when the status is unresolvable', async () => {
	const resolver = createLedgerAnchoredStatusListResolver({
		expectedIssuerDid: DID, resolvers: [BASE], fetch: async () => { throw new Error('network'); }, primitives, now: () => NOW,
	});
	await assert.rejects(() => resolver.checkStatus(STATUS), /ledger_anchored_status_unresolvable/);
});

test('checkStatus throws when the issuer does not match the one this resolver trusts', async () => {
	const resolver = createLedgerAnchoredStatusListResolver({
		expectedIssuerDid: 'did:cheqd:testnet:someone-else', resolvers: [BASE], fetch: fetchFor(world([])), primitives, now: () => NOW,
	});
	await assert.rejects(() => resolver.checkStatus(STATUS), /ledger_anchored_status_unresolvable/);
});
