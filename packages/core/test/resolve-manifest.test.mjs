// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { resolveManifest, createManifestCache } from '../dist/index.js';

const NOW = Date.parse('2026-11-03T12:00:00Z');
const DID = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
const RESOURCE_ID = '1a79a313-8fc3-421c-af3d-34730fa046d1';
const BASE = 'https://resolver.test/1.0/identifiers';
const NAME = 'trust-config';
const KIND = 'TrustConfigManifest';

const primitives = {
	sha256Hex: (bytes) => createHash('sha256').update(bytes).digest('hex'),
	decodeUtf8: (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
};

function world(content, opts = {}) {
	const bytes = Buffer.from(JSON.stringify(content));
	const checksum = opts.checksum ?? createHash('sha256').update(bytes).digest('hex');
	const linked = {
		resourceId: RESOURCE_ID, resourceName: NAME, resourceType: KIND,
		resourceVersion: '2026-11-01T00:00:00Z', checksum, nextVersionId: null,
		...opts.linked,
	};
	const meta = {
		dereferencingMetadata: { retrieved: new Date(opts.retrievedAt ?? NOW).toISOString() },
		contentMetadata: { linkedResourceMetadata: opts.linkedList ?? [linked] },
	};
	return { meta, bytes };
}

function fetchFor(w) {
	let calls = 0;
	const fn = async (url) => {
		calls++;
		if (url.includes('resourceMetadata=true')) return { status: 200, body: Buffer.from(JSON.stringify(w.meta)) };
		if (url.includes('/resources/')) return { status: 200, body: w.bytes };
		return { status: 404, body: new Uint8Array() };
	};
	fn.calls = () => calls;
	return fn;
}

test('resolves a well-formed manifest and checks the checksum', async () => {
	const w = world({ acceptedIssuers: ['did:cheqd:testnet:abc'] });
	const result = await resolveManifest(DID, KIND, NAME, { resolvers: [BASE], fetch: fetchFor(w), primitives, now: () => NOW });
	assert.equal(result.ok, true);
	assert.deepEqual(result.content, { acceptedIssuers: ['did:cheqd:testnet:abc'] });
	assert.equal(result.resourceId, RESOURCE_ID);
});

test('a checksum that does not match the bytes is rejected', async () => {
	const w = world({ a: 1 }, { checksum: '0'.repeat(64) });
	const result = await resolveManifest(DID, KIND, NAME, { resolvers: [BASE], fetch: fetchFor(w), primitives, now: () => NOW });
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('checksum_mismatch'));
});

test('the wrong manifest kind at the same name is rejected', async () => {
	const w = world({ a: 1 }, { linked: { resourceType: 'CapabilityManifest' } });
	const result = await resolveManifest(DID, KIND, NAME, { resolvers: [BASE], fetch: fetchFor(w), primitives, now: () => NOW });
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('resource_mismatch'));
});

test('a stale resolver reply is rejected', async () => {
	const w = world({ a: 1 }, { retrievedAt: NOW - 10 * 60_000 });
	const result = await resolveManifest(DID, KIND, NAME, { resolvers: [BASE], fetch: fetchFor(w), primitives, now: () => NOW });
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('resolver_stale'));
});

test('a non-latest version is rejected', async () => {
	const w = world({ a: 1 }, { linked: { nextVersionId: 'something-newer-exists' } });
	const result = await resolveManifest(DID, KIND, NAME, { resolvers: [BASE], fetch: fetchFor(w), primitives, now: () => NOW });
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('not_latest_version'));
});

test('an oversized resource is rejected without being parsed', async () => {
	const w = world({ a: 1 });
	const result = await resolveManifest(DID, KIND, NAME, { resolvers: [BASE], fetch: fetchFor(w), primitives, now: () => NOW, maxBytes: 1 });
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('resource_too_large'));
});

test('http resolvers are refused unless explicitly allowed', async () => {
	const w = world({ a: 1 });
	const result = await resolveManifest(DID, KIND, NAME, { resolvers: ['http://resolver.test/1.0/identifiers'], fetch: fetchFor(w), primitives, now: () => NOW });
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('resolver_not_https'));
});

// --- createManifestCache -------------------------------------------------------------------

test('the cache serves a fresh entry without re-fetching', async () => {
	const w = world({ a: 1 });
	const fetch = fetchFor(w);
	const cache = createManifestCache({ resolvers: [BASE], fetch, primitives, now: () => NOW, defaultTtlMs: 60_000 });
	await cache.get(DID, KIND, NAME);
	await cache.get(DID, KIND, NAME);
	assert.equal(fetch.calls(), 2); // metadata + resource, once - the second get() hit the cache
});

test('the cache re-fetches once the per-kind TTL has elapsed', async () => {
	const w = world({ a: 1 });
	const fetch = fetchFor(w);
	let clock = NOW;
	const cache = createManifestCache({
		resolvers: [BASE], fetch, primitives, now: () => clock,
		ttlMsByKind: { [KIND]: 1000 },
	});
	await cache.get(DID, KIND, NAME);
	clock += 2000;
	await cache.get(DID, KIND, NAME);
	assert.equal(fetch.calls(), 4); // two full resolutions (metadata + resource each)
});

test('a failed resolution is cached too, so a down resolver is not hammered within the TTL', async () => {
	let calls = 0;
	const fetch = async () => { calls++; return { status: 503, body: new Uint8Array() }; };
	const cache = createManifestCache({ resolvers: [BASE], fetch, primitives, now: () => NOW, defaultTtlMs: 60_000 });
	const first = await cache.get(DID, KIND, NAME);
	const second = await cache.get(DID, KIND, NAME);
	assert.equal(first.ok, false);
	assert.deepEqual(first, second);
	assert.equal(calls, 1);
});

test('clear() drops cached entries', async () => {
	const w = world({ a: 1 });
	const fetch = fetchFor(w);
	const cache = createManifestCache({ resolvers: [BASE], fetch, primitives, now: () => NOW, defaultTtlMs: 60_000 });
	await cache.get(DID, KIND, NAME);
	cache.clear();
	await cache.get(DID, KIND, NAME);
	assert.equal(fetch.calls(), 4);
});
