// SPDX-License-Identifier: Apache-2.0
// Unit tests for verifyTrustExtension/createTrustExtensionCache: fakes resolveDidDocument,
// manifestCache and checkStatus directly rather than exercising @cheqd/agent-identity's own
// building blocks again (those are tested in packages/core).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyTrustExtension, createTrustExtensionCache } from '../dist/index.js';

const CANONICAL = 'did:web:server.example';
const ANCHORED = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';

test('an activation with nothing declared passes trivially', async () => {
	const result = await verifyTrustExtension(CANONICAL, {}, { resolveDidDocument: async () => null, manifestCache: { get: async () => ({ ok: true }), clear() {} } });
	assert.deepEqual(result, { ok: true });
});

test('reciprocal linkage is checked when anchoredDid is declared', async () => {
	const docs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [CANONICAL] },
	};
	const deps = { resolveDidDocument: async (did) => docs[did] ?? null, manifestCache: { get: async () => ({ ok: true }), clear() {} } };
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED }, deps);
	assert.deepEqual(result, { ok: true });
});

test('a one-directional linkage claim fails closed', async () => {
	const docs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [] },
	};
	const deps = { resolveDidDocument: async (did) => docs[did] ?? null, manifestCache: { get: async () => ({ ok: true }), clear() {} } };
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED }, deps);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.some((r) => r.startsWith('linkage_')));
});

test('a manifest resolution failure fails closed', async () => {
	const ref = `${ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	const deps = {
		resolveDidDocument: async () => ({ id: CANONICAL }),
		manifestCache: { get: async () => ({ ok: false, reasons: ['resource_unavailable'] }), clear() {} },
	};
	const result = await verifyTrustExtension(CANONICAL, { trustConfigRef: ref }, deps);
	assert.equal(result.ok, false);
	assert.deepEqual(result.reasons, ['manifest_resource_unavailable']);
});

test('a malformed trustConfigRef fails closed without calling the manifest cache', async () => {
	let called = false;
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: { get: async () => { called = true; return { ok: true }; }, clear() {} },
	};
	const result = await verifyTrustExtension(CANONICAL, { trustConfigRef: 'not-a-ref' }, deps);
	assert.equal(result.ok, false);
	assert.equal(called, false);
});

test('statusCheck required fails closed when no checker is configured', async () => {
	const deps = { resolveDidDocument: async () => null, manifestCache: { get: async () => ({ ok: true }), clear() {} } };
	const result = await verifyTrustExtension(CANONICAL, { statusCheck: 'required' }, deps);
	assert.deepEqual(result, { ok: false, reasons: ['status_check_unavailable'] });
});

test('statusCheck required fails closed on a revoked or stale result', async () => {
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
		checkStatus: async () => ({ revoked: true, fresh: true }),
	};
	const result = await verifyTrustExtension(CANONICAL, { statusCheck: 'required' }, deps);
	assert.deepEqual(result, { ok: false, reasons: ['status_revoked'] });
});

test('statusCheck required passes when the status is clear and fresh', async () => {
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
		checkStatus: async () => ({ revoked: false, fresh: true }),
	};
	const result = await verifyTrustExtension(CANONICAL, { statusCheck: 'required' }, deps);
	assert.deepEqual(result, { ok: true });
});

test('createTrustExtensionCache serves a fresh entry without re-checking', async () => {
	let calls = 0;
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: { get: async () => { calls++; return { ok: true }; }, clear() {} },
	};
	const ref = `${ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	const cache = createTrustExtensionCache(deps, { ttlMs: 60_000 });
	await cache.get(CANONICAL, { trustConfigRef: ref });
	await cache.get(CANONICAL, { trustConfigRef: ref });
	assert.equal(calls, 1);
});

test('createTrustExtensionCache re-checks once the TTL has elapsed', async () => {
	let calls = 0;
	let now = 0;
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: { get: async () => { calls++; return { ok: true }; }, clear() {} },
	};
	const ref = `${ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	const cache = createTrustExtensionCache(deps, { ttlMs: 1000, now: () => now });
	await cache.get(CANONICAL, { trustConfigRef: ref });
	now = 1001;
	await cache.get(CANONICAL, { trustConfigRef: ref });
	assert.equal(calls, 2);
});
