// SPDX-License-Identifier: Apache-2.0
// Unit tests for verifyTrustExtension/createTrustExtensionCache: fakes resolveDidDocument,
// manifestCache and checkStatus directly rather than exercising @cheqd/agent-identity's own
// building blocks again (those are tested in packages/core).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyTrustExtension, createTrustExtensionCache } from '../dist/index.js';
import { createManifestCache } from '@cheqd/agent-identity';

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

// Regression: createTrustExtensionCache used to be an unbounded Map - every (canonicalDid,
// activation) lookup cached its result forever, regardless of outcome. A caller presenting a
// fresh self-asserted DID per request (cheap: one keypair) and failing the trust check every
// time would grow the cache without bound - a memory-exhaustion DoS vector. maxEntries caps the
// entry count, evicting the oldest entry to make room for a new key.
test('the cache is bounded: distinct canonicalDids beyond maxEntries evict the oldest, never growing past the cap', async () => {
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
		checkStatus: async () => ({ revoked: false, fresh: true }),
	};
	const cache = createTrustExtensionCache(deps, { maxEntries: 3 });
	for (let i = 0; i < 10; i++) {
		await cache.get(`did:example:caller-${i}`, { statusCheck: 'required' });
		assert.ok(cache.size() <= 3, `size ${cache.size()} exceeded maxEntries after caller-${i}`);
	}
	assert.equal(cache.size(), 3);
});

// Every test above exercises exactly one check with a faked dependency - never reciprocal
// linkage, manifest resolution and status all declared together, and never against the real
// @cheqd/agent-identity building blocks (verifyReciprocalLinkage, createManifestCache's real
// resolveManifest) rather than a mock standing in for them. This closes that gap: `did`
// discovery - linkage, a real checksummed DID-Linked Resource manifest, and status - run as one
// real flow, only the HTTP resolver and status checker faked (the two genuinely
// deployment-specific seams), matching the shape a real verifier actually calls
// `verifyTrustExtension` with.
test('a full discovery flow - real linkage check, real manifest resolution, status - together', async () => {
	const didDocs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [CANONICAL] },
	};
	const manifestContent = { acceptedIssuers: [CANONICAL] };
	const manifestBytes = Buffer.from(JSON.stringify(manifestContent));
	const resourceId = '1a79a313-8fc3-421c-af3d-34730fa046d1';
	const resolverBase = 'https://resolver.test/1.0/identifiers';
	const manifestMeta = {
		dereferencingMetadata: { retrieved: new Date().toISOString() },
		contentMetadata: {
			linkedResourceMetadata: [
				{
					resourceId,
					// Must match ANCHORED's own method-specific-id (collectionIdOf) - resolveManifest now
					// binds the resolved resource to the DID's own collection, not merely to a matching
					// (kind, name) pair.
					resourceCollectionId: ANCHORED.split(':').pop(),
					resourceName: 'trust-config',
					resourceType: 'TrustConfigManifest',
					resourceVersion: '2026-11-01T00:00:00Z',
					checksum: createHash('sha256').update(manifestBytes).digest('hex'),
					nextVersionId: null,
				},
			],
		},
	};
	const fetchManifest = async (url) => {
		if (url.includes('resourceMetadata=true')) return { status: 200, body: Buffer.from(JSON.stringify(manifestMeta)) };
		if (url.includes('/resources/')) return { status: 200, body: manifestBytes };
		return { status: 404, body: new Uint8Array() };
	};

	// The real manifest cache/resolver from @cheqd/agent-identity, not a mock standing in for it.
	const manifestCache = createManifestCache({
		resolvers: [resolverBase],
		fetch: fetchManifest,
		primitives: {
			sha256Hex: (bytes) => createHash('sha256').update(bytes).digest('hex'),
			decodeUtf8: (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
		},
	});

	let statusChecked = false;
	const deps = {
		resolveDidDocument: async (did) => didDocs[did] ?? null,
		manifestCache,
		checkStatus: async (canonicalDid) => {
			statusChecked = true;
			assert.equal(canonicalDid, CANONICAL);
			return { revoked: false, fresh: true };
		},
	};

	const result = await verifyTrustExtension(
		CANONICAL,
		{
			anchoredDid: ANCHORED,
			trustConfigRef: `${ANCHORED}?resourceName=trust-config&resourceType=TrustConfigManifest`,
			statusCheck: 'required',
		},
		deps,
	);

	assert.deepEqual(result, { ok: true });
	assert.equal(statusChecked, true);
});

test('the same real flow fails closed when the manifest checksum does not match the fetched bytes', async () => {
	const didDocs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [CANONICAL] },
	};
	const manifestBytes = Buffer.from(JSON.stringify({ a: 1 }));
	const resolverBase = 'https://resolver.test/1.0/identifiers';
	const manifestMeta = {
		dereferencingMetadata: { retrieved: new Date().toISOString() },
		contentMetadata: {
			linkedResourceMetadata: [
				{
					resourceId: '1a79a313-8fc3-421c-af3d-34730fa046d1',
					// Must match ANCHORED's own method-specific-id - see the other test's identical
					// comment above.
					resourceCollectionId: ANCHORED.split(':').pop(),
					resourceName: 'trust-config',
					resourceType: 'TrustConfigManifest',
					resourceVersion: '2026-11-01T00:00:00Z',
					checksum: '0'.repeat(64), // wrong, on purpose
					nextVersionId: null,
				},
			],
		},
	};
	const fetchManifest = async (url) => {
		if (url.includes('resourceMetadata=true')) return { status: 200, body: Buffer.from(JSON.stringify(manifestMeta)) };
		if (url.includes('/resources/')) return { status: 200, body: manifestBytes };
		return { status: 404, body: new Uint8Array() };
	};
	const manifestCache = createManifestCache({
		resolvers: [resolverBase],
		fetch: fetchManifest,
		primitives: {
			sha256Hex: (bytes) => createHash('sha256').update(bytes).digest('hex'),
			decodeUtf8: (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
		},
	});
	const deps = {
		resolveDidDocument: async (did) => didDocs[did] ?? null,
		manifestCache,
		checkStatus: async () => ({ revoked: false, fresh: true }),
	};

	const result = await verifyTrustExtension(
		CANONICAL,
		{ anchoredDid: ANCHORED, trustConfigRef: `${ANCHORED}?resourceName=trust-config&resourceType=TrustConfigManifest`, statusCheck: 'required' },
		deps,
	);

	assert.equal(result.ok, false);
	assert.ok(result.reasons.some((r) => r.includes('checksum')));
});
