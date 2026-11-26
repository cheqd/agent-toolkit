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
	const result = await verifyTrustExtension(
		CANONICAL,
		{},
		{ resolveDidDocument: async () => null, manifestCache: { get: async () => ({ ok: true }), clear() {} } },
	);
	assert.deepEqual(result, { ok: true });
});

test('reciprocal linkage is checked when anchoredDid is declared', async () => {
	const docs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [CANONICAL] },
	};
	const deps = {
		resolveDidDocument: async (did) => docs[did] ?? null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
	};
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED }, deps);
	assert.deepEqual(result, { ok: true });
});

test('a one-directional linkage claim fails closed', async () => {
	const docs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [] },
	};
	const deps = {
		resolveDidDocument: async (did) => docs[did] ?? null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
	};
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED }, deps);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.some((r) => r.startsWith('linkage_')));
});

test('a manifest resolution failure fails closed', async () => {
	const ref = `${ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	const deps = {
		// did-aware and reciprocal, so the (now-enforced) linkage checks pass trivially and the
		// only failure surfacing is the manifest one this test is about.
		resolveDidDocument: async (did) => ({ id: did, alsoKnownAs: [did === CANONICAL ? ANCHORED : CANONICAL] }),
		manifestCache: { get: async () => ({ ok: false, reasons: ['resource_unavailable'] }), clear() {} },
	};
	// anchoredDid must be declared (and match the ref's did) now that trustConfigRef is bound to it.
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED, trustConfigRef: ref }, deps);
	assert.equal(result.ok, false);
	assert.deepEqual(result.reasons, ['manifest_resource_unavailable']);
});

test('a malformed trustConfigRef fails closed without calling the manifest cache', async () => {
	let called = false;
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: {
			get: async () => {
				called = true;
				return { ok: true };
			},
			clear() {},
		},
	};
	const result = await verifyTrustExtension(CANONICAL, { trustConfigRef: 'not-a-ref' }, deps);
	assert.equal(result.ok, false);
	assert.equal(called, false);
});

test('statusCheck required fails closed when no checker is configured', async () => {
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
	};
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
		manifestCache: {
			get: async () => {
				calls++;
				return { ok: true };
			},
			clear() {},
		},
	};
	const ref = `${ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	const cache = createTrustExtensionCache(deps, { ttlMs: 60_000 });
	// anchoredDid must match the ref's did now that trustConfigRef is bound to it.
	await cache.get(CANONICAL, { anchoredDid: ANCHORED, trustConfigRef: ref });
	await cache.get(CANONICAL, { anchoredDid: ANCHORED, trustConfigRef: ref });
	assert.equal(calls, 1);
});

test('createTrustExtensionCache re-checks once the TTL has elapsed', async () => {
	let calls = 0;
	let now = 0;
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: {
			get: async () => {
				calls++;
				return { ok: true };
			},
			clear() {},
		},
	};
	const ref = `${ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	const cache = createTrustExtensionCache(deps, { ttlMs: 1000, now: () => now });
	// anchoredDid must match the ref's did now that trustConfigRef is bound to it.
	await cache.get(CANONICAL, { anchoredDid: ANCHORED, trustConfigRef: ref });
	now = 1001;
	await cache.get(CANONICAL, { anchoredDid: ANCHORED, trustConfigRef: ref });
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
		if (url.includes('resourceMetadata=true'))
			return { status: 200, body: Buffer.from(JSON.stringify(manifestMeta)) };
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
		if (url.includes('resourceMetadata=true'))
			return { status: 200, body: Buffer.from(JSON.stringify(manifestMeta)) };
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
		{
			anchoredDid: ANCHORED,
			trustConfigRef: `${ANCHORED}?resourceName=trust-config&resourceType=TrustConfigManifest`,
			statusCheck: 'required',
		},
		deps,
	);

	assert.equal(result.ok, false);
	assert.ok(result.reasons.some((r) => r.includes('checksum')));
});

// Regression: verifyTrustExtension used to trust `resolveDidDocument`'s result purely on the
// basis that SOMETHING resolved - verifyReciprocalLinkage only compares the two returned
// documents against each other, never against the DIDs actually requested. A lax/generic
// resolver (e.g. over did:web, unlike core's own did:cheqd resolver which binds the id itself)
// could return a document whose `id` names the OTHER party's DID - e.g. an attacker's did:web
// document declaring `id: <victim's anchored DID>` - and inherit that victim's linkage. Each
// resolved document's own `id` must equal the DID this module actually asked for.
test('a resolved document whose id does not match the requested DID fails closed, even with otherwise-valid reciprocal alsoKnownAs', async () => {
	const ATTACKER_CANONICAL = 'did:web:attacker.example';
	// The attacker's resolver returns a document claiming the VICTIM's canonical DID as its own
	// id, with alsoKnownAs pointing at ANCHORED - reciprocal with ANCHORED's own document, so
	// verifyReciprocalLinkage alone would accept this.
	const docs = {
		[ATTACKER_CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [CANONICAL] },
	};
	const deps = {
		resolveDidDocument: async (did) => docs[did] ?? null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
	};
	const result = await verifyTrustExtension(ATTACKER_CANONICAL, { anchoredDid: ANCHORED }, deps);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('linkage_resolved_doc_id_mismatch'));
});

test('a resolved anchored document whose id does not match activation.anchoredDid fails closed', async () => {
	const docs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		// Resolver answers for ANCHORED's DID but hands back a document claiming to be some
		// other DID entirely.
		[ANCHORED]: { id: 'did:cheqd:testnet:00000000-0000-0000-0000-000000000000', alsoKnownAs: [CANONICAL] },
	};
	const deps = {
		resolveDidDocument: async (did) => docs[did] ?? null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
	};
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED }, deps);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('linkage_resolved_doc_id_mismatch'));
});

// Regression: the manifest check only verified that `trustConfigRef`'s did:cheqd resolved with
// a matching checksum - never that it belonged to the right DID. An attacker who is not
// `ANCHORED` at all could declare a `trustConfigRef` pointing at a third-party DID's
// perfectly-valid manifest and have it accepted as if it were the caller's own trust config.
test('a trustConfigRef pointing at a DID other than anchoredDid fails closed without calling the manifest cache', async () => {
	const OTHER_DID = 'did:cheqd:testnet:11111111-1111-1111-1111-111111111111';
	const ref = `${OTHER_DID}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	let called = false;
	const deps = {
		resolveDidDocument: async (did) => ({ id: did, alsoKnownAs: [did === CANONICAL ? ANCHORED : CANONICAL] }),
		manifestCache: {
			get: async () => {
				called = true;
				return { ok: true };
			},
			clear() {},
		},
	};
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED, trustConfigRef: ref }, deps);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('manifest_did_mismatch'));
	assert.equal(called, false);
});

// Same binding, no anchoredDid declared: the manifest must then belong to the canonical DID
// itself (there is no other DID this check is being run for).
test('a trustConfigRef pointing at a DID other than canonicalDid fails closed when anchoredDid is not declared', async () => {
	const OTHER_DID = 'did:cheqd:testnet:22222222-2222-2222-2222-222222222222';
	const ref = `${OTHER_DID}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;
	let called = false;
	const deps = {
		resolveDidDocument: async () => null,
		manifestCache: {
			get: async () => {
				called = true;
				return { ok: true };
			},
			clear() {},
		},
	};
	const result = await verifyTrustExtension(
		'did:cheqd:testnet:0000000000000000aaaaaaaaaaaaaaaa',
		{ trustConfigRef: ref },
		deps,
	);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('manifest_did_mismatch'));
	assert.equal(called, false);
});

test('a deactivated anchored DID fails linkage as deactivated, even when the linkage is reciprocal', async () => {
	const docs = {
		[CANONICAL]: { id: CANONICAL, alsoKnownAs: [ANCHORED] },
		[ANCHORED]: { id: ANCHORED, alsoKnownAs: [CANONICAL], deactivated: true },
	};
	const deps = {
		resolveDidDocument: async (did) => docs[did] ?? null,
		manifestCache: { get: async () => ({ ok: true }), clear() {} },
	};
	const result = await verifyTrustExtension(CANONICAL, { anchoredDid: ANCHORED }, deps);
	assert.deepEqual(result, { ok: false, reasons: ['linkage_did_deactivated'] });
});
