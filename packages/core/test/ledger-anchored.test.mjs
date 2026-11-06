// SPDX-License-Identifier: Apache-2.0
// Tests for the ledger-anchored status check, against a fake resolver that mimics the public cheqd
// resolver's responses (shapes captured from resolver.cheqd.net on 13 October 2026).
// Run after a build: node --test packages/core/test/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { verifyLedgerAnchoredStatus } from '../dist/index.js';

const NOW = Date.parse('2026-10-13T12:00:00Z');
const COLLECTION = '0c3581f0-011f-4263-b1ca-15ad70d54ede';
const DID = `did:cheqd:testnet:${COLLECTION}`;
const NAME = 'agent-revocations';
const RESOURCE_ID = '1a79a313-8fc3-421c-af3d-34730fa046d1';
const BASE = 'https://resolver.test/1.0/identifiers';
const ENTRY = {
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

/** Build the world a resolver would serve. Each option mutates one thing, to make one failure. */
function world(opts = {}) {
  const entries = opts.entries ?? 131072;
  const credential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: DID,
    issuanceDate: '2026-10-01T00:00:00Z',
    credentialSubject: {
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: opts.encodedList ?? encodeList(entries, opts.setBits ?? []),
    },
    proof: { type: 'JwtProof2020', jwt: 'header.payload.signature' },
    ...opts.credential,
  };
  Object.assign(credential.credentialSubject, opts.subject);
  const record = { bitstringStatusListCredential: credential, metadata: { encrypted: false, encoding: 'base64url', length: entries, statusSize: 1, ...opts.metadata } };
  const bytes = opts.rawBytes ?? Buffer.from(JSON.stringify(record));
  const checksum = opts.checksum ?? createHash('sha256').update(opts.rawBytes ?? bytes).digest('hex');
  const linked = {
    resourceURI: `${DID}/resources/${RESOURCE_ID}`,
    resourceCollectionId: COLLECTION,
    resourceId: RESOURCE_ID,
    resourceName: NAME,
    resourceType: 'BitstringStatusListCredential',
    mediaType: 'application/json',
    resourceVersion: '2026-10-01T00:00:00Z',
    created: '2026-10-01T00:00:00Z',
    checksum,
    previousVersionId: null,
    nextVersionId: null,
    ...opts.linked,
  };
  const meta = {
    dereferencingMetadata: { retrieved: new Date(opts.retrievedAt ?? NOW).toISOString() },
    contentMetadata: { linkedResourceMetadata: opts.linkedList ?? [linked] },
  };
  return { meta, bytes };
}

/** A fetch that serves one world per resolver base, recording every URL requested. */
function fetchFor(worlds, seen = []) {
  return async (url) => {
    seen.push(url);
    const base = Object.keys(worlds).find((b) => url.startsWith(b));
    const w = base === undefined ? undefined : worlds[base];
    if (w === undefined || w === 'down') throw new Error('network');
    if (w.status !== undefined) return { status: w.status, body: new Uint8Array() };
    if (url.includes('resourceMetadata=true')) return { status: 200, body: Buffer.from(JSON.stringify(w.meta)) };
    if (url.includes('/resources/')) return { status: 200, body: w.bytes };
    return { status: 404, body: new Uint8Array() };
  };
}

async function check(w, overrides = {}, entry = ENTRY, issuer = DID) {
  const options = { resolvers: [BASE], fetch: fetchFor({ [BASE]: w }), primitives, now: () => NOW, ...overrides };
  return verifyLedgerAnchoredStatus(entry, issuer, options);
}

const rejected = (result, reason) => {
  assert.equal(result.ok, false, `expected rejection, got ${JSON.stringify(result)}`);
  assert.ok(result.reasons.includes(reason), `expected ${reason}, got ${result.reasons}`);
};

test('a clear bit reads as not revoked', async () => {
  const result = await check(world({ setBits: [7] }));
  assert.equal(result.ok, true);
  assert.equal(result.revoked, false);
  assert.equal(result.resourceId, RESOURCE_ID);
});

test('a set bit reads as revoked (bit order is MSB first within a byte)', async () => {
  const result = await check(world({ setBits: [41260] }));
  assert.equal(result.ok, true);
  assert.equal(result.revoked, true);
});

test('only the named index is read', async () => {
  const result = await check(world({ setBits: [41259, 41261] }));
  assert.equal(result.ok && result.revoked, false);
});

test('the checksum must match the bytes returned', async () => {
  const good = world({ setBits: [1] });
  const tampered = world({ setBits: [41260], checksum: createHash('sha256').update(good.bytes).digest('hex') });
  rejected(await check(tampered), 'checksum_mismatch');
});

test('a resolver serving different bytes than it described is rejected', async () => {
  const claimed = world({ setBits: [] });
  const served = world({ setBits: [41260] });
  rejected(await check({ meta: claimed.meta, bytes: served.bytes }), 'checksum_mismatch');
});

test('an older version (a newer one exists) is rejected', async () => {
  rejected(await check(world({ linked: { nextVersionId: 'ffffffff-ffff-ffff-ffff-ffffffffffff' } })), 'not_latest_version');
});

test('a stale resolver reply is rejected', async () => {
  rejected(await check(world({ retrievedAt: NOW - 10 * 60_000 })), 'resolver_stale');
});

test('a resource from another collection is rejected', async () => {
  rejected(await check(world({ linked: { resourceCollectionId: '99999999-9999-4999-8999-999999999999' } })), 'collection_mismatch');
});

test('a list issued by a different DID is rejected', async () => {
  rejected(await check(world({ credential: { issuer: 'did:cheqd:testnet:99999999-9999-4999-8999-999999999999' } })), 'issuer_mismatch');
});

test('an entry whose list is under a different DID than the expected issuer is rejected', async () => {
  rejected(await check(world(), {}, ENTRY, 'did:cheqd:testnet:99999999-9999-4999-8999-999999999999'), 'issuer_mismatch');
});

test('a purpose mismatch is rejected', async () => {
  rejected(await check(world(), {}, { ...ENTRY, statusPurpose: 'suspension' }), 'purpose_mismatch');
});

test('an out-of-range index is rejected', async () => {
  rejected(await check(world(), {}, { ...ENTRY, statusListIndex: '131072' }), 'index_out_of_range');
});

test('non-canonical indexes are rejected, never read as another bit', async () => {
  for (const index of ['0x2A', ' 1', '+1', '1e1', '-1', '1.5', '']) {
    rejected(await check(world(), {}, { ...ENTRY, statusListIndex: index }), 'invalid_status_list_index');
  }
});

test('a list shorter than the privacy floor is rejected', async () => {
  rejected(await check(world({ entries: 1024 })), 'list_too_short');
});

test('an oversized inflated list is rejected, not inflated', async () => {
  rejected(await check(world({ encodedList: gzipSync(new Uint8Array(40 * 1024 * 1024)).toString('base64url') })), 'resolver_error');
});

test('an encrypted list is rejected', async () => {
  rejected(await check(world({ metadata: { encrypted: true } })), 'encrypted_list_unsupported');
});

test('cheqd\'s default of two bits per entry is rejected', async () => {
  rejected(await check(world({ metadata: { statusSize: 2 } })), 'unsupported_status_size');
  rejected(await check(world(), {}, { ...ENTRY, statusSize: 2 }), 'unsupported_status_size');
});

test('an expired list is rejected', async () => {
  rejected(await check(world({ credential: { validUntil: '2026-10-01T00:00:00Z' } })), 'list_expired');
});

test('invalid JSON is rejected', async () => {
  const w = world();
  const bytes = Buffer.from('not json');
  rejected(await check({ meta: world({ checksum: createHash('sha256').update(bytes).digest('hex') }).meta, bytes }), 'invalid_json');
});

test('the old StatusList2021 data record is not supported', async () => {
  const bytes = Buffer.from(JSON.stringify({ StatusList2021: { statusPurpose: 'revocation', encodedList: 'H4sIAAAAAAAAA-3BAQ0AAADCoPdPbQ8HFAAAAAAAAAAAAAAAAAAAAADwaDhDr_xcRAAA', validFrom: '2023-09-22T09:47:02.025Z' }, metadata: { type: 'StatusList2021Revocation', encrypted: false } }));
  const w = world({ checksum: createHash('sha256').update(bytes).digest('hex') });
  rejected(await check({ meta: w.meta, bytes }), 'malformed_resource');
});

test('an unavailable resolver is rejected', async () => {
  rejected(await check({ status: 503 }), 'metadata_unavailable');
  rejected(await check('down'), 'resolver_error');
});

test('a missing or ambiguous resource is rejected', async () => {
  rejected(await check(world({ linkedList: [] })), 'ambiguous_or_missing_resource');
  const two = world();
  rejected(await check(world({ linkedList: [two.meta.contentMetadata.linkedResourceMetadata[0], two.meta.contentMetadata.linkedResourceMetadata[0]] })), 'ambiguous_or_missing_resource');
});

test('the host in the credential\'s URL is never fetched', async () => {
  const seen = [];
  const entry = { ...ENTRY, statusListCredential: `https://attacker.example/1.0/identifiers/${DID}?resourceName=${NAME}&resourceType=BitstringStatusListCredential` };
  await verifyLedgerAnchoredStatus(entry, DID, { resolvers: [BASE], fetch: fetchFor({ [BASE]: world() }, seen), primitives, now: () => NOW });
  assert.ok(seen.length > 0 && seen.every((url) => url.startsWith(BASE)), `fetched ${seen}`);
});

test('lists by resource id or from other DID methods are rejected', async () => {
  rejected(await check(world(), {}, { ...ENTRY, statusListCredential: `${DID}/resources/${RESOURCE_ID}` }), 'unsupported_list_reference');
  rejected(await check(world(), {}, { ...ENTRY, statusListCredential: 'https://example.com/status/1' }), 'not_a_cheqd_list');
});

test('http resolvers are refused unless explicitly allowed', async () => {
  const insecure = 'http://resolver.test/1.0/identifiers';
  const options = { resolvers: [insecure], fetch: fetchFor({ [insecure]: world() }), primitives, now: () => NOW };
  rejected(await verifyLedgerAnchoredStatus(ENTRY, DID, options), 'resolver_not_https');
  assert.equal((await verifyLedgerAnchoredStatus(ENTRY, DID, { ...options, allowInsecureResolvers: true })).ok, true);
});

test('two resolvers that agree are accepted and both reported', async () => {
  const b2 = 'https://resolver-two.test/1.0/identifiers';
  const w = world({ setBits: [41260] });
  const result = await verifyLedgerAnchoredStatus(ENTRY, DID, { resolvers: [BASE, b2], fetch: fetchFor({ [BASE]: w, [b2]: w }), primitives, now: () => NOW, minAgreement: 2 });
  assert.equal(result.ok && result.revoked, true);
  assert.equal(result.resolvers.length, 2);
});

test('two resolvers that disagree are rejected, even when one says revoked', async () => {
  const b2 = 'https://resolver-two.test/1.0/identifiers';
  const result = await verifyLedgerAnchoredStatus(ENTRY, DID, { resolvers: [BASE, b2], fetch: fetchFor({ [BASE]: world(), [b2]: world({ setBits: [41260] }) }), primitives, now: () => NOW });
  rejected(result, 'resolver_disagreement');
});

test('too few agreeing resolvers is rejected when agreement is required', async () => {
  const b2 = 'https://resolver-two.test/1.0/identifiers';
  const options = { resolvers: [BASE, b2], fetch: fetchFor({ [BASE]: world(), [b2]: 'down' }), primitives, now: () => NOW };
  rejected(await verifyLedgerAnchoredStatus(ENTRY, DID, { ...options, minAgreement: 2 }), 'resolver_error');
  assert.equal((await verifyLedgerAnchoredStatus(ENTRY, DID, { ...options, minAgreement: 1 })).ok, true);
});

test('asking for more agreement than there are resolvers is rejected', async () => {
  rejected(await check(world(), { minAgreement: 2 }), 'not_enough_resolvers');
});
