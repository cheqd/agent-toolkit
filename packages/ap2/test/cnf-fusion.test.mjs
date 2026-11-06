// SPDX-License-Identifier: Apache-2.0
// Tests for verifySameKeyContinuity/verifyCnfContinuity against real generated Ed25519 keys
// (RFC 7638 thumbprints computed by jose, not hand-rolled).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK } from 'jose';
import { verifySameKeyContinuity, verifyCnfContinuity } from '../dist/index.js';

async function newJwk() {
	const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
	const jwk = await exportJWK(publicKey);
	return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
}

test('same-key continuity passes when the mandate cnf.jwk equals the resolved agent key', async () => {
	const key = await newJwk();
	const result = await verifySameKeyContinuity(key, key);
	assert.deepEqual(result, { ok: true, tier: 'same-key' });
});

test('same-key continuity fails on a genuinely different key', async () => {
	const a = await newJwk();
	const b = await newJwk();
	const result = await verifySameKeyContinuity(a, b);
	assert.equal(result.ok, false);
	assert.equal(result.reason, 'cnf_jwk_thumbprint_mismatch');
});

test('verifyCnfContinuity falls back to same-key failure with no payment key credential supplied', async () => {
	const a = await newJwk();
	const b = await newJwk();
	const deps = { resolveDidDocument: async () => null, checkRevoked: async () => ({ revoked: false, fresh: true }) };
	const result = await verifyCnfContinuity(a, b, 'did:example:agent', undefined, deps);
	assert.equal(result.ok, false);
});

test('verifyCnfContinuity accepts same-key without needing a payment key credential at all', async () => {
	const key = await newJwk();
	const deps = { resolveDidDocument: async () => null, checkRevoked: async () => ({ revoked: false, fresh: true }) };
	const result = await verifyCnfContinuity(key, key, 'did:example:agent', undefined, deps);
	assert.deepEqual(result, { ok: true, tier: 'same-key' });
});
