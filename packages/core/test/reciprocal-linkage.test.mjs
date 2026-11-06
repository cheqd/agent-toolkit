// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyReciprocalLinkage } from '../dist/index.js';

const CHEQD = { id: 'did:cheqd:testnet:abc', alsoKnownAs: ['did:web:agent.example'] };
const WEB = { id: 'did:web:agent.example', alsoKnownAs: ['did:cheqd:testnet:abc'] };

test('reciprocal linkage in both directions is accepted', () => {
	assert.deepEqual(verifyReciprocalLinkage(CHEQD, WEB), { ok: true });
});

test('order does not matter', () => {
	assert.deepEqual(verifyReciprocalLinkage(WEB, CHEQD), { ok: true });
});

test('a one-directional claim (a names b, b does not name a) is rejected', () => {
	const unreciprocatedWeb = { id: 'did:web:agent.example', alsoKnownAs: [] };
	const result = verifyReciprocalLinkage(CHEQD, unreciprocatedWeb);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('b_does_not_name_a'));
});

test('a one-directional claim the other way is rejected', () => {
	const unreciprocatedCheqd = { id: 'did:cheqd:testnet:abc', alsoKnownAs: [] };
	const result = verifyReciprocalLinkage(unreciprocatedCheqd, WEB);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('a_does_not_name_b'));
});

test('a missing alsoKnownAs on either side is rejected, not treated as vacuously true', () => {
	const noField = { id: 'did:web:agent.example' };
	const result = verifyReciprocalLinkage(CHEQD, noField);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('b_does_not_name_a'));
});

test('neither side naming the other is rejected with both reasons', () => {
	const result = verifyReciprocalLinkage({ id: 'did:a', alsoKnownAs: [] }, { id: 'did:b', alsoKnownAs: [] });
	assert.deepEqual(result.reasons, ['a_does_not_name_b', 'b_does_not_name_a']);
});

test('a document naming itself as both sides is rejected', () => {
	const self = { id: 'did:a', alsoKnownAs: ['did:a'] };
	const result = verifyReciprocalLinkage(self, self);
	assert.equal(result.ok, false);
	assert.ok(result.reasons.includes('same_did'));
});
