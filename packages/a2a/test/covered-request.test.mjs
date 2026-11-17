// SPDX-License-Identifier: Apache-2.0
// Checks covered-request.ts's own documented contract directly: strip PROOF_META_KEY and
// nothing else, drop message.metadata entirely only if that empties it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PROOF_META_KEY, RESPONSE_PROOF_META_KEY, coveredRequest, coveredResult } from '../dist/index.js';

test('strips the proof key from message.metadata', () => {
	const wireParams = { message: { metadata: { [PROOF_META_KEY]: 'sig', other: 'keep-me' } } };
	const covered = coveredRequest('SendMessage', wireParams);
	assert.equal(covered.method, 'SendMessage');
	assert.deepEqual(covered.params.message.metadata, { other: 'keep-me' });
});

test('drops message.metadata entirely once emptied by stripping the proof key', () => {
	const wireParams = { message: { metadata: { [PROOF_META_KEY]: 'sig' } } };
	const covered = coveredRequest('SendMessage', wireParams);
	assert.ok(!('metadata' in covered.params.message));
});

test('does not mutate the original wire params', () => {
	const wireParams = { message: { metadata: { [PROOF_META_KEY]: 'sig', other: 'keep-me' } } };
	coveredRequest('SendMessage', wireParams);
	assert.equal(wireParams.message.metadata[PROOF_META_KEY], 'sig');
});

// Regression: an earlier version ALSO stripped a second, 'org.kya-os/proof@1', key from the
// covered form as a "legacy mirror" of PROOF_META_KEY, even though nothing anywhere ever read
// that key as a verification input. Excluding a metadata key from the signed/covered form
// without anything verifying it is exactly how an attacker smuggles unsigned data into
// message.metadata (and, since the gate never substitutes the covered form back into the
// request that actually gets processed, into task history too) underneath an otherwise
// genuinely valid proof - the proof's signature never covered that field, so an attacker can set
// or change it after the proof was generated without invalidating it. That former legacy key
// must now be covered like any other ordinary metadata: present in the covered form, unchanged.
test('does not strip the former legacy proof key - it is ordinary metadata now', () => {
	const wireParams = { message: { metadata: { 'org.kya-os/proof@1': 'attacker-controlled' } } };
	const covered = coveredRequest('SendMessage', wireParams);
	assert.deepEqual(covered.params.message.metadata, { 'org.kya-os/proof@1': 'attacker-controlled' });
});

test('coveredResult strips the response proof key', () => {
	const result = { status: 'ok', metadata: { [RESPONSE_PROOF_META_KEY]: 'sig', other: 'keep-me' } };
	const covered = coveredResult(result);
	assert.deepEqual(covered.metadata, { other: 'keep-me' });
});

test('coveredResult drops metadata entirely once emptied', () => {
	const result = { status: 'ok', metadata: { [RESPONSE_PROOF_META_KEY]: 'sig' } };
	const covered = coveredResult(result);
	assert.ok(!('metadata' in covered));
});
