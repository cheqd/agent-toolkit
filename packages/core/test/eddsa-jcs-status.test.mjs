// SPDX-License-Identifier: Apache-2.0
// Tests createCheqdStatusChecker against a REAL fixture: a BitstringStatusListCredential signed
// by cheqd/did-provider-cheqd#658's actual (not reimplemented) signEddsaJcs2022, not merged yet -
// see fixtures/bitstring-status-list-eddsa-jcs-2022.json's header and
// src/status/eddsa-jcs-status.ts's doc comment for how it was minted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCheqdStatusChecker } from '../dist/index.js';

const fixture = JSON.parse(
	readFileSync(fileURLToPath(new URL('./fixtures/bitstring-status-list-eddsa-jcs-2022.json', import.meta.url)), 'utf8'),
);

function checkerFor(credential) {
	const resolveDidCheqd = async (did) =>
		did === fixture.did ? { id: fixture.did, verificationMethod: [{ id: fixture.kid, publicKeyJwk: fixture.publicKeyJwk }] } : null;
	const fetch = async (url) =>
		url === credential.id
			? { ok: true, status: 200, json: async () => credential }
			: { ok: false, status: 404, json: async () => ({}) };
	return createCheqdStatusChecker({ resolveDidCheqd, fetch });
}

test('accepts a real #658-branch-signed credential and reads the revoked bit', async () => {
	const checker = checkerFor(fixture.credential);
	const result = await checker(fixture.entries.revokedIndex0);
	assert.deepEqual(result, { revoked: true, fresh: true });
});

test('reads a clear bit from the same credential', async () => {
	const checker = checkerFor(fixture.credential);
	const result = await checker(fixture.entries.clearIndex1);
	assert.deepEqual(result, { revoked: false, fresh: true });
});

test('fails closed (revoked) when the encodedList is tampered with after signing', async () => {
	const tampered = structuredClone(fixture.credential);
	tampered.credentialSubject.encodedList = tampered.credentialSubject.encodedList.slice(0, -4) + 'AAAA';
	const checker = checkerFor(tampered);
	const result = await checker(fixture.entries.revokedIndex0);
	assert.equal(result.revoked, true);
});

test('fails closed when the resolver does not know the issuer DID', async () => {
	const fetch = async (url) =>
		url === fixture.credential.id
			? { ok: true, status: 200, json: async () => fixture.credential }
			: { ok: false, status: 404, json: async () => ({}) };
	const checker = createCheqdStatusChecker({ resolveDidCheqd: async () => null, fetch });
	const result = await checker(fixture.entries.revokedIndex0);
	assert.equal(result.revoked, true);
});
