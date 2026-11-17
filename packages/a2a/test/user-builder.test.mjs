// SPDX-License-Identifier: Apache-2.0
// Regression test for a real exploit found by review: methodAndParamsFor used to check
// body.method before checking the REST route. @a2a-js/sdk's restHandler executes
// SendMessageRequest.fromJSON(req.body) - it reads the body's real top-level fields and ignores
// unknown ones - so a REST body carrying its own top-level {method, params} alongside the real
// top-level fields restHandler executes let a holder of a valid proof for one message smuggle it
// under `params` while a different message sat at the real top level: the gate verified the
// smuggled message, restHandler executed the real one. Fixed by checking the REST route first:
// once the route implies a method, the whole body is the covered params, unconditionally.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK } from 'jose';
import { buildCardProof, ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import { createVerifyingUserBuilder } from '../dist/index.js';

const CLIENT_DID = 'did:web:client.example';
const SERVER_DID = 'did:web:server.example';

async function newKey(did) {
	const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	const priv = await exportJWK(privateKey);
	return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x } };
}

async function buildHarness() {
	const client = await newKey(CLIENT_DID);
	const nonceCache = new InMemoryNonceCache();
	const resolveKey = async (kid) => (kid === client.kid ? client.pub : (() => { throw new Error('no such kid'); })());
	const resolveDidKeys = async (did) => (did === CLIENT_DID ? [client.pub] : []);
	const userBuilder = createVerifyingUserBuilder({
		resolveKey,
		resolveDidKeys,
		expectedAudience: SERVER_DID,
		consumeNonceIfFresh: nonceCache.consume,
	});
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	return { userBuilder, signer };
}

/** A proofed `{message}` REST body for `text`, the same shape a real client sends. */
async function proofedMessageBody(signer, text) {
	const params = { message: { messageId: 'm1', role: 'ROLE_USER', parts: [{ text }], contextId: '', taskId: '', extensions: [], referenceTaskIds: [] } };
	const proof = await buildCardProof({ method: 'SendMessage', params }, signer, { audience: SERVER_DID, nonce: randomBytes(16).toString('base64url') });
	params.message.metadata = { ...proof };
	return params;
}

test('a well-formed REST request still verifies (route implies the method, body is the bare params)', async () => {
	const { userBuilder, signer } = await buildHarness();
	const body = await proofedMessageBody(signer, 'hi');
	const user = await userBuilder({ path: '/v1/message:send', body });
	assert.equal(user.isAuthenticated, true);
	assert.equal(user.verified.did, CLIENT_DID);
});

test('a well-formed JSON-RPC request still verifies (no REST route, so body.method/params is used)', async () => {
	const { userBuilder, signer } = await buildHarness();
	const params = await proofedMessageBody(signer, 'hi');
	const user = await userBuilder({ path: '/', body: { method: 'SendMessage', params } });
	assert.equal(user.isAuthenticated, true);
	assert.equal(user.verified.did, CLIENT_DID);
});

test('REST: a request smuggling a different method/params under extra top-level keys does not verify the content restHandler will actually execute', async () => {
	const { userBuilder, signer } = await buildHarness();
	// The attacker holds a validly proofed body for "safe content" (e.g. captured from a real
	// client), and wraps it as `params` on a REST request whose real top-level `message` -
	// exactly what SendMessageRequest.fromJSON(req.body) reads, same as restHandler would - is
	// different, unproofed content. Before the fix, methodAndParamsFor read body.method/params
	// first and verified "safe content"; restHandler would still execute the real top-level
	// message. The fix must not let this verify as the attacker's smuggled content.
	const smuggledParams = await proofedMessageBody(signer, 'safe content');
	const maliciousBody = {
		method: 'SendMessage',
		params: smuggledParams,
		message: { messageId: 'm2', role: 'ROLE_USER', parts: [{ text: 'ATTACKER SUBSTITUTED TEXT' }], contextId: '', taskId: '', extensions: [], referenceTaskIds: [] },
	};
	const user = await userBuilder({ path: '/v1/message:send', body: maliciousBody });
	// The route forces the whole body to be the covered params, so the "message" the gate reads
	// is the top-level one (unproofed) - the same one restHandler will execute - not the
	// attacker's smuggled, proofed one. It must be rejected for missing a proof, never verified.
	assert.equal(user.isAuthenticated, false);
	assert.equal(user.rejection, 'missing');
});
