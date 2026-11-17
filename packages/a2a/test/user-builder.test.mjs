// SPDX-License-Identifier: Apache-2.0
// Regression tests for two real exploits found by review, both rooted in the same mechanism:
// `methodAndParamsFor` used to decide "is this a REST message:send/stream route?" with a regex
// on `req.path` (case-sensitive, no trailing-slash tolerance). @a2a-js/sdk's `restHandler` mounts
// on a default `express.Router()`, which is case-INsensitive and trailing-slash-tolerant, so the
// regex and the router's own routing decision could diverge:
//
//   1. Message substitution (fixed once by #32, but only for the exact-cased, no-trailing-slash
//      path): on the message:send/stream route, SendMessageRequest.fromJSON(req.body) reads the
//      body's real top-level fields. A REST body carrying its own top-level {method, params}
//      alongside the real top-level fields let a holder of a valid proof for one message smuggle
//      it under `params` while a different message sat at the real top level - verified ≠
//      executed. #32 fixed this for `/message:send` exactly, but `/message:send/`, `/MESSAGE:SEND`,
//      `/Message:Send/` and `/t1/message:send/` all still reach the same handler via Express's own
//      case-insensitive, trailing-slash-tolerant matching, and the regex missed every one of them
//      - falling through to the pre-#32 body.method/body.params path.
//
//   2. Cross-scope task access (never fixed): the SAME fallback applies to every OTHER REST route
//      (GET /tasks/:id, POST /tasks/:id:cancel, GET /tasks, push-notification-config routes, GET
//      /extendedAgentCard, ...), none of which the old regex recognised at all. A request to any
//      of those routes carrying a smuggled `{method: 'SendMessage', params: <captured proof>}`
//      body got verified as a full SendMessage request and authenticated as the proof's DID, even
//      though the route itself never reads `body.method`/`body.params` - letting one captured
//      proof grant victim-scoped read/cancel/webhook-registration access on routes that have
//      nothing to do with sending a message.
//
// Fixed by deriving "is this the message:send/stream route?" from `req.route.path` - the pattern
// Express itself matched the request against, assigned strictly AFTER Express's own routing (case
// folding, trailing-slash tolerance, tenant-prefix stripping) has already happened - instead of a
// regex re-derived from the raw, attacker-controlled request path. `req.route.path` cannot diverge
// from what Express decided to dispatch to, because Express is the one who sets it. Every route
// that isn't provably the message:send/stream pattern (or the single JSON-RPC "/" endpoint) now
// never consults body.method/body.params at all - closing both bugs for every case/trailing-slash
// variant at once, not just the two strings in the PoC.
//
// These tests spin up a *real* `express.Router()`, registered exactly as `@a2a-js/sdk`'s
// `restHandler`/`jsonRpcHandler` register their routes (verified against the actual installed
// `@a2a-js/sdk@1.3.0` + `express@5.3.0`), and fire real HTTP requests at it - so the case-folding
// and trailing-slash tolerance under test is Express's real behaviour, not a simulation of it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import express from 'express';
import http from 'node:http';
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

/**
 * Fires one real HTTP request at a real `express.Router()` registered exactly as
 * `@a2a-js/sdk`'s `restHandler`/`jsonRpcHandler` register their routes, and returns the gate's
 * verdict for whatever `req` Express actually built - including Express's own case-insensitive,
 * trailing-slash-tolerant route matching. This is the only way to prove the fix tracks Express's
 * real routing decision rather than a simulation of it.
 */
async function verdictFromRealExpressRequest(userBuilder, { method, requestPath, body }) {
	const app = express();
	app.use(express.json());
	const router = express.Router();
	const handler = async (req, res) => {
		const user = await userBuilder(req);
		res.json({ isAuthenticated: user.isAuthenticated, userName: user.userName, rejection: user.rejection ?? null });
	};
	const registerRoute = (httpMethod, path) => {
		router[httpMethod](path, handler);
		router[httpMethod](`/:tenant${path}`, handler);
	};
	// Mirrors restHandler's real registrations (src/server/express/rest_handler.ts).
	registerRoute('post', '/message\\:send');
	registerRoute('post', '/message\\:stream');
	registerRoute('get', '/tasks/:taskId');
	registerRoute('post', '/tasks/:taskId\\:cancel');
	registerRoute('get', '/tasks');
	registerRoute('get', '/extendedAgentCard');
	// Mirrors jsonRpcHandler's single POST "/" endpoint (src/server/express/json_rpc_handler.ts).
	router.post('/', handler);
	app.use(router);

	const server = app.listen(0);
	try {
		await new Promise((resolve) => server.once('listening', resolve));
		const { port } = server.address();
		// A real attacker (curl --request GET --data, a raw socket, ...) can put a body on a GET
		// request; Express parses it the same as any other method. The WHATWG `fetch` client
		// refuses to send one at all (spec restriction on GET/HEAD), so a raw `http.request` is
		// used here to faithfully reproduce what the PoC actually sends over the wire.
		return await sendRawHttpRequest({ port, method, path: requestPath, body: JSON.stringify(body) });
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
}

function sendRawHttpRequest({ port, method, path, body }) {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{ host: '127.0.0.1', port, method, path, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
			(res) => {
				const chunks = [];
				res.on('data', (chunk) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
					} catch (err) {
						reject(err);
					}
				});
			}
		);
		req.on('error', reject);
		req.end(body);
	});
}

test('a well-formed REST request on the exact registered path still verifies', async () => {
	const { userBuilder, signer } = await buildHarness();
	const body = await proofedMessageBody(signer, 'hi');
	const verdict = await verdictFromRealExpressRequest(userBuilder, { method: 'POST', requestPath: '/message:send', body });
	assert.equal(verdict.isAuthenticated, true);
	assert.equal(verdict.userName, CLIENT_DID);
});

for (const requestPath of ['/message:send/', '/MESSAGE:SEND', '/Message:Send/', '/t1/message:send/', '/t1/MESSAGE:SEND']) {
	test(`a well-formed REST request still verifies on the case/trailing-slash/tenant variant ${requestPath}`, async () => {
		const { userBuilder, signer } = await buildHarness();
		const body = await proofedMessageBody(signer, 'hi');
		const verdict = await verdictFromRealExpressRequest(userBuilder, { method: 'POST', requestPath, body });
		assert.equal(verdict.isAuthenticated, true, `expected ${requestPath} to verify, got ${JSON.stringify(verdict)}`);
		assert.equal(verdict.userName, CLIENT_DID);
	});
}

test('a well-formed JSON-RPC request still verifies (the "/" endpoint reads body.method/params)', async () => {
	const { userBuilder, signer } = await buildHarness();
	const params = await proofedMessageBody(signer, 'hi');
	const verdict = await verdictFromRealExpressRequest(userBuilder, { method: 'POST', requestPath: '/', body: { method: 'SendMessage', params } });
	assert.equal(verdict.isAuthenticated, true);
	assert.equal(verdict.userName, CLIENT_DID);
});

for (const requestPath of ['/message:send', '/message:send/', '/MESSAGE:SEND', '/Message:Send/', '/t1/message:send/']) {
	test(`REST message substitution is rejected on the case/trailing-slash/tenant variant ${requestPath}`, async () => {
		const { userBuilder, signer } = await buildHarness();
		// The attacker holds a validly proofed body for "safe content" (e.g. captured from a real
		// client), and wraps it as `params` on a REST request whose real top-level `message` -
		// exactly what SendMessageRequest.fromJSON(req.body) reads, same as restHandler would - is
		// different, unproofed content. Before the fix, any path Express routed here but the regex
		// missed (anything but the exact-cased, no-trailing-slash `/message:send`) fell through to
		// body.method/body.params and verified "safe content", while restHandler would still have
		// executed the real top-level message.
		const smuggledParams = await proofedMessageBody(signer, 'safe content');
		const maliciousBody = {
			method: 'SendMessage',
			params: smuggledParams,
			message: { messageId: 'm2', role: 'ROLE_USER', parts: [{ text: 'ATTACKER SUBSTITUTED TEXT' }], contextId: '', taskId: '', extensions: [], referenceTaskIds: [] },
		};
		const verdict = await verdictFromRealExpressRequest(userBuilder, { method: 'POST', requestPath, body: maliciousBody });
		// The route forces the whole body to be the covered params, so the "message" the gate
		// reads is the top-level one (unproofed) - the same one restHandler will execute - not the
		// attacker's smuggled, proofed one. It must be rejected for missing a proof, never verified.
		assert.equal(verdict.isAuthenticated, false, `expected ${requestPath} to reject the smuggled proof, got ${JSON.stringify(verdict)}`);
		assert.equal(verdict.rejection, 'missing');
	});
}

for (const [method, requestPath] of [
	['GET', '/tasks/victim-task-id'],
	['GET', '/Tasks/victim-task-id/'],
	['POST', '/tasks/victim-task-id:cancel'],
	['GET', '/tasks'],
	['GET', '/extendedAgentCard'],
]) {
	test(`cross-scope access via smuggled body.method/params is rejected on ${method} ${requestPath}`, async () => {
		const { userBuilder, signer } = await buildHarness();
		// The attacker captured a victim's validly proofed SendMessage body (e.g. off the wire) and
		// replays it as the JSON body of an unrelated REST route that has nothing to do with
		// sending a message - exactly the InMemoryTaskStore cross-scope read/cancel finding. Before
		// the fix, none of these paths matched the message:send/stream regex, so
		// methodAndParamsFor fell through to body.method/body.params, verified the captured proof,
		// and returned `isAuthenticated: true, userName: <victim DID>` for a route that never reads
		// body.method/body.params at all - letting the attacker's request proceed authenticated as
		// the victim.
		const victimProof = await proofedMessageBody(signer, 'victim content');
		const smugglingBody = { method: 'SendMessage', params: victimProof };
		const verdict = await verdictFromRealExpressRequest(userBuilder, { method, requestPath, body: smugglingBody });
		assert.equal(verdict.isAuthenticated, false, `expected ${method} ${requestPath} to stay unauthenticated, got ${JSON.stringify(verdict)}`);
		assert.notEqual(verdict.userName, CLIENT_DID);
	});
}
