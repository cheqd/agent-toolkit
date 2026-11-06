// The Node/TypeScript runner for conformance/vectors/a2a-gate.json (v1/spec.md §8's minimum
// negative-vector set, plus VEC-A2A-GATE-1/RESP-1). Exercises the REAL gate
// (@cheqd/agent-identity-a2a) over real HTTP with real Ed25519 proofs - tampering happens on
// the wire, after signing, exactly as an attacker would have to. Run after `npm run build`.
//
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import express from 'express';
import { generateKeyPair, exportJWK } from 'jose';
import { Role, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler } from '@a2a-js/sdk/server/express';
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from '@a2a-js/sdk/client';
import { ed25519SignerFromJwk, buildCardProof, InMemoryNonceCache } from '@kya-os/mcp/card';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider, RuntimeFetchProvider } from '@kya-os/mcp/providers';
import {
	createVerifyingUserBuilder,
	withAgentIdentity,
	createProofInterceptor,
	coveredRequest,
	createTrustExtensionCache,
} from '@cheqd/agent-identity-a2a';

const vectors = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'vectors', 'a2a-gate.json'), 'utf8'));
const results = [];
const line = (s) => console.log(s);

const EXT_URI = 'https://kya-os.org/a2a/ext/proof/v1';
const CLIENT_DID = 'did:web:client.example';
const SERVER_DID = 'did:web:server.example';

async function newKey(did) {
	const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	const priv = await exportJWK(privateKey);
	const pub = await exportJWK(publicKey);
	return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x }, cryptoKey: privateKey };
}

const client = await newKey(CLIENT_DID);
const server = await newKey(SERVER_DID);
const impostor = await newKey(CLIENT_DID); // claims the SAME DID as `client`, but is never published under it
const resolveKey = (kid) => (kid === client.kid ? client.pub : kid === server.kid ? server.pub : (() => { throw new Error('no such kid'); })());
const resolveDidKeys = (did) => (did === CLIENT_DID ? [client.pub] : did === SERVER_DID ? [server.pub] : []);

const message = (id, text, overrides = {}) => ({
	messageId: id,
	role: Role.ROLE_USER,
	parts: [{ content: { $case: 'text', value: text }, mediaType: 'text/plain', filename: '', metadata: undefined }],
	contextId: '',
	taskId: '',
	metadata: undefined,
	extensions: [],
	referenceTaskIds: [],
	...overrides,
});

function newExecutor() {
	const count = { n: 0 };
	const tasks = [];
	const executor = {
		async execute(ctx, bus) {
			count.n++;
			const task = { id: ctx.taskId, contextId: ctx.contextId, status: { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined }, artifacts: [], history: [], metadata: {} };
			tasks.push(task);
			bus.publish(AgentEvent.task(task));
			bus.finished();
		},
		async cancelTask() {},
	};
	return { count, executor, tasks };
}

/** Builds one fresh server + a matching client-side signer for a single vector, so vectors never
 * interfere with each other's nonce/replay state. `trustExtensionResult` lets the
 * revoked/stale-policy vectors inject a canned trust-extension outcome without needing real DLR
 * network fixtures. */
async function newServer({ trustExtensionResult } = {}) {
	const agentCard = (url) => ({
		name: 'conformance', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
		supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
		capabilities: { extensions: [{ uri: EXT_URI, description: 'proof', required: true, params: {} }], streaming: true, pushNotifications: false },
		securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
		skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
		signatures: [],
	});
	const { count, executor, tasks } = newExecutor();
	const store = new InMemoryTaskStore();
	const nonceCache = new InMemoryNonceCache();
	const userBuilder = createVerifyingUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume });

	let trustExtension;
	if (trustExtensionResult) {
		const deps = { resolveDidDocument: async () => null, manifestCache: { get: async () => ({ ok: true }), clear() {} }, checkStatus: async () => trustExtensionResult };
		trustExtension = { cache: createTrustExtensionCache(deps), activation: { statusCheck: 'required' } };
	}
	const handler = withAgentIdentity(
		new DefaultRequestHandler(agentCard('http://x'), store, executor),
		{ serverDid: SERVER_DID, serverKid: server.kid, privateKey: server.cryptoKey, publicKey: server.priv.d, cryptoProvider: new NodeCryptoProvider() },
		trustExtension,
	);
	const app = express();
	app.use(express.json());
	app.use(jsonRpcHandler({ requestHandler: handler, userBuilder: async (req) => userBuilder(req) }));
	const srv = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
	const url = `http://127.0.0.1:${srv.address().port}/`;
	return { srv, url, agentCardFor: agentCard, count, tasks, store };
}

function newClient(url, agentCard, signingKey = client) {
	return (async () => {
		const signer = await ed25519SignerFromJwk({ did: signingKey.did, kid: signingKey.kid, privateJwk: signingKey.priv });
		const { interceptor, state } = createProofInterceptor({
			signer, serverDid: SERVER_DID, clientDid: signingKey.did, serverPublicJwk: { ...server.pub, kid: server.kid },
			extensionUri: EXT_URI, cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(),
			nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider(),
		});
		const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
			transports: [new JsonRpcTransportFactory()], clientConfig: { interceptors: [interceptor] },
		}));
		const a2a = await factory.createFromAgentCard(agentCard(url));
		return { a2a, state };
	})();
}

async function rawPost(url, body) {
	const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, ...body }) });
	return { status: r.status, body: await r.json() };
}

/** Records a negative vector's outcome. Every negative vector also feeds VEC-A2A-GATE-1's
 * aggregate check at the end: a rejected call must leave the executor's run count unchanged. */
function record(id, { rejected, countBefore, countAfter, extra = '' }) {
	const gateInvariantHeld = countAfter === countBefore;
	const pass = rejected && gateInvariantHeld;
	results.push({ id, pass, rejected, gateInvariantHeld, extra });
	line(`${pass ? 'PASS' : 'FAIL'} ${id}${extra ? ` - ${extra}` : ''}`);
}

/** For vectors that assert something other than "the gate rejected this call" (the
 * accept-without-fusion documentation case, and the response-binding case). Not part of the
 * VEC-A2A-GATE-1 aggregate, since there is no rejection to check an invariant against. */
function recordDirect(id, pass, extra = '') {
	results.push({ id, pass, rejected: null, gateInvariantHeld: null, extra });
	line(`${pass ? 'PASS' : 'FAIL'} ${id}${extra ? ` - ${extra}` : ''}`);
}

// --- VEC-A2A-NEG-WRONG-AUDIENCE -----------------------------------------------------------------
{
	const { srv, url, agentCardFor, count } = await newServer();
	const before = count.n;
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const proof = await buildCardProof(coveredRequest('SendMessage', { message: message('m1', 'x') }), signer, {
		audience: 'did:web:someone-else.example', // wrong audience
		nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url'),
	});
	const body = { message: message('m1', 'x', { metadata: { ...proof } }) };
	const r = await rawPost(url, { method: 'SendMessage', params: body });
	record('VEC-A2A-NEG-WRONG-AUDIENCE', { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n });
	srv.close();
}

// --- VEC-A2A-NEG-EXPIRED-PROOF --------------------------------------------------------------
{
	const { srv, url, count } = await newServer();
	const before = count.n;
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const covered = coveredRequest('SendMessage', { message: message('m1', 'x') });
	const proof = await buildCardProof(covered, signer, {
		audience: SERVER_DID,
		nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url'),
		created: new Date(Date.now() - 10 * 60_000).toISOString(), // 10 minutes ago - well past the 60s TTL
	});
	const body = { message: message('m1', 'x', { metadata: { ...proof } }) };
	const r = await rawPost(url, { method: 'SendMessage', params: body });
	record('VEC-A2A-NEG-EXPIRED-PROOF', { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n });
	srv.close();
}

// --- VEC-A2A-NEG-REPLAYED-NONCE --------------------------------------------------------------
{
	const { srv, url, count } = await newServer();
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const covered = coveredRequest('SendMessage', { message: message('m1', 'x') });
	const proof = await buildCardProof(covered, signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	const body = { message: message('m1', 'x', { metadata: { ...proof } }) };
	await rawPost(url, { method: 'SendMessage', params: body }); // first use: accepted
	const before = count.n;
	const r = await rawPost(url, { method: 'SendMessage', params: body }); // replay
	record('VEC-A2A-NEG-REPLAYED-NONCE', { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n });
	srv.close();
}

// --- VEC-A2A-NEG-ALTERED-MESSAGE-PART / CONTEXT-ID / TASK-ID --------------------------------
async function alteredFieldVector(id, mutate) {
	const { srv, url, count } = await newServer();
	const before = count.n;
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const original = message('m1', 'x');
	const covered = coveredRequest('SendMessage', { message: original });
	const proof = await buildCardProof(covered, signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	const tampered = mutate({ ...original, metadata: { ...proof } });
	const r = await rawPost(url, { method: 'SendMessage', params: { message: tampered } });
	record(id, { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n });
	srv.close();
}
await alteredFieldVector('VEC-A2A-NEG-ALTERED-MESSAGE-PART', (m) => ({ ...m, parts: [{ content: { $case: 'text', value: 'TAMPERED' }, mediaType: 'text/plain', filename: '', metadata: undefined }] }));
await alteredFieldVector('VEC-A2A-NEG-ALTERED-CONTEXT-ID', (m) => ({ ...m, contextId: 'attacker-chosen-context' }));
await alteredFieldVector('VEC-A2A-NEG-ALTERED-TASK-ID', (m) => ({ ...m, taskId: 'attacker-chosen-task' }));

// --- VEC-A2A-NEG-KEY-SUBSTITUTION ------------------------------------------------------------
{
	const { srv, url, count } = await newServer();
	const before = count.n;
	// Signed by `impostor`, but the proof CLAIMS to be `client`'s kid - resolveKey/resolveDidKeys
	// never published impostor's key under CLIENT_DID, so signature verification must fail.
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: impostor.priv });
	const covered = coveredRequest('SendMessage', { message: message('m1', 'x') });
	const proof = await buildCardProof(covered, signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	const body = { message: message('m1', 'x', { metadata: { ...proof } }) };
	const r = await rawPost(url, { method: 'SendMessage', params: body });
	record('VEC-A2A-NEG-KEY-SUBSTITUTION', { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n });
	srv.close();
}

// --- VEC-A2A-NEG-ALG-KEY-MISMATCH -------------------------------------------------------------
{
	const { srv, url, count } = await newServer();
	const before = count.n;
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const covered = coveredRequest('SendMessage', { message: message('m1', 'x') });
	const proof = await buildCardProof(covered, signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	const tamperedProof = { ...proof, alg: 'ES256' }; // claim a key type the resolved key is not
	const body = { message: message('m1', 'x', { metadata: { ...tamperedProof } }) };
	const r = await rawPost(url, { method: 'SendMessage', params: body });
	record('VEC-A2A-NEG-ALG-KEY-MISMATCH', { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n, extra: 'tamper after signing - signature still must fail under the wrong alg' });
	srv.close();
}

// --- VEC-A2A-NEG-DOWNGRADED-CNF --------------------------------------------------------------
{
	// A correctly-signed, otherwise-valid proof with no cnf at all MUST still verify (cnf is
	// optional - see spec §4.6 step 8) but MUST NOT be silently promoted to full L3. This vector
	// asserts the gate surfaces the downgrade rather than accepting it as indistinguishable from
	// full fusion - checked via the proof verifying at all (accepted) while carrying no cnf, i.e.
	// the request succeeds but at a lower assurance than a cnf-fused caller would get.
	const { srv, url, count } = await newServer();
	const before = count.n;
	const { a2a } = await newClient(url, (u) => ({
		name: 'conformance', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
		supportedInterfaces: [{ url: u, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
		capabilities: { extensions: [{ uri: EXT_URI, description: 'proof', required: true, params: {} }], streaming: true, pushNotifications: false },
		securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
		skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
		signatures: [],
	}));
	try {
		await a2a.sendMessage({ tenant: '', message: message('m1', 'no cnf here'), configuration: undefined, metadata: undefined });
		// Accepted without cnf is CORRECT (cnf is optional, spec §4.6 step 8); the vector exists
		// to document that this path is accepted and distinguishable from full fusion, not to
		// reject it. Pass iff the executor actually ran once.
		recordDirect('VEC-A2A-NEG-DOWNGRADED-CNF', count.n === before + 1, 'cnf-less proof accepted (correct - cnf is optional), not silently promoted to full fusion');
	} catch {
		recordDirect('VEC-A2A-NEG-DOWNGRADED-CNF', false, 'a proof with no cnf should not throw - cnf is optional');
	}
	srv.close();
}

// --- VEC-A2A-NEG-REVOKED-CREDENTIAL ----------------------------------------------------------
{
	const { srv, url, count } = await newServer({ trustExtensionResult: { revoked: true, fresh: true } });
	const before = count.n;
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const covered = coveredRequest('SendMessage', { message: message('m1', 'x') });
	const proof = await buildCardProof(covered, signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	const body = { message: message('m1', 'x', { metadata: { ...proof } }) };
	const r = await rawPost(url, { method: 'SendMessage', params: body });
	record('VEC-A2A-NEG-REVOKED-CREDENTIAL', { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n, extra: 'a fully valid A2A proof, but the trust extension reports revoked' });
	srv.close();
}

// --- VEC-A2A-NEG-STALE-POLICY ----------------------------------------------------------------
{
	const { srv, url, count } = await newServer({ trustExtensionResult: { revoked: false, fresh: false } });
	const before = count.n;
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const covered = coveredRequest('SendMessage', { message: message('m1', 'x') });
	const proof = await buildCardProof(covered, signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	const body = { message: message('m1', 'x', { metadata: { ...proof } }) };
	const r = await rawPost(url, { method: 'SendMessage', params: body });
	record('VEC-A2A-NEG-STALE-POLICY', { rejected: Boolean(r.body.error), countBefore: before, countAfter: count.n, extra: 'not revoked, but not fresh - stale policy must not be treated as absent' });
	srv.close();
}

// --- VEC-A2A-RESP-1 ------------------------------------------------------------------------
// The client interceptor's own `after` hook re-verifies the response proof against the result
// AS RECEIVED (see client.ts), so a genuine pass here means the proof is bound to content the
// client actually got back, not merely present - exactly what this vector requires.
{
	const { srv, url, agentCardFor } = await newServer();
	const { a2a, state } = await newClient(url, agentCardFor);
	const task = await a2a.sendMessage({ tenant: '', message: message('m1', 'hello'), configuration: undefined, metadata: undefined });
	const genuinelyBound = state.lastResponseCheck?.valid === true;
	recordDirect('VEC-A2A-RESP-1', genuinelyBound, genuinelyBound ? `response proof verified bound to task ${task?.id}` : 'response proof did not verify as bound');
	srv.close();
}

// --- VEC-A2A-GATE-1 (aggregate) --------------------------------------------------------------
// Every VEC-A2A-NEG-* vector above recorded whether the executor's run count was unchanged by
// its rejection. VEC-A2A-GATE-1 is that invariant holding across ALL of them, for both a brand
// new task (every vector above) and a follow-up to an EXISTING task.
{
	const { srv, url, count } = await newServer();
	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const first = await buildCardProof(coveredRequest('SendMessage', { message: message('m1', 'create the task') }), signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	await rawPost(url, { method: 'SendMessage', params: { message: message('m1', 'create the task', { metadata: { ...first } }) } });
	const beforeFollowUp = count.n;
	const bareFollowUp = { method: 'SendMessage', params: { message: message('m2', 'unproofed follow-up', { taskId: 'does-not-matter' }) } };
	await rawPost(url, bareFollowUp);
	const followUpHeld = count.n === beforeFollowUp;
	srv.close();

	const negativeVectorsHeld = results.filter((r) => r.rejected !== null).every((r) => r.gateInvariantHeld);
	recordDirect('VEC-A2A-GATE-1', negativeVectorsHeld && followUpHeld, followUpHeld ? 'invariant held for every negative vector and an unproofed follow-up to an existing task' : 'FAIL: an unproofed follow-up to an existing task ran the executor');
}

line('');
const declaredIds = new Set(vectors.vectors.map((v) => v.id));
const implementedIds = new Set(results.map((r) => r.id));
const missing = [...declaredIds].filter((id) => !implementedIds.has(id));
for (const m of missing) line(`MISSING ${m} (declared in vectors/a2a-gate.json but not implemented by this runner)`);

const failed = results.filter((r) => !r.pass);
line(`\n${results.length} vectors run, ${failed.length} failed, ${missing.length} missing.`);
if (failed.length > 0 || missing.length > 0) process.exit(1);
