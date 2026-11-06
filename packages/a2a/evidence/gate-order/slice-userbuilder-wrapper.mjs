// Hybrid with no Express middleware: a userBuilder reads the WIRE body, verifies the proof and sets
// the identity (it never throws); a request-handler wrapper enforces and makes the response proof.
import express from 'express';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, importJWK } from 'jose';
import { Task, TaskState } from '@a2a-js/sdk';
import { RequestMalformedError, ExtensionSupportRequiredError } from '@a2a-js/sdk/errors';
import { DefaultRequestHandler, InMemoryTaskStore, ServerCallContext, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler, UserBuilder } from '@a2a-js/sdk/server/express';
import { buildCardProof, verifyCardProof, ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import { ProofGenerator, ProofVerifier } from '@kya-os/mcp/proof';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider, RuntimeFetchProvider } from '@kya-os/mcp/providers';

const ver = (p) => JSON.parse(readFileSync(new URL(`./node_modules/${p}/package.json`, import.meta.url))).version;
console.log(`@a2a-js/sdk ${ver('@a2a-js/sdk')}, @kya-os/mcp ${ver('@kya-os/mcp')}\n`);

const PROOF_KEY = 'org.kya-os/request-proof';
const RESP_KEY = 'org.kya-os/response-proof';
const CLIENT_DID = 'did:web:client.example', OTHER_DID = 'did:web:other.example', SERVER_DID = 'did:web:server.example';

async function newKey(did) {
  const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const priv = await exportJWK(privateKey);
  return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x } };
}
const client = await newKey(CLIENT_DID), other = await newKey(OTHER_DID), server = await newKey(SERVER_DID);
const keys = [client, other, server];
const resolveKey = (kid) => keys.find((k) => k.kid === kid).pub;
const resolveDidKeys = (did) => keys.filter((k) => k.did === did).map((k) => k.pub);
const nonceCache = new InMemoryNonceCache();
const signerOf = (k) => ed25519SignerFromJwk({ did: k.did, kid: k.kid, privateJwk: k.priv });

const agentCard = {
  name: 'x', description: 'x', version: '1', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url: 'http://x', protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false }, securitySchemes: {}, securityRequirements: [],
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [], signatures: [],
};
let executed = 0;
const executor = { async execute(ctx, bus) {
  executed++;
  const status = { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined };
  if (!ctx.task) bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status, artifacts: [], history: [], metadata: {} }));
  else bus.publish(AgentEvent.statusUpdate({ taskId: ctx.taskId, contextId: ctx.contextId, status, metadata: {} }));
  bus.finished();
}, async cancelTask() {} };

function covered(method, params) {
  const p = structuredClone(params);
  const md = p?.message?.metadata;
  if (md) { delete md[PROOF_KEY]; if (Object.keys(md).length === 0) delete p.message.metadata; }
  return { method, params: p };
}
const taskForm = (json) => { const t = structuredClone(json); if (t.metadata) { delete t.metadata[RESP_KEY]; if (!Object.keys(t.metadata).length) delete t.metadata; } return t; };

// ---- piece 1: userBuilder. Reads the wire body. Never throws. ------------------------------------
const WRITE_METHODS = new Set(['SendMessage', 'SendStreamingMessage']);
const verifyingUserBuilder = async (req) => {
  const body = req.body;
  if (!WRITE_METHODS.has(body?.method)) return { isAuthenticated: false, userName: '' };
  const proof = body.params?.message?.metadata?.[PROOF_KEY];
  if (!proof) return { isAuthenticated: false, userName: '', rejection: 'missing' };
  const cov = covered(body.method, body.params);
  const r = await verifyCardProof(proof, cov, { resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume });
  return r.ok ? { isAuthenticated: true, userName: r.did, verified: { did: r.did, covered: cov } }
              : { isAuthenticated: false, userName: '', rejection: r.reasons[0] };
};

// ---- piece 2: wrapper. Enforces, then makes the response proof over the final result. ------------
const respGen = new ProofGenerator({ did: server.did, kid: server.kid, privateKey: await importJWK(server.priv, 'EdDSA') }, new NodeCryptoProvider());
function enforce(ctx) {
  const v = ctx.user?.verified;
  if (v) return v;
  const reason = ctx.user?.rejection ?? 'no_verifier_installed';
  throw reason === 'missing' || reason === 'no_verifier_installed'
    ? new ExtensionSupportRequiredError(`proof_required: ${reason}`)
    : new RequestMalformedError(`proof_invalid: ${reason}`);
}
function withAgentIdentity(inner) {
  return new Proxy(inner, { get(t, prop) {
    if (prop === 'sendMessage') return async (params, ctx) => {
      const v = enforce(ctx);
      const result = await t.sendMessage(params, ctx);
      if ('status' in result) {
        const data = taskForm(Task.toJSON(result));
        const session = { sessionId: 'a2a-stateless', audience: v.did, nonce: randomBytes(16).toString('base64url'), timestamp: Date.now(), createdAt: Date.now(), lastActivity: Date.now(), ttlMinutes: 1 };
        const proof = await respGen.generateProof(v.covered, { data }, session, { profile: 'org.kya-os/response-proof.envelope' });
        result.metadata = { ...(result.metadata ?? {}), [RESP_KEY]: proof };
      }
      return result;
    };
    if (prop === 'sendMessageStream') return async function* (params, ctx) { enforce(ctx); yield* t.sendMessageStream(params, ctx); };
    return typeof t[prop] === 'function' ? t[prop].bind(t) : t[prop];
  } });
}

async function start({ installVerifier }) {
  const store = new InMemoryTaskStore();
  const handler = withAgentIdentity(new DefaultRequestHandler(agentCard, store, executor));
  const app = express(); app.use(express.json());
  app.use(jsonRpcHandler({ requestHandler: handler, userBuilder: installVerifier ? verifyingUserBuilder : UserBuilder.noAuthentication }));
  const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  return { srv, store, url: `http://127.0.0.1:${srv.address().port}/` };
}

const respVerifier = new ProofVerifier({ cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider() });
const signer = await signerOf(client);
const base = () => ({ message: { messageId: 'm1', role: 'ROLE_USER', parts: [{ text: 'hi' }] } });

async function post(url, method, params, { sign = true, signWith = signer, audience = SERVER_DID } = {}) {
  const p = structuredClone(params);
  if (sign) {
    const proof = await buildCardProof(covered(method, p), signWith, { audience, nonce: randomBytes(16).toString('base64url') });
    p.message.metadata = { ...(p.message.metadata ?? {}), ...proof };
  }
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: p }) });
  const text = await r.text(); let j; try { j = JSON.parse(text); } catch { j = {}; }
  return { http: r.status, j, sent: p };
}
const outcome = (r) => r.j.error ? `rejected (${r.j.error.code}: ${r.j.error.message.slice(0, 32)})` : 'accepted';

// ---------------------------------------------------------------------------------------------
const A = await start({ installVerifier: true });

console.log('1. wire fidelity (client hashes exactly what it sends)');
const cases = [
  ['baseline', (p) => p],
  ['unknown field on the message', (p) => { p.message.futureField = 'x'; return p; }],
  ['unknown field on a part', (p) => { p.message.parts[0].futurePart = true; return p; }],
  ['unknown field on params', (p) => { p.futureParam = { a: 1 }; return p; }],
  ['unknown field in configuration', (p) => { p.configuration = { futureOpt: true }; return p; }],
  ['enum sent as a number', (p) => { p.message.role = 1; return p; }],
  ['explicit default values', (p) => { Object.assign(p.message, { taskId: '', contextId: '', extensions: [], referenceTaskIds: [] }); return p; }],
  ['snake_case field name', (p) => { p.message.message_id = p.message.messageId; delete p.message.messageId; return p; }],
  ['nested metadata', (p) => { p.message.metadata = { n: 1.5, nested: { a: [1, 2, null], s: 'é' } }; return p; }],
];
for (const [name, mutate] of cases) console.log(`   ${name}: ${outcome(await post(A.url, 'SendMessage', mutate(base())))}`);

console.log('\n2. attacks (executor must not run)');
const first = await post(A.url, 'SendMessage', { message: { messageId: 'f1', role: 'ROLE_USER', parts: [{ text: 'first' }] } });
const taskId = first.j.result.task.id;
const ran = executed;
const replay = await fetch(A.url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'SendMessage', params: first.sent }) }).then((r) => r.json());
console.log(`   replay: ${replay.error ? 'rejected ' + replay.error.code : 'ACCEPTED'}`);
const tamper = structuredClone(first.sent); tamper.message.parts[0].text = 'ALTERED';
console.log(`   altered part: ${outcome({ j: await fetch(A.url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'SendMessage', params: tamper }) }).then((r) => r.json()) })}`);
console.log(`   no proof: ${outcome(await post(A.url, 'SendMessage', base(), { sign: false }))}`);
console.log(`   wrong audience: ${outcome(await post(A.url, 'SendMessage', base(), { audience: 'did:web:x.example' }))}`);
const rogue = await newKey(CLIENT_DID); rogue.kid = client.kid;
console.log(`   signed by a key not in the DID: ${outcome(await post(A.url, 'SendMessage', base(), { signWith: await signerOf(rogue) }))}`);
console.log(`   executor ran ${executed - ran} extra time(s) (expected 0)`);
const stream = await post(A.url, 'SendStreamingMessage', { message: { messageId: 's1', role: 'ROLE_USER', parts: [{ text: 'x' }], taskId } }, { sign: false });
console.log(`   unproofed SendStreamingMessage to an existing task: ${outcome(stream)}`);
const snap = await A.store.load(taskId, new ServerCallContext({ user: { isAuthenticated: true, userName: CLIENT_DID } }));
console.log(`   task history afterwards: ${snap.history.length} (expected 1)`);

console.log('\n3. identity and scoping');
const tOther = await A.store.load(taskId, new ServerCallContext({ user: { isAuthenticated: true, userName: OTHER_DID } }));
console.log(`   task visible to the verified owner: true; to another verified DID: ${Boolean(tOther)}`);
const asOther = await post(A.url, 'SendMessage', { message: { messageId: 'o1', role: 'ROLE_USER', parts: [{ text: 'hijack' }], taskId } }, { signWith: await signerOf(other) });
console.log(`   another verified agent writing to that task: ${outcome(asOther)}`);

console.log('\n4. response proof');
const t = first.j.result.task;
const rp = await respVerifier.verifyProof(t.metadata[RESP_KEY], { ...server.pub, kid: server.kid }, { request: covered('SendMessage', first.sent), response: { data: taskForm(t) } }, { expectedDid: SERVER_DID, expectedAudience: CLIENT_DID });
console.log(`   proof on a normal response: valid=${rp.valid}`);
const trimmed = await post(A.url, 'SendMessage', { message: { messageId: 'h1', role: 'ROLE_USER', parts: [{ text: 'again' }], taskId }, configuration: { historyLength: 1 } });
const t2 = trimmed.j.result.task;
const rp2 = await respVerifier.verifyProof(t2.metadata[RESP_KEY], { ...server.pub, kid: server.kid }, { request: covered('SendMessage', trimmed.sent), response: { data: taskForm(t2) } }, { expectedDid: SERVER_DID, expectedAudience: CLIENT_DID });
console.log(`   proof with historyLength=1 (history ${t2.history.length}): valid=${rp2.valid}`);

console.log('\n5. misconfiguration: verifying userBuilder not installed');
const B = await start({ installVerifier: false });
console.log(`   proofed request: ${outcome(await post(B.url, 'SendMessage', base()))}`);

console.log('\n6. other methods are untouched');
const get = await fetch(A.url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'GetTask', params: { id: taskId } }) }).then((r) => r.json());
console.log(`   anonymous GetTask on the owner's task: ${get.error ? 'error ' + get.error.code + ' (not visible)' : 'RETURNED'}`);
A.srv.close(); B.srv.close();
