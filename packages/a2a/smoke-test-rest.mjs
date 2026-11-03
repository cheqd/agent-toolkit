// Smoke test: the same gate (createVerifyingUserBuilder + withAgentIdentity) mounted over
// @a2a-js/sdk's restHandler instead of jsonRpcHandler - no new code needed for this transport,
// user-builder.ts's methodAndParamsFor() already infers the method from the route when the body
// carries no {method, params} wrapper (confirmed against the real restHandler, not assumed).
import express from 'express';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK, importJWK } from 'jose';
import { TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { restHandler } from '@a2a-js/sdk/server/express';
import { buildCardProof, ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import { NodeCryptoProvider } from '@kya-os/mcp/providers';
import { coveredRequest, createVerifyingUserBuilder, withAgentIdentity } from './dist/index.js';

const CLIENT_DID = 'did:web:client.example';
const SERVER_DID = 'did:web:server.example';

async function newKey(did) {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const priv = await exportJWK(privateKey);
  return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x }, cryptoKey: privateKey };
}
const client = await newKey(CLIENT_DID);
const server = await newKey(SERVER_DID);
const resolveKey = (kid) => (kid === client.kid ? client.pub : kid === server.kid ? server.pub : (() => { throw new Error('no such kid'); })());
const resolveDidKeys = (did) => (did === CLIENT_DID ? [client.pub] : did === SERVER_DID ? [server.pub] : []);
const nonceCache = new InMemoryNonceCache();

const agentCard = { name: 'REST smoke test', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url: 'http://x', protocolBinding: 'HTTP+JSON', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false }, securitySchemes: {}, securityRequirements: [],
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [], signatures: [] };

let executed = 0;
const executor = { async execute(ctx, bus) {
  executed++;
  bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status: { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined }, artifacts: [], history: [], metadata: {} }));
  bus.finished();
}, async cancelTask() {} };

const store = new InMemoryTaskStore();
const userBuilder = createVerifyingUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume });
const handler = withAgentIdentity(new DefaultRequestHandler(agentCard, store, executor), {
  serverDid: SERVER_DID, serverKid: server.kid, privateKey: server.cryptoKey, publicKey: server.priv.d, cryptoProvider: new NodeCryptoProvider(),
});

const app = express();
app.use(express.json());
app.use('/rest', restHandler({ requestHandler: handler, userBuilder: (req) => userBuilder(req) }));
const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
const restUrl = `http://127.0.0.1:${srv.address().port}/rest`;

const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
const message = (id) => ({ messageId: id, role: 'ROLE_USER', parts: [{ text: 'hi' }], contextId: '', taskId: '', extensions: [], referenceTaskIds: [] });

async function post(path, params, sign) {
  const body = structuredClone(params);
  if (sign) {
    const proof = await buildCardProof(coveredRequest('SendMessage', body), signer, { audience: SERVER_DID, nonce: randomBytes(16).toString('base64url') });
    body.message.metadata = { ...proof };
  }
  const r = await fetch(`${restUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.text() };
}

const line = (s) => console.log(s);

const ok = await post('/message:send', { message: message('r1') }, true);
line(`1. proofed POST /message:send -> HTTP ${ok.status}; response proof present: ${ok.body.includes('response-proof')}; executor ran ${executed}x`);

const before = executed;
const bad = await post('/message:send', { message: message('r2') }, false);
line(`2. unproofed POST /message:send -> HTTP ${bad.status} ${bad.body.slice(0, 120)}; executor ran ${executed - before}x since (expected 0)`);

srv.close();
