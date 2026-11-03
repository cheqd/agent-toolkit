// Does verifying the SDK's re-serialised params (wrapper) differ from verifying the wire body
// (middleware) when a client sends payloads the SDK does not model exactly?
// The client hashes exactly the JSON it sends, as a client in any language would.
import express from 'express';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK } from 'jose';
import { SendMessageRequest, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler, UserBuilder } from '@a2a-js/sdk/server/express';
import { buildCardProof, verifyCardProof, ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';

const ver = (p) => JSON.parse(readFileSync(new URL(`./node_modules/${p}/package.json`, import.meta.url))).version;
console.log(`@a2a-js/sdk ${ver('@a2a-js/sdk')}, @kya-os/mcp ${ver('@kya-os/mcp')}\n`);

const PROOF_KEY = 'org.kya-os/request-proof';
const CLIENT_DID = 'did:web:client.example';
const SERVER_DID = 'did:web:server.example';
const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
const priv = await exportJWK(privateKey);
const pub = { kty: 'OKP', crv: 'Ed25519', x: priv.x };
const kid = `${CLIENT_DID}#key-1`;
const signer = await ed25519SignerFromJwk({ did: CLIENT_DID, kid, privateJwk: priv });
const deps = () => ({ resolveKey: () => pub, resolveDidKeys: () => [pub], expectedAudience: SERVER_DID, consumeNonceIfFresh: new InMemoryNonceCache().consume });

const agentCard = {
  name: 'x', description: 'x', version: '1', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url: 'http://x', protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: false, pushNotifications: false }, securitySchemes: {}, securityRequirements: [],
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [], signatures: [],
};
const executor = { async execute(ctx, bus) {
  bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status: { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined }, artifacts: [], history: [], metadata: {} }));
  bus.finished();
}, async cancelTask() {} };

function covered(method, params) {
  const p = structuredClone(params);
  const md = p?.message?.metadata;
  if (md) { delete md[PROOF_KEY]; if (Object.keys(md).length === 0) delete p.message.metadata; }
  return { method, params: p };
}

const logs = { middleware: [], wrapper: [] };

// Server M: verifies the parsed wire body (what the client sent)
async function serverMiddleware() {
  const app = express(); app.use(express.json());
  app.use(async (req, res, next) => {
    const proof = req.body?.params?.message?.metadata?.[PROOF_KEY];
    if (!proof) { logs.middleware.push('no proof'); return res.status(401).json({}); }
    const r = await verifyCardProof(proof, covered(req.body.method, req.body.params), deps());
    logs.middleware.push(r.ok ? 'ok' : r.reasons.join(','));
    if (!r.ok) return res.status(401).json({});
    next();
  });
  app.use(jsonRpcHandler({ requestHandler: new DefaultRequestHandler(agentCard, new InMemoryTaskStore(), executor), userBuilder: UserBuilder.noAuthentication }));
  return new Promise((r) => { const s = app.listen(0, () => r(s)); });
}
// Server W: verifies params re-serialised from the SDK's typed form
async function serverWrapper() {
  const inner = new DefaultRequestHandler(agentCard, new InMemoryTaskStore(), executor);
  const wrapped = new Proxy(inner, { get(t, prop) {
    if (prop !== 'sendMessage') return typeof t[prop] === 'function' ? t[prop].bind(t) : t[prop];
    return async (params, ctx) => {
      const wire = SendMessageRequest.toJSON(params);
      const proof = wire.message?.metadata?.[PROOF_KEY];
      const r = proof ? await verifyCardProof(proof, covered('SendMessage', wire), deps()) : { ok: false, reasons: ['no proof'] };
      logs.wrapper.push(r.ok ? 'ok' : r.reasons.join(','));
      if (!r.ok) throw new Error('proof_invalid');
      return t.sendMessage(params, ctx);
    };
  } });
  const app = express(); app.use(express.json());
  app.use(jsonRpcHandler({ requestHandler: wrapped, userBuilder: UserBuilder.noAuthentication }));
  return new Promise((r) => { const s = app.listen(0, () => r(s)); });
}
const sM = await serverMiddleware(); const sW = await serverWrapper();
const urlM = `http://127.0.0.1:${sM.address().port}/`; const urlW = `http://127.0.0.1:${sW.address().port}/`;

const base = () => ({ message: { messageId: 'm1', role: 'ROLE_USER', parts: [{ text: 'hi' }] } });
const cases = [
  ['baseline', (p) => p],
  ['unknown field on the message', (p) => { p.message.futureField = 'x'; return p; }],
  ['unknown field on a part', (p) => { p.message.parts[0].futurePart = true; return p; }],
  ['unknown field on params', (p) => { p.futureParam = { a: 1 }; return p; }],
  ['unknown field in configuration', (p) => { p.configuration = { futureOpt: true }; return p; }],
  ['enum sent as a number (role: 1)', (p) => { p.message.role = 1; return p; }],
  ['explicit default values (empty ids and arrays)', (p) => { Object.assign(p.message, { taskId: '', contextId: '', extensions: [], referenceTaskIds: [] }); return p; }],
  ['snake_case field name (message_id)', (p) => { p.message.message_id = p.message.messageId; delete p.message.messageId; return p; }],
  ['nested metadata (floats, null, arrays)', (p) => { p.message.metadata = { n: 1.5, nested: { a: [1, 2, null], s: 'é' } }; return p; }],
  ['part with mediaType and filename', (p) => { Object.assign(p.message.parts[0], { mediaType: 'text/plain', filename: 'f.txt' }); return p; }],
];

async function send(url, params) {
  const proofed = structuredClone(params);
  const proof = await buildCardProof(covered('SendMessage', proofed), signer, { audience: SERVER_DID, nonce: randomBytes(16).toString('base64url') });
  proofed.message.metadata = { ...(proofed.message.metadata ?? {}), ...proof };
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'SendMessage', params: proofed }) });
  const j = await r.json().catch(() => ({}));
  return { http: r.status, rpc: j.error ? `error ${j.error.code}` : 'ok' };
}

console.log('case | middleware (wire body) | wrapper (SDK re-serialised)');
console.log('---|---|---');
for (const [name, mutate] of cases) {
  logs.middleware.length = 0; logs.wrapper.length = 0;
  const params = mutate(base());
  const m = await send(urlM, params); const w = await send(urlW, params);
  const fmt = (r, log) => `${log.at(-1) ?? '-'} (HTTP ${r.http}, ${r.rpc})`;
  console.log(`${name} | ${fmt(m, logs.middleware)} | ${fmt(w, logs.wrapper)}`);
}
sM.close(); sW.close();
