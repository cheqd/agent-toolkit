// Smoke test for the WS1 reference implementation (dist/) against a real @a2a-js/sdk 1.3.0
// client + Express server. Same scenarios as evidence/gate-order/slice-both.mjs and
// slice-userbuilder-wrapper.mjs, now through the reusable library instead of throwaway inline
// code - this is the thing those scripts were building toward, not a new design.
import express from 'express';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK, importJWK } from 'jose';
import { Role, SendMessageRequest, TaskState, Task } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler } from '@a2a-js/sdk/server/express';
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from '@a2a-js/sdk/client';
import { ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider, RuntimeFetchProvider } from '@kya-os/mcp/providers';
import { createVerifyingUserBuilder, withAgentIdentity, createProofInterceptor, PROOF_META_KEY } from './dist/index.js';

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
const didDocs = { [CLIENT_DID]: [client], [SERVER_DID]: [server] };
const resolveKey = (kid) => { const k = Object.values(didDocs).flat().find((d) => d.kid === kid); if (!k) throw new Error('no such kid'); return k.pub; };
const resolveDidKeys = (did) => (didDocs[did] ?? []).map((d) => d.pub);
const nonceCache = new InMemoryNonceCache();

const agentCard = (url) => ({
  name: 'WS1 smoke test', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [{ uri: EXT_URI, description: 'proof', required: true, params: {} }], streaming: true, pushNotifications: false },
  securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
  signatures: [],
});

let executed = 0;
const executor = {
  async execute(ctx, bus) {
    executed++;
    bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status: { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined }, artifacts: [], history: [], metadata: {} }));
    bus.finished();
  },
  async cancelTask() {},
};

const store = new InMemoryTaskStore();
const userBuilder = createVerifyingUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume });
const handler = withAgentIdentity(new DefaultRequestHandler(agentCard('http://x'), store, executor), {
  serverDid: SERVER_DID,
  serverKid: server.kid,
  privateKey: server.cryptoKey,
  publicKey: server.priv.d,
  cryptoProvider: new NodeCryptoProvider(),
});

const app = express();
app.use(express.json());
app.use(jsonRpcHandler({ requestHandler: handler, userBuilder: async (req) => userBuilder(req) }));
const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
const url = `http://127.0.0.1:${srv.address().port}/`;

const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
const { interceptor, state } = createProofInterceptor({
  signer, serverDid: SERVER_DID, clientDid: CLIENT_DID,
  serverPublicJwk: { ...server.pub, kid: server.kid },
  extensionUri: EXT_URI,
  cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(),
  nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider(),
});

const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
  transports: [new JsonRpcTransportFactory()], clientConfig: { interceptors: [interceptor] },
}));
const a2a = await factory.createFromAgentCard(agentCard(url));

const message = (id, text) => ({ messageId: id, role: Role.ROLE_USER, parts: [{ content: { $case: 'text', value: text }, mediaType: 'text/plain', filename: '', metadata: undefined }], contextId: '', taskId: '', metadata: undefined, extensions: [], referenceTaskIds: [] });
const line = (s) => console.log(s);

let r1;
try {
  r1 = await a2a.sendMessage({ tenant: '', message: message('m1', 'hello'), configuration: undefined, metadata: undefined });
  line(`1. real client round trip through the reusable gate/interceptor -> task ${r1?.id}; executor ran ${executed}x`);
} catch (e) { line(`1. THREW ${e.message}`); }
line(`1b. response proof verified by the client interceptor -> ${JSON.stringify(state.lastResponseCheck)}`);

const before = executed;
const post = async (body, headers = {}) => { const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0', ...headers }, body: JSON.stringify({ jsonrpc: '2.0', id: 9, ...body }) }); return { status: r.status, body: await r.text() }; };
const bare = { method: 'SendMessage', params: { message: { messageId: 'm2', role: 'ROLE_USER', parts: [{ text: 'x' }], contextId: '', taskId: r1?.id ?? '', extensions: [], referenceTaskIds: [] } } };
const r2 = await post(bare);
line(`2. unproofed follow-up to a live task -> HTTP ${r2.status} ${r2.body.slice(0, 160)}; executor ran ${executed - before}x since (expected 0)`);

// 3. Replay: capture a real proofed request, resend it verbatim.
let capturedWire = null;
const captureInterceptor = { async before(args) {
  if (args.input.method !== 'sendMessage') return;
  const wire = SendMessageRequest.toJSON(args.input.value);
  await interceptor.before(args);
  capturedWire = { method: 'SendMessage', params: SendMessageRequest.toJSON(args.input.value) };
}, after: interceptor.after };
const factory2 = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
  transports: [new JsonRpcTransportFactory()], clientConfig: { interceptors: [captureInterceptor] },
}));
const a2a2 = await factory2.createFromAgentCard(agentCard(url));
await a2a2.sendMessage({ tenant: '', message: message('m3', 'capture me'), configuration: undefined, metadata: undefined });
const r3 = await post(capturedWire);
line(`3. replay of a captured proofed request -> HTTP ${r3.status} ${r3.body.slice(0, 160)}`);

srv.close();
