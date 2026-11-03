// Vertical slice, request half: a real @a2a-js/sdk client mints an org.kya-os/proof.v1 request
// proof with @kya-os/mcp's buildCardProof; an Express middleware verifies it with verifyCardProof
// before the SDK touches any task. did:web only, in-memory DID resolution, no cheqd.
import express from 'express';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, importJWK } from 'jose';
import { Role, SendMessageRequest, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler } from '@a2a-js/sdk/server/express';
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from '@a2a-js/sdk/client';
import { buildCardProof, verifyCardProof, ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import { ProofGenerator, ProofVerifier } from '@kya-os/mcp/proof';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider, RuntimeFetchProvider } from '@kya-os/mcp/providers';
import { Task } from '@a2a-js/sdk';

const ver = (p) => JSON.parse(readFileSync(new URL(`./node_modules/${p}/package.json`, import.meta.url))).version;
console.log(`@a2a-js/sdk ${ver('@a2a-js/sdk')}, @kya-os/mcp ${ver('@kya-os/mcp')}\n`);

const PROOF_KEY = 'org.kya-os/request-proof';
const RESP_KEY = 'org.kya-os/response-proof';
const EXT_URI = 'https://kya-os.org/a2a/ext/proof/v1';
const CLIENT_DID = 'did:web:client.example';
const SERVER_DID = 'did:web:server.example';

// --- keys and an in-memory "DID resolution" --------------------------------------------------
async function newKey(did) {
  const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const priv = await exportJWK(privateKey);
  return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x } };
}
const client = await newKey(CLIENT_DID);
const server = await newKey(SERVER_DID);
const didDocs = { [CLIENT_DID]: [client], [SERVER_DID]: [server] };
const resolveKey = (kid) => { const k = Object.values(didDocs).flat().find((d) => d.kid === kid); if (!k) throw new Error('no such kid'); return k.pub; };
const resolveDidKeys = (did) => (didDocs[did] ?? []).map((d) => d.pub);
const nonceCache = new InMemoryNonceCache();

// --- server ----------------------------------------------------------------------------------
const agentCard = (url) => ({
  name: 'Slice agent', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
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
    const status = { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined };
    bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status, artifacts: [], history: [], metadata: {} }));
    bus.finished();
  },
  async cancelTask() {},
};

// The A2A covered request: the wire JSON-RPC method and params, with the proof key removed.
function coveredRequest(method, params) {
  const p = structuredClone(params);
  const md = p?.message?.metadata;
  if (md) { delete md[PROOF_KEY]; if (Object.keys(md).length === 0) delete p.message.metadata; }
  return { method, params: p };
}


// --- response proof: made over the FINAL result, in a request-handler decorator -----------------
const respGen = new ProofGenerator({ did: server.did, kid: server.kid, privateKey: await importJWK(server.priv, 'EdDSA') }, new NodeCryptoProvider());
function taskCoveredForm(taskJson) {
  const t = structuredClone(taskJson);
  if (t.metadata) { delete t.metadata[RESP_KEY]; if (Object.keys(t.metadata).length === 0) delete t.metadata; }
  return t;
}
function responseProver(inner) {
  return new Proxy(inner, { get(target, prop) {
    if (prop !== 'sendMessage') return typeof target[prop] === 'function' ? target[prop].bind(target) : target[prop];
    return async (params, ctx) => {
      const result = await target.sendMessage(params, ctx);
      const v = ctx.user?.verified;
      if (v && 'status' in result) {
        const data = taskCoveredForm(Task.toJSON(result));
        const session = { sessionId: 'a2a-stateless', audience: v.did, nonce: randomBytes(16).toString('base64url'), timestamp: Date.now(), createdAt: Date.now(), lastActivity: Date.now(), ttlMinutes: 1 };
        const proof = await respGen.generateProof(v.covered, { data }, session, { profile: 'org.kya-os/response-proof.envelope' });
        result.metadata = { ...(result.metadata ?? {}), [RESP_KEY]: proof };
      }
      return result;
    };
  } });
}

const verifyLog = [];
const store = new InMemoryTaskStore();
let url;
const app = express();
app.use(express.json());
app.use(async (req, res, next) => {
  const { method, params } = req.body ?? {};
  if (method !== 'SendMessage' && method !== 'SendStreamingMessage') return next();
  const proof = params?.message?.metadata?.[PROOF_KEY];
  if (!proof) { verifyLog.push('no proof'); return res.status(401).json({ error: 'proof_missing' }); }
  const result = await verifyCardProof(proof, coveredRequest(method, params), {
    resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume,
  });
  verifyLog.push(result.ok ? `ok ${result.level} ${result.did}; extHeader=${req.header('a2a-extensions')}` : `rejected: ${result.reasons.join(',')}`);
  if (!result.ok) return res.status(401).json({ error: 'proof_invalid' });
  req.agentDid = result.did;
  req.verified = { did: result.did, covered: coveredRequest(method, params) };
  next();
});
const handler = new DefaultRequestHandler(agentCard('http://x'), store, executor);
app.use(jsonRpcHandler({ requestHandler: responseProver(handler), userBuilder: async (req) => ({ isAuthenticated: true, userName: req.agentDid ?? 'anonymous', verified: req.verified }) }));
const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
url = `http://127.0.0.1:${srv.address().port}/`;

// --- client: a real A2A client with a proof interceptor ---------------------------------------
let lastWire = null;
let lastCovered = null;
let responseCheck = null;
let lastResponseJson = null;
const respVerifier = new ProofVerifier({ cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider() });
const verifyResponse = (json, covered) => {
  const proof = json.metadata?.[RESP_KEY];
  if (!proof) return Promise.resolve({ valid: false, reason: 'no response proof' });
  return respVerifier.verifyProof(proof, { ...server.pub, kid: server.kid }, { request: covered, response: { data: taskCoveredForm(json) } }, { expectedDid: SERVER_DID, expectedAudience: CLIENT_DID });
};
const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
const proofInterceptor = {
  async before(args) {
    if (args.input.method !== 'sendMessage') return;
    const params = args.input.value;
    const wire = SendMessageRequest.toJSON(params);          // the form the transport puts on the wire
    const proof = await buildCardProof(coveredRequest('SendMessage', wire), signer, { audience: SERVER_DID, nonce: randomBytes(16).toString('base64url') });
    params.message.metadata = { ...(params.message.metadata ?? {}), ...proof };
    args.options.serviceParameters['A2A-Extensions'] = EXT_URI;
    lastWire = { method: 'SendMessage', params: SendMessageRequest.toJSON(params) };
    lastCovered = coveredRequest('SendMessage', wire);
  },
  async after(args) {
    if (args.result.method !== 'sendMessage') return;
    const t = args.result.value;
    if (!t || !('status' in t)) return;
    lastResponseJson = Task.toJSON(t);
    responseCheck = await verifyResponse(lastResponseJson, lastCovered);
  },
};
const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
  transports: [new JsonRpcTransportFactory()], clientConfig: { interceptors: [proofInterceptor] },
}));
const a2a = await factory.createFromAgentCard(agentCard(url));

const message = (id, text) => ({ messageId: id, role: Role.ROLE_USER, parts: [{ content: { $case: 'text', value: text }, mediaType: 'text/plain', filename: '', metadata: undefined }], contextId: '', taskId: '', metadata: undefined, extensions: [], referenceTaskIds: [] });
const line = (s) => console.log(s);

// 1. Happy path through the real client
let r1;
try { r1 = await a2a.sendMessage({ tenant: '', message: message('m1', 'hello'), configuration: undefined, metadata: undefined }); line(`1. real client round trip -> returned ${r1?.id ? 'task ' + r1.id : JSON.stringify(r1).slice(0, 120)}; executor ran ${executed}x; server: ${verifyLog.at(-1)}`); }
catch (e) { line(`1. real client round trip -> THREW ${e.message}; server: ${verifyLog.at(-1)}`); }

line(`1b. response proof verified by the client interceptor -> ${JSON.stringify(responseCheck)}`);
{
  const tampered = structuredClone(lastResponseJson);
  tampered.status.state = 'TASK_STATE_COMPLETED';
  const t = await verifyResponse(tampered, lastCovered);
  line(`1c. response altered after proving (status changed) -> valid=${t.valid} ${t.reason ?? ''}`);
  const otherReq = structuredClone(lastCovered); otherReq.params.message.messageId = 'some-other-request';
  const o = await verifyResponse(lastResponseJson, otherReq);
  line(`1d. same response proof presented for a different request -> valid=${o.valid} ${o.reason ?? ''}`);
}
// 1e. a client that asks for trimmed history
{
  const r = await a2a.sendMessage({ tenant: '', message: { ...message('m-hist', 'second'), taskId: r1.id, contextId: r1.contextId }, configuration: { historyLength: 1, returnImmediately: false, acceptedOutputModes: [], taskPushNotificationConfig: undefined }, metadata: undefined });
  line(`1e. follow-up with historyLength=1 -> history ${r?.history?.length}; response proof valid=${responseCheck?.valid} ${responseCheck?.reason ?? ''}`);
}

// 2-6. Attacks, replayed as raw HTTP using the captured valid request
const post = async (body, headers = {}) => { const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0', 'A2A-Extensions': EXT_URI, ...headers }, body: JSON.stringify({ jsonrpc: '2.0', id: 9, ...body }) }); return r.status; };
const before = executed;
const captured = structuredClone(lastWire);

line(`2. replay of the same request -> HTTP ${await post(captured)}; server: ${verifyLog.at(-1)}`);

const alteredPart = structuredClone(captured); alteredPart.params.message.parts[0].text = 'ALTERED';
line(`3. altered message part, same proof -> HTTP ${await post(alteredPart)}; server: ${verifyLog.at(-1)}`);

const alteredCtx = structuredClone(captured); alteredCtx.params.message.contextId = 'other-context';
line(`4. altered contextId, same proof -> HTTP ${await post(alteredCtx)}; server: ${verifyLog.at(-1)}`);

// fresh nonce proofs for audience and key tests
const mint = async (sgn, aud, wire) => ({ ...wire, params: { ...wire.params, message: { ...wire.params.message, metadata: { ...(await buildCardProof(coveredRequest('SendMessage', wire.params), sgn, { audience: aud, nonce: randomBytes(16).toString('base64url') })) } } } });
const bare = structuredClone(captured); delete bare.params.message.metadata;
line(`5. proof for a different audience -> HTTP ${await post(await mint(signer, 'did:web:someone-else.example', bare))}; server: ${verifyLog.at(-1)}`);

const rogue = await newKey(CLIENT_DID); // attacker key claiming the client's DID, not in its DID document
const rogueSigner = await ed25519SignerFromJwk({ did: rogue.did, kid: rogue.kid, privateJwk: rogue.priv });
line(`6. key not published in the DID document -> HTTP ${await post(await mint(rogueSigner, SERVER_DID, bare))}; server: ${verifyLog.at(-1)}`);

line(`7. no proof -> HTTP ${await post(bare)}; server: ${verifyLog.at(-1)}`);
line(`   executor ran ${executed - before} extra time(s) during attacks 2-7 (expected 0)`);

srv.close();
