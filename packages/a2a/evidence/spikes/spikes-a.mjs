// Spikes: (A) how the real SDK client surfaces rejections, (B) what persists and whether the owner
// can read its own task, (C) the REST transport, (E) resolver traffic caused by junk proofs.
import { randomBytes } from 'node:crypto';
import { Role, SendMessageRequest, Task } from '@a2a-js/sdk';
import { ServerCallContext } from '@a2a-js/sdk/server';
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from '@a2a-js/sdk/client';
import { buildCardProof, ed25519SignerFromJwk } from '@kya-os/mcp/card';
import { makeHarness, newKey, agentCard, covered, PROOF_KEY, RESP_KEY, SERVER_DID } from './harness.mjs';

const CLIENT_DID = 'did:web:client.example';
const client = await newKey(CLIENT_DID);
const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
const nonce = () => randomBytes(16).toString('base64url');
const line = (s = '') => console.log(s);

// ---------- A. real SDK client ---------------------------------------------------------------
{
  const h = await makeHarness({ clientKeys: [client] });
  const mode = { sign: true, audience: SERVER_DID };
  const interceptor = {
    async before(args) {
      if (args.input.method !== 'sendMessage' || !mode.sign) return;
      const params = args.input.value;
      const wire = SendMessageRequest.toJSON(params);
      const proof = await buildCardProof(covered('SendMessage', wire), signer, { audience: mode.audience, nonce: nonce() });
      params.message.metadata = { ...(params.message.metadata ?? {}), ...proof };
    },
    async after() {},
  };
  const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, { transports: [new JsonRpcTransportFactory()], clientConfig: { interceptors: [interceptor] } }));
  const a2a = await factory.createFromAgentCard(agentCard(h.url));
  const msg = (id) => ({ tenant: '', message: { messageId: id, role: Role.ROLE_USER, parts: [{ content: { $case: 'text', value: 'hi' }, mediaType: 'text/plain', filename: '', metadata: undefined }], contextId: '', taskId: '', metadata: undefined, extensions: [], referenceTaskIds: [] }, configuration: undefined, metadata: undefined });
  line('A. real SDK client');
  for (const [label, set] of [['valid proof', () => { mode.sign = true; mode.audience = SERVER_DID; }], ['no proof', () => { mode.sign = false; }], ['proof for another audience', () => { mode.sign = true; mode.audience = 'did:web:other.example'; }]]) {
    set();
    try { const r = await a2a.sendMessage(msg(label)); line(`   ${label}: returned ${r.id ? 'task' : 'message'}`); }
    catch (e) { line(`   ${label}: threw ${e.constructor.name}; message="${String(e.message).slice(0, 60)}"; code=${e.code}; reason=${e.reason}; instanceof Error=${e instanceof Error}`); }
  }
  h.close();
}

// ---------- B. persistence and owner reads ------------------------------------------------------
{
  const h = await makeHarness({ clientKeys: [client] });
  const post = async (method, params, { sign = true } = {}) => {
    const p = structuredClone(params);
    if (sign) { const proof = await buildCardProof(covered(method, p), signer, { audience: SERVER_DID, nonce: nonce() }); p.message.metadata = { ...(p.message.metadata ?? {}), ...proof }; }
    const r = await fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: p }) });
    return r.json();
  };
  const created = await post('SendMessage', { message: { messageId: 'b1', role: 'ROLE_USER', parts: [{ text: 'hi' }] } });
  const taskId = created.result.task.id;
  const stored = await h.store.load(taskId, new ServerCallContext({ user: { isAuthenticated: true, userName: CLIENT_DID } }));
  const historyHasProof = (stored.history ?? []).some((m) => m.metadata && PROOF_KEY in m.metadata);
  const taskHasRespProof = stored.metadata && RESP_KEY in stored.metadata;
  line('\nB. persistence and owner reads');
  line(`   request proof kept in stored message history: ${historyHasProof}`);
  line(`   response proof stored on the task: ${Boolean(taskHasRespProof)}`);
  const get = await fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'GetTask', params: { id: taskId } }) }).then((r) => r.json());
  line(`   the owner calling GetTask with no way to prove identity: ${get.error ? 'error ' + get.error.code : 'returned the task'}`);
  const later = await post('SendMessage', { message: { messageId: 'b2', role: 'ROLE_USER', parts: [{ text: 'again' }], taskId } });
  line(`   follow-up send by the owner: ${later.error ? 'error ' + later.error.code : 'ok'}; response proof present: ${Boolean(later.result?.task?.metadata?.[RESP_KEY])}`);
  h.close();
}

// ---------- C. REST ---------------------------------------------------------------------------
{
  const h = await makeHarness({ clientKeys: [client] });
  const params = { message: { messageId: 'c1', role: 'ROLE_USER', parts: [{ text: 'hi' }] } };
  const send = async (sign) => {
    const p = structuredClone(params);
    if (sign) { const proof = await buildCardProof(covered('SendMessage', p), signer, { audience: SERVER_DID, nonce: nonce() }); p.message.metadata = { ...proof }; }
    const r = await fetch(`${h.restUrl}/message:send`, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify(p) });
    return { status: r.status, body: await r.text() };
  };
  const ok = await send(true), bad = await send(false);
  line('\nC. REST transport (same userBuilder and wrapper, covered form is transport-neutral)');
  line(`   proofed POST /message:send: HTTP ${ok.status}; response proof present: ${ok.body.includes('response-proof')}`);
  line(`   unproofed POST /message:send: HTTP ${bad.status}; body=${bad.body.slice(0, 110)}`);
  line(`   executor ran ${h.counters.executed} time(s) (expected 1)`);
  h.close();
}

// ---------- E. junk-proof cost ------------------------------------------------------------------
{
  line('\nE. resolver traffic from 200 junk proofs (wrong audience / expired / garbage), key resolutions made');
  for (const precheck of [false, true]) {
    const h = await makeHarness({ clientKeys: [client], precheck });
    const attempts = [];
    for (let i = 0; i < 200; i++) {
      const kind = i % 3;
      const p = { message: { messageId: `j${i}`, role: 'ROLE_USER', parts: [{ text: 'x' }] } };
      const proof = await buildCardProof(covered('SendMessage', p), signer, { audience: kind === 0 ? 'did:web:other.example' : SERVER_DID, nonce: nonce(), ttlSec: 30, now: () => (kind === 1 ? Date.now() - 3_600_000 : Date.now()) });
      p.message.metadata = { ...proof };
      if (kind === 2) p.message.metadata[PROOF_KEY] = { ...proof[PROOF_KEY], jws: 'garbage' };
      attempts.push(fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify({ jsonrpc: '2.0', id: i, method: 'SendMessage', params: p }) }).then((r) => r.json()));
    }
    await Promise.all(attempts);
    line(`   ${precheck ? 'with' : 'without'} cheap pre-checks: resolveKey calls=${h.counters.resolveKey}, resolveDidKeys calls=${h.counters.resolveDidKeys}, executor ran=${h.counters.executed}`);
    h.close();
  }
}
