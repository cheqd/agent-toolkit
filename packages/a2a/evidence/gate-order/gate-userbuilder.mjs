// Does a proof gate placed in the SDK's `userBuilder` seam run before task state is touched,
// and does it scope tasks to the verified identity? Real HTTP through the Express JSON-RPC handler.
import express from 'express';
import { Role, TaskState } from '@a2a-js/sdk';
import {
  DefaultRequestHandler,
  InMemoryTaskStore,
  ServerCallContext,
  AgentEvent,
} from '@a2a-js/sdk/server';
import { jsonRpcHandler } from '@a2a-js/sdk/server/express';
import { readFileSync } from 'node:fs';

const sdkVersion = JSON.parse(
  readFileSync(new URL('./node_modules/@a2a-js/sdk/package.json', import.meta.url))
).version;

const PROOF_KEY = 'org.kya-os/request-proof';
const DID_A = 'did:web:agent-a.example';
const DID_B = 'did:web:agent-b.example';

const agentCard = {
  name: 'Gate test agent', description: 'x', version: '1.0.0', provider: undefined,
  documentationUrl: '',
  supportedInterfaces: [{ url: 'http://localhost/a2a', protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false },
  securitySchemes: {}, securityRequirements: [],
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
  signatures: [],
};

// Executor does no verification at all: the gate under test is the userBuilder.
const executor = {
  async execute(ctx, bus) {
    const status = { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined };
    if (!ctx.task) {
      bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status, artifacts: [], history: [], metadata: {} }));
    } else {
      bus.publish(AgentEvent.task({ ...ctx.task, status }));
    }
    bus.finished();
  },
  async cancelTask() {},
};

const store = new InMemoryTaskStore();
const handler = new DefaultRequestHandler(agentCard, store, executor);

let rawBodySeen = null;

// The gate. Stub verification: proof metadata must be present and name a DID.
// The returned user is the verified DID, so the task store scopes tasks to it.
const userBuilder = async (req) => {
  rawBodySeen = req.rawBody ? req.rawBody.length : 0; // can a real RFC 9421 digest be checked here?
  const proof = req.body?.params?.message?.metadata?.[PROOF_KEY];
  if (!proof?.did) throw new Error('proof_missing');
  return { isAuthenticated: true, userName: proof.did };
};

const app = express();
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(jsonRpcHandler({ requestHandler: handler, userBuilder }));
const server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
const url = `http://127.0.0.1:${server.address().port}/`;

let nextId = 1;
async function rpc(method, message, did) {
  const params = { message: { messageId: `m${nextId}`, role: Role.ROLE_USER, parts: [{ text: message.text }], ...(message.taskId ? { taskId: message.taskId } : {}),
    ...(did ? { metadata: { [PROOF_KEY]: { prf: 'org.kya-os/proof.v1', did } } } : {}) } };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
  });
  const text = await res.text();
  let body; try { body = JSON.parse(text); } catch { body = text.slice(0, 200); }
  return { status: res.status, body };
}

async function snapshot(taskId, did) {
  const t = await store.load(taskId, new ServerCallContext({ user: { isAuthenticated: true, userName: did } }));
  if (!t) return null;
  return { state: TaskState[t.status?.state], historyLength: (t.history ?? []).length,
    texts: (t.history ?? []).flatMap((m) => m.parts.map((p) => p.content?.value ?? p.text)) };
}

const lines = [];
const log = (s) => { lines.push(s); console.log(s); };
console.log(`@a2a-js/sdk ${sdkVersion}, express ${JSON.parse(readFileSync(new URL('./node_modules/express/package.json', import.meta.url))).version}\n`);

// 1. Agent A, proofed, creates a task
const created = await rpc('SendMessage', { text: 'hello' }, DID_A);
const taskId = created.body?.result?.task?.id ?? created.body?.result?.id;
log(`1. proofed create as A -> HTTP ${created.status}, task ${taskId ? 'created' : 'NOT created: ' + JSON.stringify(created.body).slice(0, 200)}`);
const before = await snapshot(taskId, DID_A);
log(`   task: state=${before?.state}, history=${before?.historyLength}; raw body bytes available to userBuilder: ${rawBodySeen}`);

// 2. Unproofed follow-up to A's task
const unproofed = await rpc('SendMessage', { text: 'INJECTED', taskId });
const afterUnproofed = await snapshot(taskId, DID_A);
log(`2. unproofed follow-up -> HTTP ${unproofed.status}, body ${JSON.stringify(unproofed.body).slice(0, 220)}`);
log(`   task afterwards: state=${afterUnproofed?.state}, history=${afterUnproofed?.historyLength}, injected present=${afterUnproofed?.texts.includes('INJECTED')}`);

// 3. Unproofed follow-up through the streaming method
const streamed = await rpc('SendStreamingMessage', { text: 'INJECTED-STREAM', taskId });
const afterStream = await snapshot(taskId, DID_A);
log(`3. unproofed follow-up via SendStreamingMessage -> HTTP ${streamed.status}, body ${JSON.stringify(streamed.body).slice(0, 220)}`);
log(`   task afterwards: state=${afterStream?.state}, history=${afterStream?.historyLength}, injected present=${afterStream?.texts.includes('INJECTED-STREAM')}`);

// 4. Proofed follow-up as a different agent B
const asB = await rpc('SendMessage', { text: 'from B', taskId }, DID_B);
const afterB = await snapshot(taskId, DID_A);
log(`4. proofed follow-up as B -> HTTP ${asB.status}, body ${JSON.stringify(asB.body).slice(0, 220)}`);
log(`   A's task afterwards: state=${afterB?.state}, history=${afterB?.historyLength}, B's text present=${afterB?.texts.includes('from B')}`);

// 5. Control: proofed follow-up as A
const asA = await rpc('SendMessage', { text: 'from A again', taskId }, DID_A);
const afterA = await snapshot(taskId, DID_A);
log(`5. proofed follow-up as A (control) -> HTTP ${asA.status}; history=${afterA?.historyLength}, text present=${afterA?.texts.includes('from A again')}`);

server.close();

// 6. Same gate as Express middleware ahead of the handler, so the failure can be a real 401.
const store2 = new InMemoryTaskStore();
const handler2 = new DefaultRequestHandler(agentCard, store2, executor);
const app2 = express();
app2.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
app2.use((req, res, next) => {
  const proof = req.body?.params?.message?.metadata?.[PROOF_KEY];
  if (!proof?.did) return res.status(401).set('WWW-Authenticate', 'A2A-Proof').json({ error: 'proof_missing' });
  req.agentDid = proof.did;
  next();
});
app2.use(jsonRpcHandler({ requestHandler: handler2, userBuilder: async (req) => ({ isAuthenticated: true, userName: req.agentDid }) }));
const server2 = await new Promise((resolve) => { const s = app2.listen(0, () => resolve(s)); });
const url2 = `http://127.0.0.1:${server2.address().port}/`;
const post2 = (message, did) => fetch(url2, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'SendMessage', params: { message: { messageId: 'x', role: Role.ROLE_USER, parts: [{ text: message.text }], ...(message.taskId ? { taskId: message.taskId } : {}), ...(did ? { metadata: { [PROOF_KEY]: { prf: 'p', did } } } : {}) } } }) });
const c2 = await (await post2({ text: 'hello' }, DID_A)).json();
const id2 = c2.result?.task?.id ?? c2.result?.id;
const u2 = await post2({ text: 'INJECTED', taskId: id2 });
const t2 = await store2.load(id2, new ServerCallContext({ user: { isAuthenticated: true, userName: DID_A } }));
log(`6. middleware variant, unproofed follow-up -> HTTP ${u2.status}, WWW-Authenticate=${u2.headers.get('www-authenticate')}, history=${(t2.history ?? []).length}`);
server2.close();
