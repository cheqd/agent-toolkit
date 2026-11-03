// Does a response proof made in the executor match what a client receives and can verify?
// Real HTTP through the Express JSON-RPC handler, SDK 1.3.0. Hash = SHA-256 over JCS (RFC 8785)
// of the task as JSON, with the proof key removed (and `metadata` removed if that leaves it empty).
import express from 'express';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize } from 'json-canonicalize';
import { Role, Task, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler, UserBuilder } from '@a2a-js/sdk/server/express';

const sdkVersion = JSON.parse(readFileSync(new URL('./node_modules/@a2a-js/sdk/package.json', import.meta.url))).version;
const PROOF_KEY = 'org.kya-os/response-proof';

const agentCard = {
  name: 'Response proof test', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url: 'http://localhost/a2a', protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false },
  securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
  signatures: [],
};

const sha = (obj) => createHash('sha256').update(canonicalize(obj)).digest('base64');

// The one hashing rule, used by whoever makes the proof and by the verifying client.
function coveredForm(taskJson) {
  const t = structuredClone(taskJson);
  if (t.metadata) {
    delete t.metadata[PROOF_KEY];
    if (Object.keys(t.metadata).length === 0) delete t.metadata;
  }
  return t;
}

let proveIn = 'executor'; // 'executor' | 'handler'
let executorView = null;

const executor = {
  async execute(ctx, bus) {
    const status = { state: TaskState.TASK_STATE_WORKING, message: undefined, timestamp: '2026-10-13T12:00:00.000Z' };
    const artifact = { artifactId: `a-${ctx.userMessage.messageId}`, name: 'out', description: '', parts: [{ content: { $case: 'text', value: 'result' }, mediaType: 'text/plain', filename: '', metadata: undefined }], metadata: undefined, extensions: [] };
    if (!ctx.task) {
      bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status, artifacts: [artifact], history: [], metadata: { note: 'created' } }));
      bus.finished();
      return;
    }
    // An honest executor-level implementation: it builds what it believes the final task is.
    const believed = { ...ctx.task, status, artifacts: [...(ctx.task.artifacts ?? []), artifact], metadata: { ...(ctx.task.metadata ?? {}), note: 'updated' } };
    executorView = coveredForm(Task.toJSON(believed));
    const meta = { note: 'updated' };
    if (proveIn === 'executor') meta[PROOF_KEY] = { hash: sha(executorView) };
    bus.publish(AgentEvent.statusUpdate({ taskId: ctx.taskId, contextId: ctx.contextId, status, metadata: meta }));
    bus.publish(AgentEvent.artifactUpdate({ taskId: ctx.taskId, contextId: ctx.contextId, artifact, append: false, lastChunk: true, metadata: undefined }));
    bus.finished();
  },
  async cancelTask() {},
};

const store = new InMemoryTaskStore();
const inner = new DefaultRequestHandler(agentCard, store, executor);

// Request-handler decorator: makes the proof over the final result, after the SDK has finished with it.
const handler = {
  getAgentCard: () => inner.getAgentCard(),
  getTask: (p, c) => inner.getTask(p, c),
  listTasks: (p, c) => inner.listTasks(p, c),
  cancelTask: (p, c) => inner.cancelTask(p, c),
  resubscribe: (p, c) => inner.resubscribe(p, c),
  sendMessageStream: (p, c) => inner.sendMessageStream(p, c),
  async sendMessage(params, ctx) {
    const result = await inner.sendMessage(params, ctx);
    if (proveIn === 'handler' && 'status' in result) {
      result.metadata = { ...(result.metadata ?? {}), [PROOF_KEY]: { hash: sha(coveredForm(Task.toJSON(result))) } };
    }
    return result;
  },
};

const app = express();
app.use(express.json());
app.use(jsonRpcHandler({ requestHandler: handler, userBuilder: UserBuilder.noAuthentication }));
const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
const url = `http://127.0.0.1:${server.address().port}/`;

let id = 1;
async function send(text, taskId, configuration) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' },
    body: JSON.stringify({ jsonrpc: '2.0', id: id++, method: 'SendMessage', params: { message: { messageId: `m${id}`, role: Role.ROLE_USER, parts: [{ text }], ...(taskId ? { taskId } : {}) }, ...(configuration ? { configuration } : {}) } }) });
  return res.json();
}

function summarise(taskJson) {
  return { state: taskJson.status?.state, history: (taskJson.history ?? []).length, artifacts: (taskJson.artifacts ?? []).length, metadataKeys: Object.keys(taskJson.metadata ?? {}).join(',') };
}

console.log(`@a2a-js/sdk ${sdkVersion}\n`);

async function scenario(label, mode, configuration) {
  proveIn = mode; executorView = null;
  const created = await send('hello');
  const taskId = created.result.task.id;
  await send('second', taskId);
  await send('third', taskId);
  const wire = await send('fourth', taskId, configuration);
  const taskJson = wire.result.task;
  const claimed = taskJson.metadata?.[PROOF_KEY]?.hash;
  const clientHash = sha(coveredForm(taskJson));
  const verifies = claimed === clientHash;
  console.log(`## ${label}`);
  console.log(`   proof present: ${Boolean(claimed)}; client recomputes the same hash: ${verifies}`);
  if (!verifies && executorView) {
    console.log(`   executor believed: ${JSON.stringify(summarise(executorView))}`);
    console.log(`   client received:   ${JSON.stringify(summarise(coveredForm(taskJson)))}`);
  } else {
    console.log(`   client received:   ${JSON.stringify(summarise(coveredForm(taskJson)))}`);
  }
  console.log();
}

await scenario('Proof made in the executor, full history', 'executor');
await scenario('Proof made in the executor, client asks for historyLength=1', 'executor', { historyLength: 1 });
await scenario('Proof made over the final result (handler decorator), full history', 'handler');
await scenario('Proof made over the final result (handler decorator), historyLength=1', 'handler', { historyLength: 1 });

server.close();
