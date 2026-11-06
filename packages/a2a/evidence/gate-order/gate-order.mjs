// Does a proof gate written as an AgentExecutor decorator run before the SDK mutates task state?
// Tests @a2a-js/sdk (version printed below) with its public API only.
import { Role, TaskState } from '@a2a-js/sdk';
import {
  DefaultRequestHandler,
  InMemoryTaskStore,
  ServerCallContext,
  AgentEvent,
} from '@a2a-js/sdk/server';
import { readFileSync } from 'node:fs';

const sdkVersion = JSON.parse(
  readFileSync(new URL('./node_modules/@a2a-js/sdk/package.json', import.meta.url))
).version;

const PROOF_KEY = 'org.kya-os/request-proof';

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

// Inner executor: creates a task and leaves it waiting for input (non-terminal).
const inner = {
  async execute(ctx, bus) {
    const status = { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined };
    if (!ctx.task) {
      bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status, artifacts: [], history: [], metadata: {} }));
    } else {
      bus.publish(AgentEvent.statusUpdate({ taskId: ctx.taskId, contextId: ctx.contextId, status, metadata: {} }));
    }
    bus.finished();
  },
  async cancelTask() {},
};

const hasProof = (message) => Boolean(message?.metadata?.[PROOF_KEY]);

// Gate A: the placement the earlier plan described. Verifies inside the executor.
const executorGate = {
  async execute(ctx, bus) {
    if (!hasProof(ctx.userMessage)) throw new Error('proof_missing');
    return inner.execute(ctx, bus);
  },
  cancelTask: inner.cancelTask,
};

// Gate B: verifies in front of the request handler, before the SDK builds its context.
function requestHandlerGate(handler, { alsoStream }) {
  return {
    getAgentCard: () => handler.getAgentCard(),
    getTask: (p, c) => handler.getTask(p, c),
    listTasks: (p, c) => handler.listTasks(p, c),
    async sendMessage(params, ctx) {
      if (!hasProof(params.message)) throw new Error('proof_missing');
      return handler.sendMessage(params, ctx);
    },
    sendMessageStream: alsoStream
      ? async function* (params, ctx) {
          if (!hasProof(params.message)) throw new Error('proof_missing');
          yield* handler.sendMessageStream(params, ctx);
        }
      : (params, ctx) => handler.sendMessageStream(params, ctx), // wraps sendMessage only
  };
}

const user = (name) => ({ isAuthenticated: true, userName: name });
const ctxFor = (name) => new ServerCallContext({ user: name ? user(name) : undefined });

const msg = (id, text, { taskId, proof } = {}) => ({
  messageId: id, role: Role.ROLE_USER, taskId: taskId ?? '', contextId: '',
  parts: [{ content: { $case: 'text', value: text }, mediaType: 'text/plain', filename: '', metadata: undefined }],
  metadata: proof ? { [PROOF_KEY]: { prf: 'org.kya-os/proof.v1', stub: true } } : undefined,
  extensions: [], referenceTaskIds: [],
});
const req = (message) => ({ tenant: '', message, configuration: undefined, metadata: undefined });

async function snapshot(store, taskId, ctx) {
  const t = await store.load(taskId, ctx);
  if (!t) return null;
  const texts = (t.history ?? []).flatMap((m) => m.parts.map((p) => p.content?.value));
  return { state: TaskState[t.status?.state], historyLength: (t.history ?? []).length, texts };
}

async function attempt(label, fn) {
  try { const r = await fn(); return { label, outcome: 'returned', detail: r?.id ? `task ${TaskState[r.status?.state]}` : 'message' }; }
  catch (e) { return { label, outcome: 'threw', detail: e.message }; }
}

async function drain(gen) { try { for await (const _ of gen) { /* consume */ } return 'stream completed'; } catch (e) { return `stream threw: ${e.message}`; } }

const results = [];
const report = (title, obj) => { results.push({ title, ...obj }); };

async function scenario(name, build, { sameUserForInjection = true, useStream = false, gated = false } = {}) {
  const store = new InMemoryTaskStore();
  const base = new DefaultRequestHandler(agentCard, store, gated ? executorGate : inner);
  const handler = build(base);
  const alice = ctxFor('alice');
  const injector = sameUserForInjection ? ctxFor('alice') : ctxFor('mallory');

  // 1. legitimate, proofed first message creates the task
  const first = await handler.sendMessage(req(msg('m1', 'hello', { proof: true })), alice);
  const taskId = first.id;
  const before = await snapshot(store, taskId, alice);

  // 2. unproofed follow-up to the same task
  let attemptResult;
  if (useStream) {
    attemptResult = { label: 'unproofed follow-up (stream)', outcome: await drain(handler.sendMessageStream(req(msg('m2', 'INJECTED', { taskId })), injector)) };
  } else {
    attemptResult = await attempt('unproofed follow-up', () => handler.sendMessage(req(msg('m2', 'INJECTED', { taskId })), injector));
  }
  const after = await snapshot(store, taskId, alice);

  report(name, {
    firstState: before?.state, historyBefore: before?.historyLength,
    attempt: attemptResult, stateAfter: after?.state, historyAfter: after?.historyLength,
    injectedVisible: after?.texts.includes('INJECTED'),
  });
}

console.log(`@a2a-js/sdk ${sdkVersion}\n`);

await scenario('executor-gate', (h) => h, { gated: true });
await scenario('handler-gate (sendMessage only), via sendMessage', (h) => requestHandlerGate(h, { alsoStream: false }));
await scenario('handler-gate (sendMessage only), via sendMessageStream', (h) => requestHandlerGate(h, { alsoStream: false }), { useStream: true });
await scenario('handler-gate (both methods), via sendMessageStream', (h) => requestHandlerGate(h, { alsoStream: true }), { useStream: true });
await scenario('executor-gate, different user (owner scoping)', (h) => h, { sameUserForInjection: false, gated: true });

for (const r of results) {
  console.log(`## ${r.title}`);
  console.log(`   task after proofed call: state=${r.firstState}, history=${r.historyBefore}`);
  console.log(`   unproofed follow-up:     ${r.attempt.outcome}${r.attempt.detail ? ' (' + r.attempt.detail + ')' : ''}`);
  console.log(`   task afterwards:         state=${r.stateAfter}, history=${r.historyAfter}, injected message in history=${r.injectedVisible}\n`);
}
