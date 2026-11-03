// Shared harness for the spikes: the chosen design (verifying userBuilder + enforcing wrapper),
// with counters so spikes can observe resolver traffic.
import express from 'express';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK, importJWK } from 'jose';
import { Task, TaskState } from '@a2a-js/sdk';
import { RequestMalformedError, ExtensionSupportRequiredError } from '@a2a-js/sdk/errors';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler, restHandler, UserBuilder } from '@a2a-js/sdk/server/express';
import { verifyCardProof, InMemoryNonceCache } from '@kya-os/mcp/card';
import { ProofGenerator } from '@kya-os/mcp/proof';
import { NodeCryptoProvider } from '@kya-os/mcp/providers';

export const PROOF_KEY = 'org.kya-os/request-proof';
export const RESP_KEY = 'org.kya-os/response-proof';
export const SERVER_DID = 'did:web:server.example';

export async function newKey(did, kid = `${did}#key-1`) {
  const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const priv = await exportJWK(privateKey);
  return { did, kid, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x } };
}

export const agentCard = (url = 'http://x') => ({
  name: 'x', description: 'x', version: '1', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }, { url, protocolBinding: 'HTTP+JSON', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false }, securitySchemes: {}, securityRequirements: [],
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [], signatures: [],
});

export function covered(method, params) {
  const p = structuredClone(params);
  const md = p?.message?.metadata;
  if (md) { delete md[PROOF_KEY]; if (Object.keys(md).length === 0) delete p.message.metadata; }
  return { method, params: p };
}
export const taskForm = (json) => { const t = structuredClone(json); if (t.metadata) { delete t.metadata[RESP_KEY]; if (!Object.keys(t.metadata).length) delete t.metadata; } return t; };

export async function makeHarness({ clientKeys = [], precheck = false } = {}) {
  const server = await newKey(SERVER_DID);
  const keys = [...clientKeys, server];
  const counters = { resolveKey: 0, resolveDidKeys: 0, executed: 0 };
  const nonceCache = new InMemoryNonceCache();
  const resolveKey = (kid) => { counters.resolveKey++; const k = keys.find((x) => x.kid === kid); if (!k) throw new Error('no such kid'); return k.pub; };
  const resolveDidKeys = (did) => { counters.resolveDidKeys++; return keys.filter((k) => k.did === did).map((k) => k.pub); };

  const executor = { async execute(ctx, bus) {
    counters.executed++;
    const status = { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined };
    if (!ctx.task) bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status, artifacts: [], history: [], metadata: {} }));
    else bus.publish(AgentEvent.statusUpdate({ taskId: ctx.taskId, contextId: ctx.contextId, status, metadata: {} }));
    bus.finished();
  }, async cancelTask() {} };

  // Cheap checks that need no network: shape, audience, time window. Runs BEFORE key resolution.
  const cheapReject = (proof) => {
    if (typeof proof !== 'object' || proof === null) return 'malformed_proof';
    if (proof.audience !== SERVER_DID) return 'audience_mismatch';
    const now = Math.floor(Date.now() / 1000);
    if (typeof proof.expires !== 'number' || proof.expires < now - 5) return 'expired';
    if (typeof proof.created !== 'number' || proof.created > now + 5) return 'not_yet_valid';
    return undefined;
  };

  const verifyingUserBuilder = async (req) => {
    const body = req.body;
    // JSON-RPC carries {method, params}; REST carries the params as the body and the method in the route.
    let method = body?.method, params = body?.params;
    if (method === undefined && /message:send$/.test(req.path ?? '')) { method = 'SendMessage'; params = body; }
    if (method === undefined && /message:stream$/.test(req.path ?? '')) { method = 'SendStreamingMessage'; params = body; }
    if (method !== 'SendMessage' && method !== 'SendStreamingMessage') return { isAuthenticated: false, userName: '' };
    const proof = params?.message?.metadata?.[PROOF_KEY];
    if (!proof) return { isAuthenticated: false, userName: '', rejection: 'missing' };
    if (precheck) { const early = cheapReject(proof); if (early) return { isAuthenticated: false, userName: '', rejection: early }; }
    const cov = covered(method, params);
    const r = await verifyCardProof(proof, cov, { resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume });
    return r.ok ? { isAuthenticated: true, userName: r.did, verified: { did: r.did, covered: cov } } : { isAuthenticated: false, userName: '', rejection: r.reasons[0] };
  };

  const respGen = new ProofGenerator({ did: server.did, kid: server.kid, privateKey: await importJWK(server.priv, 'EdDSA') }, new NodeCryptoProvider());
  const enforce = (ctx) => {
    const v = ctx.user?.verified;
    if (v) return v;
    const reason = ctx.user?.rejection ?? 'no_verifier_installed';
    throw reason === 'missing' || reason === 'no_verifier_installed'
      ? new ExtensionSupportRequiredError(`proof_required: ${reason}`)
      : new RequestMalformedError(`proof_invalid: ${reason}`);
  };
  const withAgentIdentity = (inner, { signResponses = true } = {}) => new Proxy(inner, { get(t, prop) {
    if (prop === 'sendMessage') return async (params, ctx) => {
      const v = enforce(ctx);
      const result = await t.sendMessage(params, ctx);
      if (signResponses && 'status' in result) {
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

  const store = new InMemoryTaskStore();
  const handler = withAgentIdentity(new DefaultRequestHandler(agentCard(), store, executor));
  const app = express();
  app.use(express.json());
  app.use('/rest', restHandler({ requestHandler: handler, userBuilder: verifyingUserBuilder }));
  app.use(jsonRpcHandler({ requestHandler: handler, userBuilder: verifyingUserBuilder }));
  const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  const port = srv.address().port;
  return { srv, port, url: `http://127.0.0.1:${port}/`, restUrl: `http://127.0.0.1:${port}/rest`, store, counters, server, keys, close: () => srv.close() };
}
