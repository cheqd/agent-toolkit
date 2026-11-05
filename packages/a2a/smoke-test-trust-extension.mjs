// Smoke test for the trust extension wired INTO the gate (wrapper.ts's `enforce`), not just the
// standalone verifyTrustExtension/createTrustExtensionCache module (that's unit-tested in
// test/trust-extension.test.mjs). Proves: a correctly-proofed caller whose trust-extension
// checks fail is still rejected by withAgentIdentity, with the executor never running; a caller
// whose checks pass is accepted.
import express from 'express';
import { generateKeyPair, exportJWK } from 'jose';
import { Role, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler } from '@a2a-js/sdk/server/express';
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from '@a2a-js/sdk/client';
import { ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider, RuntimeFetchProvider } from '@kya-os/mcp/providers';
import { createVerifyingUserBuilder, withAgentIdentity, createProofInterceptor, createTrustExtensionCache } from './dist/index.js';

const EXT_URI = 'https://kya-os.org/a2a/ext/proof/v1';
const CLIENT_DID = 'did:web:client.example';
const SERVER_DID = 'did:web:server.example';
const line = (s) => console.log(s);

async function newKey(did) {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const priv = await exportJWK(privateKey);
  const pub = await exportJWK(publicKey);
  return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x }, cryptoKey: privateKey };
}
const client = await newKey(CLIENT_DID);
const server = await newKey(SERVER_DID);
const resolveKey = (kid) => (kid === client.kid ? client.pub : kid === server.kid ? server.pub : (() => { throw new Error('no such kid'); })());
const resolveDidKeys = (did) => (did === CLIENT_DID ? [client.pub] : did === SERVER_DID ? [server.pub] : []);

const agentCard = (url) => ({
  name: 'trust extension smoke test', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [{ uri: EXT_URI, description: 'proof', required: true, params: {} }], streaming: true, pushNotifications: false },
  securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
  signatures: [],
});
const message = (id, text) => ({ messageId: id, role: Role.ROLE_USER, parts: [{ content: { $case: 'text', value: text }, mediaType: 'text/plain', filename: '', metadata: undefined }], contextId: '', taskId: '', metadata: undefined, extensions: [], referenceTaskIds: [] });

async function run(trustExtensionOk) {
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
  const nonceCache = new InMemoryNonceCache();
  const userBuilder = createVerifyingUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume });
  const deps = { resolveDidDocument: async () => null, manifestCache: { get: async () => ({ ok: true }), clear() {} }, checkStatus: async () => ({ revoked: !trustExtensionOk, fresh: true }) };
  const trustExtension = { cache: createTrustExtensionCache(deps), activation: { statusCheck: 'required' } };
  const handler = withAgentIdentity(
    new DefaultRequestHandler(agentCard('http://x'), store, executor),
    { serverDid: SERVER_DID, serverKid: server.kid, privateKey: server.cryptoKey, publicKey: server.priv.d, cryptoProvider: new NodeCryptoProvider() },
    trustExtension,
  );
  const app = express();
  app.use(express.json());
  app.use(jsonRpcHandler({ requestHandler: handler, userBuilder: async (req) => userBuilder(req) }));
  const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  const url = `http://127.0.0.1:${srv.address().port}/`;

  const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
  const { interceptor } = createProofInterceptor({
    signer, serverDid: SERVER_DID, clientDid: CLIENT_DID, serverPublicJwk: { ...server.pub, kid: server.kid },
    extensionUri: EXT_URI, cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider(),
  });
  const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, { transports: [new JsonRpcTransportFactory()], clientConfig: { interceptors: [interceptor] } }));
  const a2a = await factory.createFromAgentCard(agentCard(url));
  try {
    const task = await a2a.sendMessage({ tenant: '', message: message('m1', 'hello'), configuration: undefined, metadata: undefined });
    line(`trustExtensionOk=${trustExtensionOk} -> task ${task?.id}; executor ran ${executed}x`);
  } catch (e) {
    line(`trustExtensionOk=${trustExtensionOk} -> THREW ${e.message}; executor ran ${executed}x (expected 0)`);
  }
  srv.close();
}

await run(true);
await run(false);
