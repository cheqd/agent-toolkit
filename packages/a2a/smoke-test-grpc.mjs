// Smoke test: the gate over gRPC, via createVerifyingGrpcUserBuilder (a different seam from
// Express's userBuilder entirely - reads call.request, discriminates the RPC via call.path).
// Real @grpc/grpc-js server and client, no mocks beyond in-memory DIDs.
//
// Scenario 1 (a correctly proofed call) is EXPECTED TO FAIL right now, and that failure is the
// actual finding, not a bug in this test: client.ts's createProofInterceptor computes the
// covered form via SendMessageRequest.toJSON(params) - the JSON-RPC wire shape (defaults
// omitted, enums as strings, oneofs flattened, e.g. `{text: "hi"}`). gRPC's call.request on the
// server is the SDK's deserialized protobuf object instead (defaults present, enums numeric,
// oneofs as `{content: {$case: "text", value: "hi"}}`). The two shapes differ structurally, so
// the recomputed requestHash never matches and every gRPC proof is rejected as
// request_hash_mismatch - confirmed by diffing both shapes directly, not inferred from the
// error alone. There is no janky wire JSON for gRPC to canonicalise against in the first place:
// the real wire form is binary protobuf. Fixing this needs a real design decision (a
// gRPC-specific covered-form definition? raw protobuf bytes, if the SDK exposes them before
// decode? one proof that can never cross transports?) - not made here. Scenario 2 (the
// unproofed-call rejection) is unaffected and passes for real: the gate itself - call.path
// method detection, enforcement, typed-error mapping - works correctly over gRPC.
import * as grpc from '@grpc/grpc-js';
import { generateKeyPair, exportJWK } from 'jose';
import { Role, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { A2AService, grpcService } from '@a2a-js/sdk/server/grpc';
import { GrpcTransportFactory } from '@a2a-js/sdk/client/grpc';
import { ClientFactory, ClientFactoryOptions } from '@a2a-js/sdk/client';
import { ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider, RuntimeFetchProvider } from '@kya-os/mcp/providers';
import { createVerifyingGrpcUserBuilder, withAgentIdentity, createProofInterceptor, PROOF_META_KEY } from './dist/index.js';

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

const agentCard = (url) => ({
  name: 'gRPC gate smoke test', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url, protocolBinding: 'GRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false },
  securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
  signatures: [],
});

let executed = 0;
const executor = { async execute(ctx, bus) {
  executed++;
  bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status: { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined }, artifacts: [], history: [], metadata: {} }));
  bus.finished();
}, async cancelTask() {} };

const store = new InMemoryTaskStore();
const userBuilder = createVerifyingGrpcUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume });
// userBuilder must throw a typed A2A error, not a plain Error, for a clean client-side signal
// (confirmed in evidence/transports/grpc-gate.mjs) - but createVerifyingGrpcUserBuilder returns
// an unauthenticated user rather than throwing, so the typed-error mapping happens in the
// wrapper's enforce(), which already throws ExtensionSupportRequiredError/RequestMalformedError.
const handler = withAgentIdentity(new DefaultRequestHandler(agentCard('x'), store, executor), {
  serverDid: SERVER_DID, serverKid: server.kid, privateKey: server.cryptoKey, publicKey: server.priv.d, cryptoProvider: new NodeCryptoProvider(),
});

const server_ = new grpc.Server();
server_.addService(A2AService, grpcService({ requestHandler: handler, userBuilder: (call) => userBuilder(call) }));
const port = await new Promise((resolve, reject) => {
  server_.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, p) => (err ? reject(err) : resolve(p)));
});

const url = `127.0.0.1:${port}`;
const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
const { interceptor, state } = createProofInterceptor({
  signer, serverDid: SERVER_DID, clientDid: CLIENT_DID, serverPublicJwk: { ...server.pub, kid: server.kid },
  extensionUri: 'https://kya-os.org/a2a/ext/proof/v1',
  cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(),
  nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider(),
});
const proofedFactory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
  transports: [new GrpcTransportFactory({ grpcChannelCredentials: grpc.credentials.createInsecure() })],
  clientConfig: { interceptors: [interceptor] },
}));
const proofedClient = await proofedFactory.createFromAgentCard(agentCard(url));

// A second client with NO interceptor, to test the gate's rejection path for real (the first
// client's interceptor always attaches a valid proof, so it cannot send an unproofed request).
const bareFactory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
  transports: [new GrpcTransportFactory({ grpcChannelCredentials: grpc.credentials.createInsecure() })],
}));
const bareClient = await bareFactory.createFromAgentCard(agentCard(url));

const message = (id) => ({ messageId: id, role: Role.ROLE_USER, parts: [{ content: { $case: 'text', value: 'hi' }, mediaType: 'text/plain', filename: '', metadata: undefined }], contextId: '', taskId: '', metadata: undefined, extensions: [], referenceTaskIds: [] });
const line = (s) => console.log(s);

try {
  const r = await proofedClient.sendMessage({ tenant: '', message: message('g1'), configuration: undefined, metadata: undefined });
  line(`1. proofed call over real gRPC through the gate -> task ${r?.id}; executor ran ${executed}x`);
} catch (e) { line(`1. proofed call over real gRPC -> THREW ${e.message}; executor ran ${executed}x`); }
line(`1b. response proof verified by the client interceptor -> ${JSON.stringify(state.lastResponseCheck)}`);

const before = executed;
try {
  await bareClient.sendMessage({ tenant: '', message: message('g2'), configuration: undefined, metadata: undefined });
  line('2. unproofed call -> unexpectedly returned');
} catch (e) {
  line(`2. unproofed call -> THREW ${e.constructor.name}: ${e.message}; executor ran ${executed - before}x since (expected 0)`);
}

server_.forceShutdown();
