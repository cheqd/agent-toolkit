// Does a proof gate placed in the SDK's gRPC userBuilder seam run before task state is touched?
// This is a DIFFERENT seam than the Express userBuilder (gate-order/gate-userbuilder.mjs): grpc's
// UserBuilder = (call: grpc.ServerUnaryCall | grpc.ServerWritableStream) => Promise<User>, reading
// the already-deserialized protobuf request off `call.request`, not an Express req.body. A gate
// written for the JSON-RPC/Express userBuilder does not port as-is; each transport needs its own
// adapter over its own request shape. Real gRPC server + real @a2a-js/sdk gRPC client, in-process.
import * as grpc from '@grpc/grpc-js';
import { Role, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { A2AService, grpcService } from '@a2a-js/sdk/server/grpc';
import { GrpcTransportFactory } from '@a2a-js/sdk/client/grpc';
import { ClientFactory, ClientFactoryOptions } from '@a2a-js/sdk/client';
import { ExtensionSupportRequiredError } from '@a2a-js/sdk/errors';

const PROOF_KEY = 'org.kya-os/request-proof';

const agentCard = (url) => ({
  name: 'grpc gate test', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url, protocolBinding: 'GRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false },
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
const store = new InMemoryTaskStore();
const handler = new DefaultRequestHandler(agentCard('x'), store, executor);

// The gate, written against the gRPC-specific UserBuilder shape: reads the proof off the
// DESERIALIZED protobuf request (call.request), not an HTTP body.
const userBuilder = async (call) => {
  const proof = call.request?.message?.metadata?.[PROOF_KEY];
  if (!proof?.did) throw new ExtensionSupportRequiredError('proof_required: missing');
  return { isAuthenticated: true, userName: proof.did };
};

const server = new grpc.Server();
server.addService(A2AService, grpcService({ requestHandler: handler, userBuilder }));
const port = await new Promise((resolve, reject) => {
  server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, p) => (err ? reject(err) : resolve(p)));
});
server.start();

const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
  transports: [new GrpcTransportFactory({ grpcChannelCredentials: grpc.credentials.createInsecure() })],
}));
const url = `127.0.0.1:${port}`;
const a2a = await factory.createFromAgentCard(agentCard(url));

const message = (id, text, metadata) => ({
  messageId: id, role: Role.ROLE_USER, parts: [{ content: { $case: 'text', value: text }, mediaType: 'text/plain', filename: '', metadata: undefined }],
  contextId: '', taskId: '', metadata, extensions: [], referenceTaskIds: [],
});
const line = (s) => console.log(s);

// 1. Proofed call through the real client/server gRPC round trip.
try {
  const r = await a2a.sendMessage({ tenant: '', message: message('m1', 'hi', { [PROOF_KEY]: { prf: 'org.kya-os/proof.v1', did: 'did:web:client.example' } }), configuration: undefined, metadata: undefined });
  line(`1. proofed call over real gRPC -> returned ${r?.id ? 'task ' + r.id : JSON.stringify(r).slice(0, 100)}; executor ran ${executed}x`);
} catch (e) { line(`1. proofed call over real gRPC -> THREW ${e.message}; executor ran ${executed}x`); }

const before = executed;

// 2. Unproofed call: the gate must reject before the executor runs.
try {
  const r = await a2a.sendMessage({ tenant: '', message: message('m2', 'hi', undefined), configuration: undefined, metadata: undefined });
  line(`2. unproofed call -> returned ${JSON.stringify(r).slice(0, 100)} (expected a throw); executor ran ${executed - before}x since`);
} catch (e) {
  line(`2. unproofed call, gate throws ExtensionSupportRequiredError -> client sees ${e.constructor.name}: ${e.message} (grpc code ${e.code}); executor ran ${executed - before}x since (expected 0)`);
}

// 3. Compare: a second server whose gate throws a PLAIN Error instead of a typed one.
{
  const userBuilder2 = async (call) => {
    const proof = call.request?.message?.metadata?.[PROOF_KEY];
    if (!proof?.did) throw new Error('proof_missing');
    return { isAuthenticated: true, userName: proof.did };
  };
  const server2 = new grpc.Server();
  server2.addService(A2AService, grpcService({ requestHandler: new DefaultRequestHandler(agentCard('x'), new InMemoryTaskStore(), executor), userBuilder: userBuilder2 }));
  const port2 = await new Promise((resolve, reject) => {
    server2.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, p) => (err ? reject(err) : resolve(p)));
  });
  const a2a2 = await factory.createFromAgentCard(agentCard(`127.0.0.1:${port2}`));
  try {
    await a2a2.sendMessage({ tenant: '', message: message('m3', 'hi', undefined), configuration: undefined, metadata: undefined });
    line('3. unproofed call, gate throws a plain Error -> unexpectedly returned');
  } catch (e) {
    line(`3. unproofed call, gate throws a plain Error -> client sees ${e.constructor.name}: ${e.message} (grpc code ${e.code})`);
  }
  server2.forceShutdown();
}

server.forceShutdown();
