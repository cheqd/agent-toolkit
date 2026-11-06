// Runnable sample: the WS1 gate + CallInterceptor (`@cheqd/agent-identity-a2a`) composed with
// the DID-backed Agent Card key resolver and did:cheqd / status-list checks
// (`@cheqd/agent-identity`), against a real `@a2a-js/sdk` client/server. See sample/README.md
// for what is live against the public cheqd testnet and what is a labelled synthetic fixture.
//
// DRAFT — early exploration, not reviewed or stable. See the repository README.
//
// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import * as grpc from '@grpc/grpc-js';
import { generateKeyPair, exportJWK } from 'jose';
import { Role, TaskState } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore, AgentEvent } from '@a2a-js/sdk/server';
import { jsonRpcHandler, restHandler } from '@a2a-js/sdk/server/express';
import { A2AService, grpcService } from '@a2a-js/sdk/server/grpc';
import { GrpcTransportFactory } from '@a2a-js/sdk/client/grpc';
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from '@a2a-js/sdk/client';
import { ed25519SignerFromJwk, buildCardProof } from '@kya-os/mcp/card';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider, RuntimeFetchProvider } from '@kya-os/mcp/providers';
import {
	createVerifyingUserBuilder,
	createVerifyingGrpcUserBuilder,
	withAgentIdentity,
	createProofInterceptor,
	coveredRequest,
	verifyTrustExtension,
	createTrustExtensionCache,
} from '../dist/index.js';
import {
	createDidCheqdResolver,
	createRetrievePublicKey,
	verifyLedgerAnchoredStatus,
	createCheqdStatusChecker,
	createManifestCache,
	FileNonceCacheProvider,
} from '@cheqd/agent-identity';

// Persistent (file-backed) replay cache, shared by all three transport sections below - the WS1
// "replay cache" deliverable. A fresh temp directory per run keeps the sample self-contained;
// a real deployment would point `directory` at a path that survives a process restart.
const nonceCacheDir = mkdtempSync(join(tmpdir(), 'a2a-sample-nonces-'));
const makeNonceCache = () => new FileNonceCacheProvider({ directory: nonceCacheDir });

const line = (s) => console.log(s);
const section = (title) => line(`\n== ${title} ==`);

const EXT_URI = 'https://kya-os.org/a2a/ext/proof/v1';
const CLIENT_DID = 'did:web:client.example';
const SERVER_DID = 'did:web:server.example';

async function newKey(did) {
	const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	const priv = await exportJWK(privateKey);
	const pub = await exportJWK(publicKey);
	return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x }, cryptoKey: privateKey };
}

// These are the only two identities the sample can actually SIGN as - both did:web, both
// keys generated here. cheqd identity is demonstrated separately, in the "live cheqd testnet
// resolution" section below, as resolution only: the sample does not hold the private key for
// any real cheqd DID, so it cannot produce a genuine signature from one.
const client = await newKey(CLIENT_DID);
const server = await newKey(SERVER_DID);
const resolveKey = (kid) => (kid === client.kid ? client.pub : kid === server.kid ? server.pub : (() => { throw new Error('no such kid'); })());
const resolveDidKeys = (did) => (did === CLIENT_DID ? [client.pub] : did === SERVER_DID ? [server.pub] : []);

const message = (id, text) => ({ messageId: id, role: Role.ROLE_USER, parts: [{ content: { $case: 'text', value: text }, mediaType: 'text/plain', filename: '', metadata: undefined }], contextId: '', taskId: '', metadata: undefined, extensions: [], referenceTaskIds: [] });

function newExecutor() {
	const count = { n: 0 };
	const executor = {
		async execute(ctx, bus) {
			count.n++;
			bus.publish(AgentEvent.task({ id: ctx.taskId, contextId: ctx.contextId, status: { state: TaskState.TASK_STATE_INPUT_REQUIRED, message: undefined, timestamp: undefined }, artifacts: [], history: [], metadata: {} }));
			bus.finished();
		},
		async cancelTask() {},
	};
	return { count, executor };
}

// === 1. JSON-RPC: real client, real Express server, through the reusable gate + interceptor ===
section('JSON-RPC transport');
{
	const nonceCache = makeNonceCache();
	const agentCard = (url) => ({
		name: 'sample (JSON-RPC)', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
		supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
		capabilities: { extensions: [{ uri: EXT_URI, description: 'proof', required: true, params: {} }], streaming: true, pushNotifications: false },
		securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
		skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
		signatures: [],
	});
	const { count, executor } = newExecutor();
	const store = new InMemoryTaskStore();
	const userBuilder = createVerifyingUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume.bind(nonceCache) });
	const handler = withAgentIdentity(new DefaultRequestHandler(agentCard('http://x'), store, executor), {
		serverDid: SERVER_DID, serverKid: server.kid, privateKey: server.cryptoKey, publicKey: server.priv.d, cryptoProvider: new NodeCryptoProvider(),
	});
	const app = express();
	app.use(express.json());
	app.use(jsonRpcHandler({ requestHandler: handler, userBuilder: async (req) => userBuilder(req) }));
	const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
	const url = `http://127.0.0.1:${srv.address().port}/`;

	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const { interceptor, state } = createProofInterceptor({
		signer, serverDid: SERVER_DID, clientDid: CLIENT_DID, serverPublicJwk: { ...server.pub, kid: server.kid },
		extensionUri: EXT_URI, cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(),
		nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider(),
	});
	const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
		transports: [new JsonRpcTransportFactory()], clientConfig: { interceptors: [interceptor] },
	}));
	const a2a = await factory.createFromAgentCard(agentCard(url));
	const task = await a2a.sendMessage({ tenant: '', message: message('jr1', 'hello over JSON-RPC'), configuration: undefined, metadata: undefined });
	line(`proofed call -> task ${task?.id}; executor ran ${count.n}x; response proof ${JSON.stringify(state.lastResponseCheck)}`);
	srv.close();
}

// === 2. REST: the same gate, no new code - restHandler's method-from-route convention ===
section('REST transport');
{
	const agentCard = { name: 'sample (REST)', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
		supportedInterfaces: [{ url: 'http://x', protocolBinding: 'HTTP+JSON', tenant: '', protocolVersion: '1.0' }],
		capabilities: { extensions: [], streaming: true, pushNotifications: false }, securitySchemes: {}, securityRequirements: [],
		defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [], signatures: [] };
	const { count, executor } = newExecutor();
	const store = new InMemoryTaskStore();
	const nonceCache = makeNonceCache();
	const userBuilder = createVerifyingUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume.bind(nonceCache) });
	const handler = withAgentIdentity(new DefaultRequestHandler(agentCard, store, executor), {
		serverDid: SERVER_DID, serverKid: server.kid, privateKey: server.cryptoKey, publicKey: server.priv.d, cryptoProvider: new NodeCryptoProvider(),
	});
	const app = express();
	app.use(express.json());
	app.use('/rest', restHandler({ requestHandler: handler, userBuilder: (req) => userBuilder(req) }));
	const srv = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
	const restUrl = `http://127.0.0.1:${srv.address().port}/rest`;

	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const body = { message: { messageId: 'rest1', role: 'ROLE_USER', parts: [{ text: 'hello over REST' }], contextId: '', taskId: '', extensions: [], referenceTaskIds: [] } };
	const proof = await buildCardProof(coveredRequest('SendMessage', body), signer, { audience: SERVER_DID, nonce: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url') });
	body.message.metadata = { ...proof };
	const r = await fetch(`${restUrl}/message:send`, { method: 'POST', headers: { 'content-type': 'application/json', 'A2A-Version': '1.0' }, body: JSON.stringify(body) });
	line(`proofed POST /message:send -> HTTP ${r.status}; executor ran ${count.n}x`);
	srv.close();
}

// === 3. gRPC: a different UserBuilder seam, same gate behaviour. Exercises the covered-form fix ===
section('gRPC transport');
{
	const agentCard = (url) => ({
		name: 'sample (gRPC)', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
		supportedInterfaces: [{ url, protocolBinding: 'GRPC', tenant: '', protocolVersion: '1.0' }],
		capabilities: { extensions: [], streaming: true, pushNotifications: false },
		securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
		skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
		signatures: [],
	});
	const { count, executor } = newExecutor();
	const store = new InMemoryTaskStore();
	const nonceCache = makeNonceCache();
	const userBuilder = createVerifyingGrpcUserBuilder({ resolveKey, resolveDidKeys, expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume.bind(nonceCache) });
	const handler = withAgentIdentity(new DefaultRequestHandler(agentCard('x'), store, executor), {
		serverDid: SERVER_DID, serverKid: server.kid, privateKey: server.cryptoKey, publicKey: server.priv.d, cryptoProvider: new NodeCryptoProvider(),
	});
	const srv = new grpc.Server();
	srv.addService(A2AService, grpcService({ requestHandler: handler, userBuilder: (call) => userBuilder(call) }));
	const port = await new Promise((resolve, reject) => srv.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, p) => (err ? reject(err) : resolve(p))));
	const url = `127.0.0.1:${port}`;

	const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
	const { interceptor, state } = createProofInterceptor({
		signer, serverDid: SERVER_DID, clientDid: CLIENT_DID, serverPublicJwk: { ...server.pub, kid: server.kid },
		extensionUri: EXT_URI, cryptoProvider: new NodeCryptoProvider(), clockProvider: new SystemClockProvider(),
		nonceCacheProvider: new MemoryNonceCacheProvider(), fetchProvider: new RuntimeFetchProvider(),
	});
	const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
		transports: [new GrpcTransportFactory({ grpcChannelCredentials: grpc.credentials.createInsecure() })],
		clientConfig: { interceptors: [interceptor] },
	}));
	const a2a = await factory.createFromAgentCard(agentCard(url));
	const task = await a2a.sendMessage({ tenant: '', message: message('g1', 'hello over gRPC'), configuration: undefined, metadata: undefined });
	line(`proofed call -> task ${task?.id}; executor ran ${count.n}x; response proof ${JSON.stringify(state.lastResponseCheck)}`);
	srv.forceShutdown();
}

// === 4. Live cheqd testnet DID resolution (real network call, no injected fetch) ===
section('Live cheqd testnet DID resolution (real network call)');
line('This resolves a REAL public testnet DID through resolver.cheqd.net - resolution only.');
line('The sample does not hold this DID\'s private key, so it cannot sign or verify a real');
line('A2A proof as this identity; it only shows the opt-in did:cheqd resolver wired into the');
line('Agent Card key resolution path, against live data.');
{
	const REAL_TESTNET_DID = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
	const resolveDidCheqd = createDidCheqdResolver({ resolverUrl: 'https://resolver.cheqd.net/1.0/identifiers' });
	const retrieve = createRetrievePublicKey({ resolveDidCheqd });
	try {
		const jwk = await retrieve(`${REAL_TESTNET_DID}#key-1`);
		line(`resolved live -> ${JSON.stringify(jwk)}`);
		line('(this DID publishes the legacy Ed25519VerificationKey2018/publicKeyBase58 format -');
		line(' exercises the fix in retrieve-public-key.ts, not just the newer publicKeyMultibase/publicKeyJwk forms)');
	} catch (e) {
		line(`live resolution failed: ${e.message} (network-dependent; re-run or check resolver.cheqd.net)`);
	}
}

// === 5. Ledger-anchored status check - SYNTHETIC fixture, not live ===
section('Ledger-anchored status check (SYNTHETIC fixture - not live)');
line('No BitstringStatusListCredential has been found live on cheqd testnet as of November 2026');
line('(see evidence/status-list/README.md). This section fabricates a resolver response in the');
line('exact shape resolver.cheqd.net returns (captured 13 October 2026), the same approach');
line('packages/core/test/ledger-anchored.test.mjs uses - it is NOT a live network call.');
{
	const COLLECTION = '0c3581f0-011f-4263-b1ca-15ad70d54ede';
	const DID = `did:cheqd:testnet:${COLLECTION}`;
	const NAME = 'agent-revocations';
	const RESOURCE_ID = '1a79a313-8fc3-421c-af3d-34730fa046d1';
	const BASE = 'https://resolver.synthetic.example/1.0/identifiers';
	const ENTRY = {
		statusListCredential: `${BASE}/${DID}?resourceName=${NAME}&resourceType=BitstringStatusListCredential#41260`,
		statusListIndex: '41260',
		statusPurpose: 'revocation',
	};
	const primitives = {
		sha256Hex: (bytes) => createHash('sha256').update(bytes).digest('hex'),
		gunzip: (bytes, maxBytes) => gunzipSync(bytes, { maxOutputLength: maxBytes }),
		decodeUtf8: (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
	};
	const entries = 131072;
	const bits = new Uint8Array(entries / 8); // index 41260 left clear -> "not revoked"
	const encodedList = gzipSync(bits).toString('base64url');
	const credential = {
		'@context': ['https://www.w3.org/2018/credentials/v1'],
		type: ['VerifiableCredential', 'BitstringStatusListCredential'],
		issuer: DID, issuanceDate: '2026-10-01T00:00:00Z',
		credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList },
		proof: { type: 'JwtProof2020', jwt: 'header.payload.signature' },
	};
	const record = { bitstringStatusListCredential: credential, metadata: { encrypted: false, encoding: 'base64url', length: entries, statusSize: 1 } };
	const bytes = Buffer.from(JSON.stringify(record));
	const checksum = createHash('sha256').update(bytes).digest('hex');
	const linked = { resourceURI: `${DID}/resources/${RESOURCE_ID}`, resourceCollectionId: COLLECTION, resourceId: RESOURCE_ID, resourceName: NAME, resourceType: 'BitstringStatusListCredential', mediaType: 'application/json', resourceVersion: '2026-10-01T00:00:00Z', created: '2026-10-01T00:00:00Z', checksum, previousVersionId: null, nextVersionId: null };
	const NOW = Date.now();
	const meta = { dereferencingMetadata: { retrieved: new Date(NOW).toISOString() }, contentMetadata: { linkedResourceMetadata: [linked] } };
	const fetch_ = async (url) => {
		if (url.includes('resourceMetadata=true')) return { status: 200, body: Buffer.from(JSON.stringify(meta)) };
		if (url.includes('/resources/')) return { status: 200, body: bytes };
		return { status: 404, body: new Uint8Array() };
	};
	const result = await verifyLedgerAnchoredStatus(ENTRY, DID, { resolvers: [BASE], fetch: fetch_, primitives, now: () => NOW });
	line(`synthetic check -> ${JSON.stringify(result)}`);
}

// === 6. The trust extension's per-DID checks: linkage + DLR manifest + proof-checked status ===
section('Trust extension checks (reciprocal linkage + DLR manifest + signed status - SYNTHETIC)');
line('No cheqd DID has a real reciprocal alsoKnownAs link to this sample\'s did:web identity, and');
line('no TrustConfigManifest/CapabilityManifest/ConformanceManifest DLR has been found live on');
line('testnet (see README.md) - so this section builds synthetic linkage + manifest fixtures,');
line('clearly labelled. The status check is different: it uses a BitstringStatusListCredential');
line('signed with the REAL (not reimplemented) signEddsaJcs2022 from cheqd/did-provider-cheqd\'s');
line('not-yet-merged #658 branch (see fixtures/bitstring-status-list-eddsa-jcs-2022.json and');
line('evidence/status-list/mint-fixture.mjs in the a2a-drafts working repo) - once #658 ships a');
line('real signed list, this fixture is replaced and nothing here changes.');
{
	const ANCHORED_DID = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
	const TRUST_CONFIG_REF = `${ANCHORED_DID}?resourceName=TrustConfig&resourceType=TrustConfigManifest`;

	// Synthetic reciprocal linkage: SERVER_DID's did:web document and the anchored did:cheqd
	// document each name the other in alsoKnownAs. Not live - no funded testnet account to
	// actually anchor this (same constraint noted throughout evidence/status-list/README.md).
	const linkageDocs = {
		[SERVER_DID]: { id: SERVER_DID, alsoKnownAs: [ANCHORED_DID] },
		[ANCHORED_DID]: { id: ANCHORED_DID, alsoKnownAs: [SERVER_DID] },
	};

	// Synthetic DLR manifest resolver: same resolver-response shape resolve-manifest.ts expects
	// from a real `/1.0/identifiers` endpoint, fabricated rather than fetched.
	const manifestContent = { acceptedIssuers: [ANCHORED_DID], acceptedDidMethods: ['did:cheqd', 'did:web'] };
	const manifestBytes = Buffer.from(JSON.stringify(manifestContent));
	const manifestChecksum = createHash('sha256').update(manifestBytes).digest('hex');
	const manifestResourceId = 'c9b1a9a0-7b7a-4b1a-9a9a-0a9a0a9a0a9a';
	const manifestMeta = {
		dereferencingMetadata: { retrieved: new Date().toISOString() },
		contentMetadata: {
			linkedResourceMetadata: [{
				resourceId: manifestResourceId, resourceName: 'TrustConfig', resourceType: 'TrustConfigManifest',
				resourceVersion: '2026-11-01T00:00:00Z', checksum: manifestChecksum, nextVersionId: null,
			}],
		},
	};
	const manifestCache = createManifestCache({
		resolvers: ['https://resolver.synthetic.example/1.0/identifiers'],
		fetch: async (url) => {
			if (url.includes('resourceMetadata=true')) return { status: 200, body: Buffer.from(JSON.stringify(manifestMeta)) };
			if (url.includes('/resources/')) return { status: 200, body: manifestBytes };
			return { status: 404, body: new Uint8Array() };
		},
		primitives: {
			sha256Hex: (bytes) => createHash('sha256').update(bytes).digest('hex'),
			decodeUtf8: (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
		},
	});

	// The REAL #658-branch-signed status fixture.
	const fixturePath = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'bitstring-status-list-eddsa-jcs-2022.json');
	const statusFixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
	const checkStatus = async (canonicalDid) => {
		const checker = createCheqdStatusChecker({
			resolveDidCheqd: async (did) =>
				did === statusFixture.did ? { id: statusFixture.did, verificationMethod: [{ id: statusFixture.kid, publicKeyJwk: statusFixture.publicKeyJwk }] } : null,
			fetch: async (url) => (url === statusFixture.credential.id ? { ok: true, status: 200, json: async () => statusFixture.credential } : { ok: false, status: 404, json: async () => ({}) }),
		});
		// canonicalDid is unused by this fixture's single entry - a real deployment maps the
		// verified caller's DID to its own status entry.
		void canonicalDid;
		return checker(statusFixture.entries.clearIndex1);
	};

	const deps = { resolveDidDocument: async (did) => linkageDocs[did] ?? null, manifestCache, checkStatus };
	const activation = { anchoredDid: ANCHORED_DID, trustConfigRef: TRUST_CONFIG_REF, statusCheck: 'required' };
	const direct = await verifyTrustExtension(SERVER_DID, activation, deps);
	line(`verifyTrustExtension(SERVER_DID) -> ${JSON.stringify(direct)}`);

	const cache = createTrustExtensionCache(deps);
	const cached = await cache.get(SERVER_DID, activation);
	line(`createTrustExtensionCache.get(SERVER_DID) -> ${JSON.stringify(cached)} (cached for subsequent calls)`);
}
