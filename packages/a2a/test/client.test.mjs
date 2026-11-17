// SPDX-License-Identifier: Apache-2.0
// Regression tests for createProofInterceptor's two found-by-review bugs:
//  1. FAIL-OPEN: a missing/invalid response proof used to only set `state.lastResponseCheck`
//     and return normally - the sendMessage() call itself succeeded regardless.
//  2. SHARED CONCURRENT STATE: the covered request computed in before() used to live in a
//     single module-level variable shared by every call through one interceptor instance, so a
//     second concurrent call's before() could silently overwrite the first call's covered
//     request before the first call's after() read it back.
//
// These tests stub ProofVerifier.prototype.verifyProof (rather than minting real end-to-end
// crypto) because what's under test is the interceptor's OWN control flow and state routing,
// not @kya-os/mcp's proof cryptography (covered by that package's own tests).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ProofVerifier } from '@kya-os/mcp/proof';
import { NodeCryptoProvider, SystemClockProvider, MemoryNonceCacheProvider } from '@kya-os/mcp/providers';
import { createProofInterceptor, PROOF_META_KEY } from '../dist/index.js';
import { RESPONSE_PROOF_META_KEY } from '../dist/index.js';

function fakeSigner(did) {
	return { did, kid: `${did}#key-1`, async sign() { return 'fake.jws.signature'; } };
}

function baseOptions(overrides = {}) {
	return {
		signer: fakeSigner('did:example:client'),
		serverDid: 'did:example:server',
		clientDid: 'did:example:client',
		serverPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'ignored-fake-key', kid: 'did:example:server#key-1' },
		extensionUri: 'https://example.org/ext/proof',
		cryptoProvider: new NodeCryptoProvider(),
		clockProvider: new SystemClockProvider(),
		nonceCacheProvider: new MemoryNonceCacheProvider(),
		fetchProvider: { fetch: async () => { throw new Error('fetchProvider should not be called in this test'); } },
		...overrides,
	};
}

function makeCallArgs(messageText) {
	return {
		input: {
			method: 'sendMessage',
			value: { message: { messageId: `m-${messageText}`, role: 'ROLE_USER', parts: [{ text: messageText }], metadata: {} } },
		},
		options: { serviceParameters: {} },
	};
}

function taskResult(extraMetadata) {
	return { id: 't-1', status: { state: 'TASK_STATE_COMPLETED' }, metadata: extraMetadata };
}

test('a response with no proof at all REJECTS the call, not just records failure (fail-closed)', async () => {
	const { interceptor, state } = createProofInterceptor(baseOptions());
	const before = makeCallArgs('hello');
	await interceptor.before(before);

	await assert.rejects(
		() => interceptor.after({ result: { method: 'sendMessage', value: taskResult(undefined) }, options: before.options }),
		/A2A response proof verification failed/,
	);
	assert.equal(state.lastResponseCheck?.valid, false);
});

test('after() with no prior before() for this call REJECTS rather than silently skipping verification', async () => {
	const { interceptor, state } = createProofInterceptor(baseOptions());
	// No before() call at all - args.options.context was never populated.
	await assert.rejects(
		() => interceptor.after({ result: { method: 'sendMessage', value: taskResult(undefined) }, options: { serviceParameters: {} } }),
		/A2A response proof verification failed/,
	);
	assert.equal(state.lastResponseCheck?.valid, false);
});

test('a response proof that fails verification REJECTS the call (fail-closed)', async (t) => {
	const originalVerifyProof = ProofVerifier.prototype.verifyProof;
	t.after(() => { ProofVerifier.prototype.verifyProof = originalVerifyProof; });
	ProofVerifier.prototype.verifyProof = async () => ({ valid: false, reason: 'signature_mismatch' });

	const { interceptor, state } = createProofInterceptor(baseOptions());
	const before = makeCallArgs('hello');
	await interceptor.before(before);

	await assert.rejects(
		() => interceptor.after({ result: { method: 'sendMessage', value: taskResult({ [RESPONSE_PROOF_META_KEY]: { fake: 'proof' } }) }, options: before.options }),
		/signature_mismatch/,
	);
	assert.equal(state.lastResponseCheck?.valid, false);
});

test('a genuinely valid response proof resolves normally (no false positive from the fail-closed change)', async (t) => {
	const originalVerifyProof = ProofVerifier.prototype.verifyProof;
	t.after(() => { ProofVerifier.prototype.verifyProof = originalVerifyProof; });
	ProofVerifier.prototype.verifyProof = async () => ({ valid: true });

	const { interceptor, state } = createProofInterceptor(baseOptions());
	const before = makeCallArgs('hello');
	await interceptor.before(before);

	await interceptor.after({ result: { method: 'sendMessage', value: taskResult({ [RESPONSE_PROOF_META_KEY]: { fake: 'proof' } }) }, options: before.options });
	assert.equal(state.lastResponseCheck?.valid, true);
});

test('concurrent calls through one interceptor: each after() verifies against its OWN covered request, not another in-flight call\'s', async (t) => {
	const originalVerifyProof = ProofVerifier.prototype.verifyProof;
	t.after(() => { ProofVerifier.prototype.verifyProof = originalVerifyProof; });
	const seenRequests = [];
	ProofVerifier.prototype.verifyProof = async (_proof, _jwk, context) => {
		seenRequests.push(context.request);
		return { valid: true };
	};

	const { interceptor } = createProofInterceptor(baseOptions());

	// Simulate the SDK's real interleaving under concurrency: call A's before(), THEN call B's
	// before() (which would clobber a shared module-level variable), THEN call A's after().
	const callA = makeCallArgs('message-A');
	const callB = makeCallArgs('message-B');
	await interceptor.before(callA);
	await interceptor.before(callB);

	await interceptor.after({ result: { method: 'sendMessage', value: taskResult({ [RESPONSE_PROOF_META_KEY]: { fake: 'proof' } }) }, options: callA.options });
	await interceptor.after({ result: { method: 'sendMessage', value: taskResult({ [RESPONSE_PROOF_META_KEY]: { fake: 'proof' } }) }, options: callB.options });

	assert.equal(seenRequests.length, 2);
	// A's after() must have verified against A's own covered request (containing A's message),
	// not B's (which overwrote a shared variable in the pre-fix code).
	assert.ok(JSON.stringify(seenRequests[0]).includes('message-A'), `expected call A's verification to use A's covered request, got: ${JSON.stringify(seenRequests[0])}`);
	assert.ok(!JSON.stringify(seenRequests[0]).includes('message-B'), `call A's verification must NOT use call B's covered request, got: ${JSON.stringify(seenRequests[0])}`);
	assert.ok(JSON.stringify(seenRequests[1]).includes('message-B'), `expected call B's verification to use B's covered request, got: ${JSON.stringify(seenRequests[1])}`);
});

test('before() mints a request proof under PROOF_META_KEY and sets the extension service parameter', async () => {
	const { interceptor } = createProofInterceptor(baseOptions());
	const before = makeCallArgs('hello');
	await interceptor.before(before);
	assert.ok(before.input.value.message.metadata[PROOF_META_KEY]);
	assert.equal(before.options.serviceParameters['A2A-Extensions'], 'https://example.org/ext/proof');
});

test('a non-sendMessage method is left untouched by before() and after()', async () => {
	const { interceptor, state } = createProofInterceptor(baseOptions());
	const before = { input: { method: 'getTask', value: { id: 't-1' } }, options: { serviceParameters: {} } };
	await interceptor.before(before);
	assert.deepEqual(before.input.value, { id: 't-1' });
	await interceptor.after({ result: { method: 'getTask', value: { id: 't-1' } }, options: before.options });
	assert.equal(state.lastResponseCheck, undefined);
});
