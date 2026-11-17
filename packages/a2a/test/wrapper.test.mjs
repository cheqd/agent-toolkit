// SPDX-License-Identifier: Apache-2.0
// Regression tests for withAgentIdentity's two found-by-review issues:
//  1. NON-TASK RESPONSE BYPASS (MEDIUM): a Message result used to pass through unsigned
//     ("nothing to prove here yet"), unlike a Task result, which always got a response
//     proof. That let anyone who could answer in the server's place substitute an
//     arbitrary, unproven Message for what should have been a proven Task - closed here by
//     having sendMessage sign a response proof for a Message result too (see client.test.mjs
//     for the client-side half of this fix).
//  2. STREAMING ENFORCEMENT (HIGH, confirmed already correct in TypeScript): sendMessageStream
//     must still reject an unverified caller before the real stream handler/executor ever
//     runs - the Python port (gate.py/proto_bridge.py) was missing this entirely; this test
//     documents that TS already had it right, as the reference behaviour the Python fix
//     mirrors.
//
// Stubs ProofGenerator.prototype.generateProof (rather than minting real end-to-end crypto)
// because what's under test is withAgentIdentity's OWN control flow - which result shapes get
// a proof, and in what order enforcement happens relative to the inner handler - not
// @kya-os/mcp's proof cryptography (covered by that package's own tests).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ProofGenerator } from '@kya-os/mcp/proof';
import { withAgentIdentity } from '../dist/index.js';

const SERVER_DID = 'did:example:server';
const CALLER_DID = 'did:example:caller';

function responseProofOptions() {
	return {
		serverDid: SERVER_DID,
		serverKid: `${SERVER_DID}#key-1`,
		// Never actually used to sign - generateProof is stubbed in every test below.
		privateKey: /** @type {any} */ ({}),
		publicKey: 'ignored-fake-key',
		cryptoProvider: /** @type {any} */ ({}),
	};
}

/** A ServerCallContext carrying a verified caller, the shape wrapper.ts's enforce() reads. */
function verifiedContext() {
	return { user: { isAuthenticated: true, userName: CALLER_DID, verified: { did: CALLER_DID, covered: { method: 'SendMessage', params: {} } } } };
}

/** A ServerCallContext for a caller the userBuilder never verified. */
function unverifiedContext() {
	return { user: { isAuthenticated: false, userName: '', rejection: 'missing' } };
}

function taskResult() {
	return { id: 't-1', status: { state: 'TASK_STATE_COMPLETED' } };
}

function messageResult() {
	return { messageId: 'm-1', role: 'ROLE_AGENT', parts: [{ text: 'hi' }] };
}

test('sendMessage: a Task result gets a response proof', async (t) => {
	t.after(() => { ProofGenerator.prototype.generateProof = originalGenerateProof; });
	const originalGenerateProof = ProofGenerator.prototype.generateProof;
	ProofGenerator.prototype.generateProof = async () => ({ jws: 'fake.jws' });

	const inner = { async sendMessage() { return taskResult(); } };
	const wrapped = withAgentIdentity(inner, responseProofOptions());

	const result = await wrapped.sendMessage({}, verifiedContext());
	assert.ok(result.metadata?.['org.kya-os/response-proof'], 'expected a response proof on the Task result');
});

test('sendMessage: a Message result ALSO gets a response proof (closes the non-Task-response bypass)', async (t) => {
	const originalGenerateProof = ProofGenerator.prototype.generateProof;
	t.after(() => { ProofGenerator.prototype.generateProof = originalGenerateProof; });
	ProofGenerator.prototype.generateProof = async () => ({ jws: 'fake.jws' });

	const inner = { async sendMessage() { return messageResult(); } };
	const wrapped = withAgentIdentity(inner, responseProofOptions());

	const result = await wrapped.sendMessage({}, verifiedContext());
	assert.ok(
		result.metadata?.['org.kya-os/response-proof'],
		'a Message result must be signed exactly like a Task result - leaving it unsigned is what let an unproven Message silently replace a proven Task',
	);
});

test('sendMessage: an unverified caller is rejected before the inner handler runs, for either result shape', async () => {
	let handlerCalled = false;
	const inner = { async sendMessage() { handlerCalled = true; return taskResult(); } };
	const wrapped = withAgentIdentity(inner, responseProofOptions());

	await assert.rejects(() => wrapped.sendMessage({}, unverifiedContext()), /proof_required/);
	assert.equal(handlerCalled, false);
});

test('sendMessageStream: an unverified caller is rejected before the inner stream handler/executor ever runs', async () => {
	// This is the TS reference behaviour the HIGH finding says Python's gate.py/proto_bridge.py
	// was missing entirely - confirms it still holds here.
	let handlerCalled = false;
	const inner = {
		async *sendMessageStream() {
			handlerCalled = true;
			yield messageResult();
		},
	};
	const wrapped = withAgentIdentity(inner, responseProofOptions());

	await assert.rejects(async () => {
		for await (const _event of wrapped.sendMessageStream({}, unverifiedContext())) {
			// must never be reached
		}
	}, /proof_required/);
	assert.equal(handlerCalled, false);
});

test('sendMessageStream: a verified caller reaches the inner stream handler and its events pass through unmodified', async () => {
	const events = [messageResult(), messageResult()];
	const inner = {
		async *sendMessageStream() {
			yield* events;
		},
	};
	const wrapped = withAgentIdentity(inner, responseProofOptions());

	const received = [];
	for await (const event of wrapped.sendMessageStream({}, verifiedContext())) {
		received.push(event);
	}
	assert.deepEqual(received, events);
});
