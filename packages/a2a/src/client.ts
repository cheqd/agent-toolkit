/**
 * Client-side counterpart: a CallInterceptor that mints the request proof before `SendMessage`
 * leaves the client, and verifies the response proof against the result as received - the
 * client MUST verify in `CallInterceptor.after`, never trust the server's claim.
 *
 * Two correctness requirements this file must hold, both found by review:
 *
 * 1. FAIL CLOSED: a failed or missing response-proof check must make the `sendMessage()` call
 *    itself reject, not merely record a result on `state.lastResponseCheck` for a caller to
 *    remember to check afterwards. The SDK's `Client.executeWithInterceptors` awaits every
 *    `CallInterceptor.after` in sequence and propagates whatever it throws straight out of the
 *    original call (see `node_modules/@a2a-js/sdk/dist/client/index.js`'s
 *    `executeWithInterceptors`/`interceptAfter`), so throwing here is both sufficient and the
 *    only thing that actually enforces "never trust the server's claim" - setting `state` alone
 *    lets an unverified or invalidly-proved task flow back to the caller as if it had succeeded.
 *
 * 2. PER-CALL STATE: the covered request computed in `before()` must be associated with the ONE
 *    `sendMessage()` call it was computed for, not stored in a single module-level variable
 *    shared by every call through this interceptor instance. A client is typically reused across
 *    many concurrent calls; with a shared variable, call B's `before()` can overwrite the value
 *    call A's `before()` just set, so call A's `after()` verifies A's response against B's
 *    covered request - at best a spurious failure, at worst a meaningless comparison. The SDK
 *    passes the SAME `options` object to both `before()` and `after()` for a given call (see
 *    `executeWithInterceptors`: `afterArgs.options = beforeArgs.options`), and provides
 *    `options.context` (a `ClientCallContext`) specifically as "per-call context data" - that,
 *    not a closure variable, is this interceptor's only call-scoped storage.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { Message, SendMessageRequest, Task } from '@a2a-js/sdk';
import { ClientCallContext, ClientCallContextKey, type RequestOptions } from '@a2a-js/sdk/client';
import { randomBytes } from 'node:crypto';
import { buildCardProof } from '@kya-os/mcp/card';
import type { ProofSigner } from '@kya-os/mcp/card';
import { ProofVerifier } from '@kya-os/mcp/proof';

// @kya-os/mcp/proof's barrel doesn't export DetachedProof/Ed25519JWK by name (they live in
// internal modules), so derive the types structurally from the method that needs them.
type VerifyProofArgs = Parameters<ProofVerifier['verifyProof']>;
type DetachedProof = VerifyProofArgs[0];
type Ed25519Jwk = VerifyProofArgs[1];
import type { CryptoProvider, ClockProvider, NonceCacheProvider, FetchProvider } from '@kya-os/mcp/providers';
import { coveredRequest, coveredResult, PROOF_META_KEY, RESPONSE_PROOF_META_KEY } from './covered-request.js';

export interface ProofInterceptorOptions {
	signer: ProofSigner;
	serverDid: string;
	clientDid: string;
	/** The server's public JWK, with `kid` set - resolved and pinned by the caller (§4.5: the
	 * client MUST resolve and bind the server's key itself; the verifier does not do a
	 * DID-membership check for the response-proof side). */
	serverPublicJwk: Ed25519Jwk;
	extensionUri: string;
	cryptoProvider: CryptoProvider;
	clockProvider: ClockProvider;
	nonceCacheProvider: NonceCacheProvider;
	fetchProvider: FetchProvider;
}

export interface ResponseProofCheck {
	valid: boolean;
	reason?: string;
}

/** Last response-proof check result, surfaced for the caller to inspect/log/assert on. */
export interface ProofInterceptorState {
	lastResponseCheck?: ResponseProofCheck;
}

type Covered = { method: string; params: unknown };

/** Call-scoped key for the covered request `before()` computed - see the class doc comment on
 * why this, not a closure variable, is what carries it to the matching `after()`. */
const coveredRequestKey = new ClientCallContextKey<Covered>('a2a-proof-covered-request');

export function createProofInterceptor(options: ProofInterceptorOptions) {
	const state: ProofInterceptorState = {};
	const verifier = new ProofVerifier({
		cryptoProvider: options.cryptoProvider,
		clockProvider: options.clockProvider,
		nonceCacheProvider: options.nonceCacheProvider,
		fetchProvider: options.fetchProvider,
	});

	const interceptor = {
		async before(args: { input: { method: string; value: unknown }; options: RequestOptions & { serviceParameters: Record<string, string> } }) {
			if (args.input.method !== 'sendMessage') return;
			const params = args.input.value as { message?: { metadata?: Record<string, unknown> } };
			const wire = SendMessageRequest.toJSON(params as never);
			const covered = coveredRequest('SendMessage', wire);
			const proof = await buildCardProof(covered, options.signer, {
				audience: options.serverDid,
				nonce: randomBytes(16).toString('base64url'),
			});
			params.message = { ...params.message, metadata: { ...(params.message?.metadata ?? {}), ...proof } } as never;
			args.options.serviceParameters['A2A-Extensions'] = options.extensionUri;
			// Mutate the SAME options object the SDK will pass to this call's matching after() -
			// not a module-level variable, which a concurrently in-flight call would overwrite.
			args.options.context = ClientCallContext.createFrom(args.options.context, coveredRequestKey.set(covered));
		},
		async after(args: { result: { method: string; value: unknown }; options?: RequestOptions }) {
			if (args.result.method !== 'sendMessage') return;
			const covered = args.options?.context && coveredRequestKey.get(args.options.context);
			// No covered request for THIS call's context: either before() never ran for it (an
			// earlier interceptor short-circuited with earlyReturn before ours), or the context
			// was lost in transit. Either way, there is nothing to verify the response against -
			// fail closed rather than let an unverifiable task through as if checked.
			if (!covered) {
				const check: ResponseProofCheck = { valid: false, reason: 'no covered request for this call (before() did not run)' };
				state.lastResponseCheck = check;
				throw new Error(`A2A response proof verification failed: ${check.reason}`);
			}
			const task = args.result.value as Record<string, unknown> | null | undefined;
			if (!task) return;
			// Both a Task and a Message result are checked against the response proof. A
			// Message result used to skip this check entirely ("nothing to prove here yet" on
			// the server side), which let anyone who could answer in the server's place (a
			// compromised proxy, TLS terminator, DNS hijack) substitute an arbitrary, unproven
			// Message for what should have been a proven Task - and this client would never
			// notice. See wrapper.ts's matching fix, which now signs a response proof for a
			// Message result too, so this check applies uniformly and fails closed either way.
			const isTask = 'status' in task;
			const json = (isTask ? Task.toJSON(task as never) : Message.toJSON(task as never)) as Record<
				string,
				unknown
			>;
			const proof = (json.metadata as Record<string, unknown> | undefined)?.[RESPONSE_PROOF_META_KEY];
			if (!proof) {
				const check: ResponseProofCheck = { valid: false, reason: 'no response proof' };
				state.lastResponseCheck = check;
				throw new Error(`A2A response proof verification failed: ${check.reason}`);
			}
			const coveredResponse = coveredResult(json as { metadata?: Record<string, unknown> });
			const check = await verifier.verifyProof(
				proof as DetachedProof,
				options.serverPublicJwk,
				{ request: covered, response: { data: coveredResponse } },
				{ expectedDid: options.serverDid, expectedAudience: options.clientDid }
			);
			state.lastResponseCheck = check;
			// FAIL CLOSED: see the class doc comment - the SDK propagates this throw out of the
			// original sendMessage() call. Recording the result on `state` alone (the old
			// behaviour) let a failed/absent proof flow back to the caller as a successful call.
			if (!check.valid) throw new Error(`A2A response proof verification failed: ${check.reason ?? 'invalid'}`);
		},
	};

	return { interceptor, state };
}

export { PROOF_META_KEY };
