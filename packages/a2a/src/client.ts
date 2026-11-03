/**
 * Client-side counterpart: a CallInterceptor that mints the request proof before `SendMessage`
 * leaves the client, and verifies the response proof against the result as received - the
 * client MUST verify in `CallInterceptor.after`, never trust the server's claim.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { SendMessageRequest, Task } from '@a2a-js/sdk';
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

export function createProofInterceptor(options: ProofInterceptorOptions) {
	const state: ProofInterceptorState = {};
	let lastCovered: { method: string; params: unknown } | undefined;
	const verifier = new ProofVerifier({
		cryptoProvider: options.cryptoProvider,
		clockProvider: options.clockProvider,
		nonceCacheProvider: options.nonceCacheProvider,
		fetchProvider: options.fetchProvider,
	});

	const interceptor = {
		async before(args: { input: { method: string; value: unknown }; options: { serviceParameters: Record<string, string> } }) {
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
			lastCovered = covered;
		},
		async after(args: { result: { method: string; value: unknown } }) {
			if (args.result.method !== 'sendMessage' || !lastCovered) return;
			const task = args.result.value as Record<string, unknown>;
			if (!('status' in task)) return;
			const json = Task.toJSON(task as never) as Record<string, unknown>;
			const proof = (json.metadata as Record<string, unknown> | undefined)?.[RESPONSE_PROOF_META_KEY];
			if (!proof) {
				state.lastResponseCheck = { valid: false, reason: 'no response proof' };
				return;
			}
			const covered = coveredResult(json as { metadata?: Record<string, unknown> });
			state.lastResponseCheck = await verifier.verifyProof(
				proof as DetachedProof,
				options.serverPublicJwk,
				{ request: lastCovered, response: { data: covered } },
				{ expectedDid: options.serverDid, expectedAudience: options.clientDid }
			);
		},
	};

	return { interceptor, state };
}

export { PROOF_META_KEY };
