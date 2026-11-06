/**
 * The enforcing-wrapper half of the chosen gate design (see
 * docs/research/a2a-trust-binding-findings-2026-11.md §2). Rejects any write without a
 * verified identity (set by the userBuilder in user-builder.ts) before the SDK's request
 * handler runs, and makes the response proof over the FINAL result - never in the executor,
 * which cannot see what the client actually receives after the SDK's event-merge and
 * historyLength trimming.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import type { A2ARequestHandler, ServerCallContext } from '@a2a-js/sdk/server';
import { Task } from '@a2a-js/sdk';
import { ExtensionSupportRequiredError, RequestMalformedError } from '@a2a-js/sdk/errors';
import { ProofGenerator } from '@kya-os/mcp/proof';

// Same reason as client.ts: ResponseProofProfile isn't exported from the public barrel.
type GenerateProofOptions = Parameters<ProofGenerator['generateProof']>[3];
type ResponseProofProfile = NonNullable<GenerateProofOptions>['profile'];
import type { CryptoProvider } from '@kya-os/mcp/providers';
import { randomBytes } from 'node:crypto';
import { coveredResult, RESPONSE_PROOF_META_KEY } from './covered-request.js';
import type { TrustExtensionActivation, TrustExtensionCache } from './trust-extension.js';
import type { GateUser, VerifiedCaller } from './types.js';

interface UserCarryingContext extends ServerCallContext {
	user: GateUser;
}

/** Applies the trust extension's checks (spec §4.6 step 10) if activated for this deployment. */
export interface TrustExtensionGate {
	readonly cache: TrustExtensionCache;
	readonly activation: TrustExtensionActivation;
}

async function enforce(ctx: ServerCallContext, trustExtension?: TrustExtensionGate): Promise<VerifiedCaller> {
	const user = (ctx as UserCarryingContext).user;
	if (!user?.verified) {
		const reason = user?.rejection ?? 'no_verifier_installed';
		// Fails closed: a missing userBuilder looks identical to a missing proof, by design, not convention.
		if (reason === 'missing' || reason === 'no_verifier_installed') {
			throw new ExtensionSupportRequiredError(`proof_required: ${reason}`);
		}
		throw new RequestMalformedError(`proof_invalid: ${reason}`);
	}
	if (trustExtension) {
		const result = await trustExtension.cache.get(user.verified.did, trustExtension.activation);
		if (!result.ok) throw new RequestMalformedError(`trust_extension_failed: ${result.reasons.join(',')}`);
	}
	return user.verified;
}

export interface ResponseProofOptions {
	serverDid: string;
	serverKid: string;
	/** The server's Ed25519 private key, already imported as a jose CryptoKey. */
	privateKey: CryptoKey;
	/** The server's base64 public key (ProofGenerator wants it alongside the private key). */
	publicKey: string;
	cryptoProvider: CryptoProvider;
	profile?: ResponseProofProfile;
}

/**
 * Wrap an A2ARequestHandler so that `sendMessage`/`sendMessageStream` reject any caller the
 * userBuilder did not verify, and `sendMessage` additionally attaches a response proof over the
 * final result. Every other method passes through unchanged - note the
 * (currently unresolved) task-addressed-method identity gap this leaves.
 *
 * `trustExtension`, when supplied, additionally rejects a verified caller whose cached §5.2
 * linkage/manifest/status checks are not `ok` - optional, since the trust extension itself is
 * optional per the Agent Card (spec §5.1).
 */
export function withAgentIdentity(
	inner: A2ARequestHandler,
	responseProof: ResponseProofOptions,
	trustExtension?: TrustExtensionGate,
): A2ARequestHandler {
	const generator = new ProofGenerator(
		{
			did: responseProof.serverDid,
			kid: responseProof.serverKid,
			privateKey: responseProof.privateKey,
			publicKey: responseProof.publicKey,
		},
		responseProof.cryptoProvider
	);
	return new Proxy(inner, {
		get(target, prop, receiver) {
			if (prop === 'sendMessage') {
				return async (params: Parameters<A2ARequestHandler['sendMessage']>[0], ctx: ServerCallContext) => {
					const caller = await enforce(ctx, trustExtension);
					const result: unknown = await target.sendMessage(params, ctx);
					const resultObj = result as Record<string, unknown>;
					if (!result || !('status' in resultObj)) return result; // a Message, not a Task - nothing to prove here yet
					// The proof MUST be made over the JSON-safe wire form , not the
					// SDK's typed object - which carries explicit `undefined` fields JCS can't
					// canonicalize (found via the smoke test, not by inspection).
					const json = Task.toJSON(result as never) as Record<string, unknown>;
					const data = coveredResult(json as { metadata?: Record<string, unknown> });
					const session = {
						sessionId: 'a2a-stateless',
						audience: caller.did,
						nonce: randomBytes(16).toString('base64url'),
						timestamp: Date.now(),
						createdAt: Date.now(),
						lastActivity: Date.now(),
						ttlMinutes: 1,
						identityState: 'authenticated' as const,
					};
					const proof = await generator.generateProof(caller.covered, { data }, session, {
						profile: responseProof.profile ?? 'org.kya-os/response-proof.envelope',
					});
					return {
						...resultObj,
						metadata: { ...(resultObj.metadata as Record<string, unknown> | undefined), [RESPONSE_PROOF_META_KEY]: proof },
					};
				};
			}
			if (prop === 'sendMessageStream') {
				return async function* (params: Parameters<A2ARequestHandler['sendMessageStream']>[0], ctx: ServerCallContext) {
					await enforce(ctx, trustExtension);
					// streaming is out of scope for now - no response proof is made
					// here, by construction, not just by convention (evidence/gate-order/
					// slice-userbuilder-wrapper.mjs confirmed this already for the throwaway version).
					yield* target.sendMessageStream(params, ctx);
				};
			}
			const value = Reflect.get(target, prop, receiver);
			return typeof value === 'function' ? value.bind(target) : value;
		},
	});
}
