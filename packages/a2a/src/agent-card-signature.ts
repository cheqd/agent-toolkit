/**
 * Signs an A2A Agent Card with a DID-anchored key, using `@a2a-js/sdk`'s own
 * `generateAgentCardSignature` for the actual JWS construction - this package never reimplements
 * that construction (see the Agent Card findings in
 * docs/research/a2a-trust-binding-findings-2026-11.md §4, which tested the SDK's own
 * generate/verify pair directly). The `kid` on the resulting signature is a DID URL, so a
 * verifier resolves the signer's public key by DID rather than trusting an embedded `jku`.
 *
 * This is the one piece of this programme's A2A work that previously existed only as a
 * standalone JWS helper inside the `cheqd/credo-ts` fork's `packages/cheqd/src/agent-id/`
 * (`agentCardSignature.ts`), built against Credo's own key/DID APIs because this package wasn't
 * published anywhere a Credo-based agent could depend on it. It belongs here, since this package
 * is specifically about A2A trust binding and Credo is just one of its possible consumers.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import type { AgentCard } from '@a2a-js/sdk';
import { generateAgentCardSignature } from '@a2a-js/sdk';
import { importJWK, type JWK } from 'jose';

export interface SignAgentCardOptions {
	/** The DID this agent controls, anchoring the signing key. */
	did: string;
	/**
	 * Verification method id: a full DID URL (`did:example:abc#key-1`) or a bare fragment
	 * (`#key-1`), resolved against `did` in the latter case.
	 */
	kid: string;
	/** The signing key as a private JWK. Only Ed25519 and P-256 are supported. */
	privateJwk: JWK;
}

/** `EdDSA` for an Ed25519 key, `ES256` for a P-256 key - the only two curves signed with elsewhere in this package. */
function algFor(jwk: JWK): 'EdDSA' | 'ES256' {
	if (jwk.crv === 'Ed25519') return 'EdDSA';
	if (jwk.crv === 'P-256') return 'ES256';
	throw new Error(`unsupported key for agent card signing: kty=${jwk.kty} crv=${jwk.crv}`);
}

function resolveKid(did: string, kid: string): string {
	return kid.startsWith('did:') ? kid : `${did}${kid.startsWith('#') ? kid : `#${kid}`}`;
}

/**
 * Signs `agentCard` with `options.privateJwk`, over `@a2a-js/sdk`'s own canonical payload, and
 * returns the card with the new signature appended to `signatures`. A card may carry more than
 * one signature; this does not remove any that are already present.
 */
export async function signAgentCard(agentCard: AgentCard, options: SignAgentCardOptions): Promise<AgentCard> {
	const alg = algFor(options.privateJwk);
	const kid = resolveKid(options.did, options.kid);
	const privateKey = await importJWK(options.privateJwk, alg);
	const sign = generateAgentCardSignature(privateKey as Parameters<typeof generateAgentCardSignature>[0], {
		alg,
		kid,
		typ: 'JWT',
	});
	return sign(agentCard);
}
