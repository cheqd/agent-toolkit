/**
 * Signs an A2A Agent Card with a DID-anchored key. The `kid` on the resulting signature is a DID
 * URL, so a verifier resolves the signer's public key by DID rather than trusting an embedded
 * `jku`.
 *
 * Two ways to supply the key:
 *
 * - `privateJwk`: the key is in this process. The JWS is built by `@a2a-js/sdk`'s own
 *   `generateAgentCardSignature` (see the Agent Card findings in
 *   docs/research/a2a-trust-binding-findings-2026-11.md §4, which tested the SDK's own
 *   generate/verify pair directly).
 * - `signer`: the key stays in a KMS, HSM or agent framework (for example a Credo agent's
 *   `Kms.KeyManagementApi`) that signs bytes but does not export private keys. The SDK has no hook
 *   for an external signer - `generateAgentCardSignature` needs a key object for `jose` - so the
 *   flattened JWS is assembled here, over the SDK's own `canonicalizeAgentCard` payload, in
 *   exactly the form `jose.FlattenedSign` produces. `test/agent-card-signature.test.mjs` proves the
 *   two paths interchangeable: both are verified by the SDK's own `verifyAgentCardSignature`.
 *
 * This replaces `signAgentCardPayload` / `verifyAgentCardSignature` in the `cheqd/credo-ts` fork's
 * `packages/cheqd/src/agent-id/`, which were removed from there: agent cards are not specific to
 * any ledger or agent framework, and this package is where A2A trust binding lives. A Credo agent
 * signs through `signer` (its KMS key id) and verifies with `@a2a-js/sdk`'s
 * `verifyAgentCardSignature` plus `@cheqd/agent-identity`'s `createRetrievePublicKey`.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import type { AgentCard } from '@a2a-js/sdk';
import { canonicalizeAgentCard, generateAgentCardSignature } from '@a2a-js/sdk';
import { importJWK, type JWK } from 'jose';

export type AgentCardSignatureAlgorithm = 'EdDSA' | 'ES256';

/**
 * Signs with a key held elsewhere. `sign` receives the JWS signing input (the ASCII bytes of
 * `BASE64URL(protected header) || '.' || BASE64URL(payload)`) and must return the signature in
 * JOSE form: 64 bytes for both algorithms - for `ES256` that is raw `r || s`, NOT the DER encoding
 * many crypto libraries and KMSs return by default.
 */
export interface AgentCardSigner {
	alg: AgentCardSignatureAlgorithm;
	sign(signingInput: Uint8Array): Promise<Uint8Array>;
}

interface SignAgentCardBaseOptions {
	/** The DID this agent controls, anchoring the signing key. */
	did: string;
	/**
	 * Verification method id: a full DID URL (`did:example:abc#key-1`) or a bare fragment
	 * (`#key-1`), resolved against `did` in the latter case.
	 */
	kid: string;
}

export type SignAgentCardOptions = SignAgentCardBaseOptions &
	(
		| {
				/** The signing key as a private JWK. Only Ed25519 and P-256 are supported. */
				privateJwk: JWK;
				signer?: never;
		  }
		| {
				/** A signer for a key that never leaves its KMS. See {@link AgentCardSigner}. */
				signer: AgentCardSigner;
				privateJwk?: never;
		  }
	);

/** `EdDSA` for an Ed25519 key, `ES256` for a P-256 key - the only two curves signed with elsewhere in this package. */
function algFor(jwk: JWK): AgentCardSignatureAlgorithm {
	if (jwk.crv === 'Ed25519') return 'EdDSA';
	if (jwk.crv === 'P-256') return 'ES256';
	throw new Error(`unsupported key for agent card signing: kty=${jwk.kty} crv=${jwk.crv}`);
}

function resolveKid(did: string, kid: string): string {
	return kid.startsWith('did:') ? kid : `${did}${kid.startsWith('#') ? kid : `#${kid}`}`;
}

function base64url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('base64url');
}

/**
 * Signs `agentCard` and returns the card with the new signature appended to `signatures`. A card
 * may carry more than one signature; this does not remove any that are already present.
 */
export async function signAgentCard(agentCard: AgentCard, options: SignAgentCardOptions): Promise<AgentCard> {
	const kid = resolveKid(options.did, options.kid);

	if (options.privateJwk !== undefined) {
		const alg = algFor(options.privateJwk);
		const privateKey = await importJWK(options.privateJwk, alg);
		const sign = generateAgentCardSignature(privateKey as Parameters<typeof generateAgentCardSignature>[0], {
			alg,
			kid,
			typ: 'JWT',
		});
		return sign(agentCard);
	}

	const { signer } = options;
	if (signer?.alg !== 'EdDSA' && signer?.alg !== 'ES256') {
		throw new Error(`unsupported agent card signing algorithm: ${String(signer?.alg)}`);
	}
	// Same header, same key order, same encoding as the privateJwk path's jose.FlattenedSign.
	const protectedHeader = base64url(
		new TextEncoder().encode(JSON.stringify({ alg: signer.alg, kid, typ: 'JWT' })),
	);
	const payload = base64url(new TextEncoder().encode(canonicalizeAgentCard(agentCard)));
	const signature = await signer.sign(new TextEncoder().encode(`${protectedHeader}.${payload}`));
	if (!(signature instanceof Uint8Array) || signature.length !== 64) {
		// The usual cause is an ES256 signer returning DER: it would produce a card no verifier accepts.
		throw new Error(
			`agent card signer returned ${signature instanceof Uint8Array ? `${signature.length} bytes` : 'a non-Uint8Array'}; ` +
				`${signer.alg} signatures must be 64 bytes (raw r||s for ES256, not DER)`,
		);
	}
	return {
		...agentCard,
		// `header` is the (empty) unprotected header the SDK's type requires; `signatures` is not
		// part of the canonical payload, so it has no effect on what was signed.
		signatures: [
			...(agentCard.signatures ?? []),
			{ protected: protectedHeader, signature: base64url(signature), header: {} },
		],
	};
}
