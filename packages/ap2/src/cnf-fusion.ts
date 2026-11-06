/**
 * cnf key-continuity (WS5 decision 1): `thumbprint(AP2 cnf.jwk) == thumbprint(resolve(kid))`.
 * The same RFC 7638 thumbprint already used throughout this programme for the A2A proof's own
 * `cnf.jkt` fusion (spec §4.6 step 8) - this module compares the Open Mandate's `cnf.jwk`
 * against whichever agent key the caller resolved, so AP2's key continuity and A2A's share one
 * notion of "the same key", without this package reaching into `@cheqd/agent-identity-a2a`'s
 * gate internals to get it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { calculateJwkThumbprint } from 'jose';
import type { AgentPaymentKeyCredential, PaymentKeyAuthorizationDeps } from './payment-key-authorization.js';
import { verifyAgentPaymentKeyCredential } from './payment-key-authorization.js';

export type CnfFusionResult =
	| { readonly ok: true; readonly tier: 'same-key' | 'authorised-secondary-key' }
	| { readonly ok: false; readonly reason: string };

/**
 * Compare the Open Mandate's `cnf.jwk` thumbprint against the resolved agent key's thumbprint.
 * `ok: true` means the SAME key signs both the A2A proof and the AP2 mandate - full continuity.
 * A mismatch is not automatically a failure: see `payment-key-authorization.ts` for the
 * authorised-secondary-key tier, which accepts a DIFFERENT key when it is itself authorised by
 * the agent's primary key via a verified, non-revoked Agent Payment Key Credential.
 */
export async function verifySameKeyContinuity(mandateCnfJwk: Record<string, unknown>, resolvedAgentKeyJwk: Record<string, unknown>): Promise<CnfFusionResult> {
	try {
		const [mandateThumbprint, agentThumbprint] = await Promise.all([
			calculateJwkThumbprint(mandateCnfJwk as never, 'sha256'),
			calculateJwkThumbprint(resolvedAgentKeyJwk as never, 'sha256'),
		]);
		if (mandateThumbprint !== agentThumbprint) return { ok: false, reason: 'cnf_jwk_thumbprint_mismatch' };
		return { ok: true, tier: 'same-key' };
	} catch {
		return { ok: false, reason: 'cnf_jwk_malformed' };
	}
}

/**
 * Full WS5 decision 1+2 composition: try same-key continuity first; if the mandate's `cnf.jwk`
 * is a different key, accept it only when `paymentKeyCredential` is given AND verifies as an
 * authorised secondary key (decision A) AND its `paymentKeyJwk` is the one actually bound in
 * the mandate's `cnf`. Fails closed if neither path succeeds.
 */
export async function verifyCnfContinuity(
	mandateCnfJwk: Record<string, unknown>,
	resolvedAgentKeyJwk: Record<string, unknown>,
	primaryAgentDid: string,
	paymentKeyCredential: AgentPaymentKeyCredential | undefined,
	deps: PaymentKeyAuthorizationDeps,
): Promise<CnfFusionResult> {
	const sameKey = await verifySameKeyContinuity(mandateCnfJwk, resolvedAgentKeyJwk);
	if (sameKey.ok) return sameKey;
	if (!paymentKeyCredential) return sameKey;

	const authorized = await verifyAgentPaymentKeyCredential(paymentKeyCredential, primaryAgentDid, deps);
	if (!authorized.ok) return { ok: false, reason: authorized.reason };

	const boundToAuthorizedKey = await verifySameKeyContinuity(mandateCnfJwk, authorized.paymentKeyJwk);
	if (!boundToAuthorizedKey.ok) return { ok: false, reason: 'cnf_jwk_not_the_authorised_payment_key' };

	return { ok: true, tier: 'authorised-secondary-key' };
}
