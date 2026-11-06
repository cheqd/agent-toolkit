/**
 * The authorised-secondary-key path (WS5 decision 2 + decision A): an "Agent Payment Key
 * Credential", a short-lived VC issued and signed by the agent's PRIMARY key, naming a
 * DIFFERENT key as authorised for payments. This is deliberately NOT the DID-document
 * verification-method path - a VC reuses this programme's existing status-list/revocation
 * machinery directly (`@cheqd/agent-identity`'s `createCheqdStatusChecker`/
 * `verifyLedgerAnchoredStatus`) instead of needing an on-chain write to rotate.
 *
 * Trust tier (decision A): spec §4.6 step 8's `L3`/`L3-minus` assumes the SAME key signs the A2A
 * proof and is `cnf`-bound. A properly-authorised secondary key is a DIFFERENT key by design, so
 * it is neither `L3` nor `L3-minus` - it is a distinct tier, `authorised-secondary-key`,
 * established by verifying the authorisation CHAIN (primary key -> signed VC -> secondary key)
 * rather than by key identity. A revoked or expired credential, or one whose proof does not
 * verify against the agent's own primary key, is never promoted to this tier.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { verifyEddsaJcs2022, type MinimalDidDocument } from '@cheqd/agent-identity';

export const AGENT_PAYMENT_KEY_CREDENTIAL_TYPE = 'AgentPaymentKeyCredential';

export interface AgentPaymentKeyCredential {
	readonly '@context'?: readonly string[] | string;
	readonly type: readonly string[];
	/** The agent's own primary DID - this credential is self-issued, naming a different key as authorised. */
	readonly issuer: string;
	readonly issuanceDate?: string;
	readonly validFrom?: string;
	readonly validUntil?: string;
	readonly credentialSubject: {
		readonly id: string;
		readonly paymentKeyJwk: Record<string, unknown>;
	};
	readonly credentialStatus?: {
		readonly type: string;
		readonly statusPurpose: 'revocation' | 'suspension';
		readonly statusListCredential: string;
		readonly statusListIndex: string;
	};
	readonly proof?: Record<string, unknown>;
}

export interface PaymentKeyAuthorizationDeps {
	readonly resolveDidDocument: (did: string) => Promise<MinimalDidDocument | null>;
	/** Fails closed: a credential with no `credentialStatus`, or whose status cannot be checked, is rejected. */
	readonly checkRevoked: (credential: AgentPaymentKeyCredential) => Promise<{ revoked: boolean; fresh: boolean }>;
	/** Epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

export type PaymentKeyAuthorizationResult =
	| { readonly ok: true; readonly tier: 'authorised-secondary-key'; readonly paymentKeyJwk: Record<string, unknown> }
	| { readonly ok: false; readonly reason: string };

/**
 * Verify an Agent Payment Key Credential: its proof verifies against the issuer's (the agent's
 * primary) resolved key, it is self-issued (subject == issuer), it is within its validity
 * window, and it is not revoked. Fails closed on every unverifiable case.
 */
export async function verifyAgentPaymentKeyCredential(
	credential: AgentPaymentKeyCredential,
	primaryAgentDid: string,
	deps: PaymentKeyAuthorizationDeps,
): Promise<PaymentKeyAuthorizationResult> {
	if (!credential.type.includes(AGENT_PAYMENT_KEY_CREDENTIAL_TYPE)) return { ok: false, reason: 'wrong_credential_type' };
	if (credential.issuer !== primaryAgentDid) return { ok: false, reason: 'issuer_is_not_primary_agent' };
	if (credential.credentialSubject.id !== primaryAgentDid) return { ok: false, reason: 'not_self_issued' };

	const now = deps.now ?? Date.now;
	const validUntil = credential.validUntil;
	if (validUntil !== undefined && Date.parse(validUntil) <= now()) return { ok: false, reason: 'credential_expired' };

	if (!(await verifyEddsaJcs2022(credential, deps.resolveDidDocument))) return { ok: false, reason: 'proof_invalid' };

	if (!credential.credentialStatus) return { ok: false, reason: 'missing_credential_status' };
	let status: { revoked: boolean; fresh: boolean };
	try {
		status = await deps.checkRevoked(credential);
	} catch {
		return { ok: false, reason: 'status_check_failed' };
	}
	if (status.revoked || !status.fresh) return { ok: false, reason: status.revoked ? 'payment_key_revoked' : 'payment_key_status_not_fresh' };

	return { ok: true, tier: 'authorised-secondary-key', paymentKeyJwk: credential.credentialSubject.paymentKeyJwk };
}
