/**
 * The verifying `userBuilder` half of the chosen gate design (verifying userBuilder + enforcing
 * wrapper - see docs/research/a2a-trust-binding-findings-2026-11.md §2). Reads the WIRE
 * JSON-RPC body (never the SDK's typed objects), verifies the request proof, and returns the
 * verified DID as the SDK's user, or an unauthenticated user carrying the rejection reason. It
 * never throws: a throwing userBuilder surfaces as an opaque HTTP 500, which this design
 * deliberately avoids.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { verifyCardProof } from '@kya-os/mcp/card';
import { coveredRequest, PROOF_META_KEY } from './covered-request.js';
import type { GateUser, GateVerifyDeps } from './types.js';

const WRITE_METHODS = new Set(['SendMessage', 'SendStreamingMessage']);

export interface WireRequest {
	body?: { method?: string; params?: unknown };
}

export function createVerifyingUserBuilder(deps: GateVerifyDeps) {
	return async function verifyingUserBuilder(req: WireRequest): Promise<GateUser> {
		const { method, params } = req.body ?? {};
		if (!method || !WRITE_METHODS.has(method)) {
			return { isAuthenticated: false, userName: '' };
		}
		const message = (params as { message?: { metadata?: Record<string, unknown> } } | undefined)?.message;
		const proof = message?.metadata?.[PROOF_META_KEY];
		if (!proof) {
			return { isAuthenticated: false, userName: '', rejection: 'missing' };
		}
		const covered = coveredRequest(method, params);
		const result = await verifyCardProof(proof, covered, deps);
		if (!result.ok || !result.did) {
			return { isAuthenticated: false, userName: '', rejection: result.reasons[0] ?? 'invalid' };
		}
		return { isAuthenticated: true, userName: result.did, verified: { did: result.did, covered } };
	};
}
