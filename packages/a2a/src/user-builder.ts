/**
 * The verifying `userBuilder` half of the chosen gate design (verifying userBuilder + enforcing
 * wrapper - see docs/research/a2a-trust-binding-findings-2026-11.md §2). Reads the WIRE body
 * (never the SDK's typed objects), verifies the request proof, and returns the verified DID as
 * the SDK's user, or an unauthenticated user carrying the rejection reason. It never throws: a
 * throwing userBuilder surfaces as an opaque HTTP 500, which this design deliberately avoids.
 *
 * Works for both `@a2a-js/sdk/server/express`'s `jsonRpcHandler` and `restHandler` unchanged:
 * JSON-RPC carries `{ method, params }`; REST carries the params as the bare body, with the
 * method implied by the route (`POST .../message:send` / `.../message:stream`). The covered
 * form (`coveredRequest`) is transport-neutral either way - only the method/params extraction
 * differs here. gRPC is NOT covered by this function: it has its own `UserBuilder` shape
 * entirely (reading the deserialised protobuf request, not an HTTP body) - see
 * `grpc-user-builder.ts`.
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
	path?: string;
}

function methodAndParamsFor(req: WireRequest): { method?: string; params?: unknown } {
	const body = req.body ?? {};
	if (body.method !== undefined) return { method: body.method, params: body.params };
	// REST: no top-level method, so it's implied by the route (restHandler's own convention).
	if (/message:send$/.test(req.path ?? '')) return { method: 'SendMessage', params: body };
	if (/message:stream$/.test(req.path ?? '')) return { method: 'SendStreamingMessage', params: body };
	return {};
}

export function createVerifyingUserBuilder(deps: GateVerifyDeps) {
	return async function verifyingUserBuilder(req: WireRequest): Promise<GateUser> {
		const { method, params } = methodAndParamsFor(req);
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
