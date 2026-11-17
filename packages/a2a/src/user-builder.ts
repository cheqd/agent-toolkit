/**
 * The verifying `userBuilder` half of the chosen gate design (verifying userBuilder + enforcing
 * wrapper - see docs/research/a2a-trust-binding-findings-2026-11.md §2). Reads the WIRE body
 * (never the SDK's typed objects), verifies the request proof, and returns the verified DID as
 * the SDK's user, or an unauthenticated user carrying the rejection reason. It never throws: a
 * throwing userBuilder surfaces as an opaque HTTP 500, which this design deliberately avoids.
 *
 * Works for both `@a2a-js/sdk/server/express`'s `jsonRpcHandler` and `restHandler` unchanged:
 * JSON-RPC carries `{ method, params }` on its single `POST /` route; REST carries the params as
 * the bare body, with the method implied by the route (`POST .../message:send` /
 * `.../message:stream`). The covered form (`coveredRequest`) is transport-neutral either way -
 * only the method/params extraction differs here. Which route a request hit is read from
 * Express's own `req.route.path` (set strictly after Express's router has already matched the
 * request), never re-derived from the raw request path by regex - see `methodAndParamsFor`'s
 * comments for why that distinction matters. gRPC is NOT covered by this function: it has its
 * own `UserBuilder` shape entirely (reading the deserialised protobuf request, not an HTTP
 * body) - see `grpc-user-builder.ts`.
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
	/**
	 * The route Express itself matched against (Express's own `req.route`), set strictly AFTER
	 * Express's router has already applied its own matching - case-insensitive, trailing-slash-
	 * tolerant, tenant-prefix-stripping - against one of the fixed patterns `restHandler`/
	 * `jsonRpcHandler` registered. This MUST be read from here, never re-derived from the raw
	 * request path: a regex on the path can diverge from what Express decided to dispatch to
	 * (see the `message:send$`-style regex this replaced, and the comment below for why).
	 */
	route?: { path?: string };
}

// The exact suffix of `req.route.path` for the message:send/message:stream routes, as registered
// by @a2a-js/sdk's restHandler (and its v0.3 legacy-compat rest handler) - e.g. "/message\:send",
// or "/:tenant/message\:send" once Express strips a tenant prefix into req.params.tenant. This is
// Express's own matched-route pattern string, assigned from the SDK's hardcoded registration, so
// it is identical regardless of the request's casing or trailing slash - unlike the request path
// itself, which is attacker-controlled.
const MESSAGE_SEND_ROUTE_SUFFIX = '/message\\:send';
const MESSAGE_STREAM_ROUTE_SUFFIX = '/message\\:stream';
// jsonRpcHandler registers exactly one route for its POST body: "/". It is the only route where
// reading body.method/body.params is ever legitimate.
const JSON_RPC_ROUTE_PATH = '/';

function methodAndParamsFor(req: WireRequest | null | undefined): { method?: string; params?: unknown } {
	const body = req?.body ?? {};
	const routePath = req?.route?.path;
	// A request on the message:send/message:stream route is executed by restHandler as
	// SendMessageRequest.fromJSON(body): a body carrying its own top-level `method`/`params`
	// fields (smuggled alongside the real top-level fields restHandler actually reads) does not
	// change what gets executed, so it MUST NOT change what gets verified either. Once the route
	// is (robustly) identified, the bare body is the covered params with no further
	// interpretation - never body.method/body.params.
	if (typeof routePath === 'string') {
		if (routePath.endsWith(MESSAGE_SEND_ROUTE_SUFFIX)) return { method: 'SendMessage', params: body };
		if (routePath.endsWith(MESSAGE_STREAM_ROUTE_SUFFIX)) return { method: 'SendStreamingMessage', params: body };
		// The single JSON-RPC endpoint: this is the only case where body.method/body.params is
		// the request's actual, intended shape.
		if (routePath === JSON_RPC_ROUTE_PATH && body.method !== undefined) {
			return { method: body.method, params: body.params };
		}
		// Every other REST route (GET /tasks/:id, POST /tasks/:id:cancel, GET /tasks,
		// push-notification-config routes, GET /extendedAgentCard, ...) is provably neither the
		// message route nor the JSON-RPC endpoint, so body.method/body.params is NEVER consulted,
		// no matter what it contains. That fallback is exactly how a captured SendMessage proof
		// could be replayed on an unrelated route to authenticate as its DID and read/cancel/
		// register webhooks for another user's scoped data.
		return {};
	}
	// No Express route information at all: we cannot prove this is the JSON-RPC endpoint (or any
	// other route), so never fall back to body.method/body.params - that was the pre-#32 gap.
	return {};
}

export function createVerifyingUserBuilder(deps: GateVerifyDeps) {
	return async function verifyingUserBuilder(req: WireRequest | null | undefined): Promise<GateUser> {
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
