/**
 * The gRPC form of the verifying `userBuilder`. gRPC's `UserBuilder` is a different seam from
 * the Express one in `user-builder.ts`: `(call: grpc.ServerUnaryCall | grpc.ServerWritableStream)
 * => Promise<User>`, reading the already-deserialised protobuf request off `call.request`, not
 * an HTTP body. A gate written for Express does not port to gRPC as-is - this is that port.
 *
 * `@a2a-js/sdk`'s `grpcService({ requestHandler, userBuilder })` registers ONE `userBuilder` for
 * the WHOLE service (confirmed by reading `grpc_service.ts`: every method handler -
 * `sendMessage`, `getTask`, `cancelTask`, ... - calls the same injected `userBuilder(call)`
 * before dispatching). So this cannot be told in advance which RPC it is guarding; it has to
 * work it out from `call` itself.
 *
 * It does that via `call.path` (e.g. `/lf.a2a.v1.A2AService/SendMessage`), confirmed empirically
 * against `@grpc/grpc-js` by logging a real call - `path` is declared `private` on grpc-js's own
 * `ServerUnaryCall`/`ServerWritableStream` CLASSES (so importing their real type and reading
 * `.path` off it would not compile), but is a plain, readable JS property at runtime, since
 * TypeScript's `private` has no runtime effect. This module reads it through its own loosely
 * typed `GrpcCallLike`, not grpc-js's class, so nothing here fights the compiler - but it is
 * reading an internal field grpc-js does not document or promise stability for. Re-verify this
 * (`evidence/transports/grpc-gate.mjs`'s pattern, logging `Object.keys(call)`) on any
 * `@grpc/grpc-js` upgrade.
 *
 * The enforcing wrapper (`wrapper.ts`) is unchanged for gRPC: it only cares about
 * `ServerCallContext.user`, which this userBuilder populates the same way the Express one does.
 *
 * COVERED FORM: `call.request` is the raw *decoded* protobuf object - ts-proto's `decode()`
 * shape (field defaults present, enums numeric, `oneof`s as `{content: {$case, value}}`). That
 * is NOT what the client signed: `client.ts`'s `createProofInterceptor` computes the covered
 * form via `SendMessageRequest.toJSON(params)` - protobuf's standard canonical-JSON mapping
 * (enums as strings, defaults omitted, `oneof`s flattened), the same mapping every protobuf
 * implementation defines (https://protobuf.dev/programming-guides/json/). Hashing the decoded
 * object directly, as an earlier version of this file did, makes every gRPC proof fail with
 * `request_hash_mismatch` even when correctly signed - confirmed by diffing both shapes
 * (`smoke-test-grpc.mjs`'s original finding). The fix is not a new canonicalisation scheme: run
 * `call.request` through the SAME `SendMessageRequest.toJSON` the client already uses (it is a
 * root `@a2a-js/sdk` export, not `server/grpc`-specific), so both sides hash the identical JSON
 * value regardless of which side decoded it.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { SendMessageRequest } from '@a2a-js/sdk';
import { verifyCardProof } from '@kya-os/mcp/card';
import { coveredRequest, PROOF_META_KEY } from './covered-request.js';
import type { GateUser, GateVerifyDeps } from './types.js';

const WRITE_METHODS = new Set(['SendMessage', 'SendStreamingMessage']);

/** The subset of a gRPC call this module reads - avoids a hard `@grpc/grpc-js` dependency for
 * just a type, and avoids the compile error `.path` being `private` on the real class would
 * cause if imported directly. */
export interface GrpcCallLike {
	readonly request: unknown;
	readonly path?: string;
}

function methodFromPath(path: string | undefined): string | undefined {
	if (path?.endsWith('/SendMessage')) return 'SendMessage';
	if (path?.endsWith('/SendStreamingMessage')) return 'SendStreamingMessage';
	return undefined;
}

export function createVerifyingGrpcUserBuilder(deps: GateVerifyDeps) {
	return async function verifyingGrpcUserBuilder(call: GrpcCallLike | null | undefined): Promise<GateUser> {
		const method = methodFromPath(call?.path);
		if (!method || !WRITE_METHODS.has(method)) return { isAuthenticated: false, userName: '' };
		const params = SendMessageRequest.toJSON(call?.request as never) as {
			message?: { metadata?: Record<string, unknown> };
		};
		const proof = params?.message?.metadata?.[PROOF_META_KEY];
		if (!proof) return { isAuthenticated: false, userName: '', rejection: 'missing' };
		const covered = coveredRequest(method, params);
		const result = await verifyCardProof(proof, covered, deps);
		if (!result.ok || !result.did) {
			return { isAuthenticated: false, userName: '', rejection: result.reasons[0] ?? 'invalid' };
		}
		return { isAuthenticated: true, userName: result.did, verified: { did: result.did, covered } };
	};
}
