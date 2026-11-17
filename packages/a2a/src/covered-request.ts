/**
 * The A2A canonical request shape — the one genuinely new piece of this binding.
 * `requestHash` MUST be computed over `{ method, params }` with the proof metadata key removed
 * from `params.message.metadata`, and that key alone - nothing else stripped.
 *
 * Found by review: an earlier version also stripped a second, `'org.kya-os/proof@1'`, key from
 * the covered form, as a "legacy mirror" of `PROOF_META_KEY`. Nothing in this codebase - not
 * `user-builder.ts`, not `grpc-user-builder.ts`, not the Python port's `gate.py` - ever reads
 * that key as a verification input; it was never anything but write-only dead weight. Excluding
 * ANY `message.metadata` key from the covered/signed form is only safe when that key is also
 * verified by some other means - otherwise excluding it from coverage is exactly how you let an
 * attacker smuggle unsigned data into `message.metadata` (and, since the gate never substitutes
 * the covered form back into the request that actually gets processed, into task history too)
 * past a proof that is otherwise genuinely valid: the proof's own signature never covered that
 * field, so putting anything there, or changing it after the fact, does not invalidate it. Do
 * not add another excluded key here unless something actually reads and verifies it.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
export const PROOF_META_KEY = 'org.kya-os/request-proof';
export const RESPONSE_PROOF_META_KEY = 'org.kya-os/response-proof';

export interface CoveredRequest {
	method: string;
	params: unknown;
}

/**
 * Build the covered form of an A2A `SendMessage` / `SendStreamingMessage` request: the wire
 * `params` with `message.metadata[PROOF_META_KEY]` removed, and `message.metadata` removed
 * entirely if that empties it. `method` MUST be the wire method name (`SendMessage`,
 * `SendStreamingMessage`) - never the v0.3 `message/send` spelling.
 */
export function coveredRequest(method: string, wireParams: unknown): CoveredRequest {
	const params = structuredClone(wireParams) as { message?: { metadata?: Record<string, unknown> } };
	const metadata = params?.message?.metadata;
	if (metadata) {
		delete metadata[PROOF_META_KEY];
		if (Object.keys(metadata).length === 0 && params.message) {
			delete params.message.metadata;
		}
	}
	return { method, params };
}

/** The covered form of a final result, with the response proof key removed from its metadata. */
export function coveredResult<T extends { metadata?: Record<string, unknown> }>(result: T): T {
	const covered = structuredClone(result);
	if (covered.metadata) {
		delete covered.metadata[RESPONSE_PROOF_META_KEY];
		if (Object.keys(covered.metadata).length === 0) {
			delete (covered as { metadata?: unknown }).metadata;
		}
	}
	return covered;
}
