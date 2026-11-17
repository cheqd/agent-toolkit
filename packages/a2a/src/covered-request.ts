/**
 * The A2A canonical request shape — the one genuinely new piece of this binding.
 * `coveredRequest` (below) itself strips exactly one thing: `PROOF_META_KEY` from
 * `params.message.metadata` (dropping `message.metadata` entirely if that empties it) — and
 * that key alone, nothing else in `message.metadata`.
 *
 * `requestHash`, however, is NOT hashed directly from this function's output: this binding never
 * computes it itself - `user-builder.ts`/`grpc-user-builder.ts` hand the covered form produced
 * here to `@kya-os/mcp/card`'s `verifyCardProof`, which hashes it via that package's OWN
 * `computeRequestHash` (`card/proof/canonical.ts`). That function applies ONE MORE stripping
 * step before canonicalizing - it also removes the top-level `params._meta` member, the MCP
 * transport-metadata carrier (it carries the proof itself, so it can never be part of the
 * signed material). That means `params._meta` is UNSIGNED, UNVERIFIED data end to end: nothing
 * here or in `@kya-os/mcp` authenticates it, so whatever a sender puts there travels unchecked
 * by this binding. It is harmless today only because the SDK's `fromJSON`/`ParseDict` already
 * drop `_meta` before this code ever sees it — do not rely on that incidentally, and do not
 * treat `params._meta` as verified input if that ever changes.
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
