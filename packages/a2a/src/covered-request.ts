/**
 * The A2A canonical request shape — the one genuinely new piece of this binding.
 * `requestHash` MUST be computed over `{ method, params }` with the proof metadata key removed
 * from `params.message.metadata`, and that key alone - nothing else stripped.
 *
 * DRAFT — early exploration, not reviewed or stable. See the repository README.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
export const PROOF_META_KEY = 'org.kya-os/request-proof';
export const LEGACY_PROOF_META_KEY = 'org.kya-os/proof@1';
export const RESPONSE_PROOF_META_KEY = 'org.kya-os/response-proof';

export interface CoveredRequest {
	method: string;
	params: unknown;
}

/**
 * Build the covered form of an A2A `SendMessage` / `SendStreamingMessage` request: the wire
 * `params` with `message.metadata[PROOF_META_KEY]` (and its legacy mirror) removed, and
 * `message.metadata` removed entirely if that empties it. `method` MUST be the wire method name
 * (`SendMessage`, `SendStreamingMessage`) - never the v0.3 `message/send` spelling.
 */
export function coveredRequest(method: string, wireParams: unknown): CoveredRequest {
	const params = structuredClone(wireParams) as { message?: { metadata?: Record<string, unknown> } };
	const metadata = params?.message?.metadata;
	if (metadata) {
		delete metadata[PROOF_META_KEY];
		delete metadata[LEGACY_PROOF_META_KEY];
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
