/**
 * A `did:cheqd` resolver, for the opt-in slot in `createRetrievePublicKey` (and anywhere else
 * that needs a `did:cheqd` document). Fetches from a universal-resolver-shaped endpoint (the
 * public `resolver.cheqd.net` or an equivalent), accepting either a DID Resolution Result
 * (`{ didDocument: ... }`) or a raw DID document - the public resolver has returned both shapes
 * across versions, so this reads whichever is present rather than assuming one.
 *
 * Deliberately NOT the default for `createRetrievePublicKey`'s `resolveDidCheqd` option: `did:
 * cheqd` resolution needs an explicit, injected resolver URL the caller trusts, not a hardcoded
 * endpoint this package reaches for on its own.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Reuses the Agent Card resolver's own document shape, so the function returned here satisfies
// its `resolveDidCheqd` option exactly, with no separate type to drift out of sync.
import type { MinimalDidDocument } from '../agent-card/retrieve-public-key.js';
export type { MinimalDidDocument };

export interface DidCheqdResolverResponse {
	readonly status: number;
	json(): Promise<unknown>;
}

export interface DidCheqdResolverOptions {
	/** Resolver base URL ending at `/1.0/identifiers`, e.g. `https://resolver.cheqd.net/1.0/identifiers`. */
	readonly resolverUrl: string;
	/** Injected fetch, so tests never hit the network. Defaults to the global `fetch`. */
	readonly fetch?: (url: string) => Promise<DidCheqdResolverResponse>;
}

/**
 * Build a `resolveDidCheqd(did)` callback. Fails closed - returns `null`, never throws past its
 * own boundary - on a non-200 response, invalid JSON, a document with no `id`, or a document
 * whose `id` does not match the DID actually requested.
 */
export function createDidCheqdResolver(options: DidCheqdResolverOptions): (did: string) => Promise<MinimalDidDocument | null> {
	const doFetch = options.fetch ?? ((url: string) => fetch(url));
	const base = options.resolverUrl.replace(/\/+$/, '');
	return async function resolveDidCheqd(did: string): Promise<MinimalDidDocument | null> {
		if (!did.startsWith('did:cheqd:')) return null;
		let response: DidCheqdResolverResponse;
		try {
			response = await doFetch(`${base}/${did}`);
		} catch {
			return null;
		}
		if (response.status !== 200) return null;
		let body: unknown;
		try {
			body = await response.json();
		} catch {
			return null;
		}
		if (!isRecord(body)) return null;
		// Universal Resolver shape, or a raw DID document - read whichever is present.
		const candidate = isRecord(body.didDocument) ? body.didDocument : body;
		if (!isMinimalDidDocument(candidate) || candidate.id !== did) return null;
		return candidate;
	};
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

function isMinimalDidDocument(value: unknown): value is MinimalDidDocument {
	return (
		isRecord(value) &&
		typeof value.id === 'string' &&
		(value.verificationMethod === undefined || Array.isArray(value.verificationMethod))
	);
}
