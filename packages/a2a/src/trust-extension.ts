/**
 * The `https://cheqd.io/a2a/ext/trust/v1` extension's per-DID checks (spec §5.2 steps 5-7):
 * reciprocal `alsoKnownAs` linkage, DID-Linked Resource manifest resolution, and credential
 * status - composed from building blocks `@cheqd/agent-identity` already ships
 * (`verifyReciprocalLinkage`, `createManifestCache`, `createCheqdStatusChecker`/
 * `verifyLedgerAnchoredStatus`), not reimplemented here.
 *
 * These are discovery-time checks, refreshed on a TTL, never per call (spec §5.5) - so this
 * module caches a verdict per canonical DID and `enforce()` in wrapper.ts consults the cache,
 * rather than resolving a manifest or a status list on every proof it verifies.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import {
	verifyReciprocalLinkage,
	type LinkageDidDocument,
	type ManifestCache,
	type ManifestKind,
} from '@cheqd/agent-identity';

/** The trust extension's activation params, per spec §5.1. */
export interface TrustExtensionActivation {
	/** The caller's claimed anchored `did:cheqd`, if any. Reciprocal linkage is required when present. */
	readonly anchoredDid?: string;
	/** `did:cheqd:...?resourceName=...&resourceType=TrustConfigManifest|CapabilityManifest|ConformanceManifest`. */
	readonly trustConfigRef?: string;
	readonly statusCheck?: 'required' | 'optional';
}

export interface TrustExtensionDeps {
	/** Resolves a `did:web` or `did:cheqd` document for the linkage check. Fails closed (returns null) on any error. */
	resolveDidDocument(did: string): Promise<LinkageDidDocument | null>;
	manifestCache: ManifestCache;
	/** Required when any activation can set `statusCheck: 'required'`. Fails closed if omitted. */
	checkStatus?: (canonicalDid: string) => Promise<{ revoked: boolean; fresh: boolean }>;
}

export type TrustExtensionResult = { readonly ok: true } | { readonly ok: false; readonly reasons: readonly string[] };

/**
 * Parse a DID-Linked Resource reference (`did:cheqd:...?resourceName=X&resourceType=Y`) into its
 * parts. Returns `undefined` on anything malformed - callers fail closed on that, same as every
 * other reason.
 */
function parseResourceRef(ref: string): { did: string; kind: ManifestKind; resourceName: string } | undefined {
	const match = /^(did:cheqd:(?:mainnet|testnet):[A-Za-z0-9_-]{16,64})\?(.+)$/.exec(ref);
	if (!match) return undefined;
	const [, did, query] = match;
	const params = new URLSearchParams(query);
	const resourceName = params.get('resourceName');
	const resourceType = params.get('resourceType');
	if (!did || !resourceName || !resourceType) return undefined;
	if (resourceType !== 'TrustConfigManifest' && resourceType !== 'CapabilityManifest' && resourceType !== 'ConformanceManifest') {
		return undefined;
	}
	return { did, kind: resourceType, resourceName };
}

/**
 * Run the trust extension's per-DID checks (spec §5.2 steps 5-7) for `canonicalDid` under the
 * given activation params. Fails closed: a declared check that cannot be completed (malformed
 * ref, missing dependency, resolver failure) is a failure, never a skip.
 */
export async function verifyTrustExtension(
	canonicalDid: string,
	activation: TrustExtensionActivation,
	deps: TrustExtensionDeps,
): Promise<TrustExtensionResult> {
	const reasons: string[] = [];

	if (activation.anchoredDid) {
		const [canonicalDoc, anchoredDoc] = await Promise.all([
			deps.resolveDidDocument(canonicalDid),
			deps.resolveDidDocument(activation.anchoredDid),
		]);
		if (!canonicalDoc || !anchoredDoc) {
			reasons.push('linkage_resolution_failed');
		} else {
			const linkage = verifyReciprocalLinkage(canonicalDoc, anchoredDoc);
			if (!linkage.ok) reasons.push(...linkage.reasons.map((r) => `linkage_${r}`));
		}
	}

	if (activation.trustConfigRef) {
		const parsed = parseResourceRef(activation.trustConfigRef);
		if (!parsed) {
			reasons.push('malformed_trust_config_ref');
		} else {
			const manifest = await deps.manifestCache.get(parsed.did, parsed.kind, parsed.resourceName);
			if (!manifest.ok) reasons.push(...manifest.reasons.map((r) => `manifest_${r}`));
		}
	}

	if (activation.statusCheck === 'required') {
		if (!deps.checkStatus) {
			reasons.push('status_check_unavailable');
		} else {
			const status = await deps.checkStatus(canonicalDid);
			if (status.revoked || !status.fresh) reasons.push(status.revoked ? 'status_revoked' : 'status_not_fresh');
		}
	}

	return reasons.length === 0 ? { ok: true } : { ok: false, reasons };
}

export interface TrustExtensionCacheOptions {
	/** TTL in milliseconds. Default 5 minutes, matching `createManifestCache`'s default (spec §5.5). */
	readonly ttlMs?: number;
	/** Epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

export interface TrustExtensionCache {
	get(canonicalDid: string, activation: TrustExtensionActivation): Promise<TrustExtensionResult>;
	clear(): void;
}

const DEFAULT_TTL_MS = 5 * 60_000;

/**
 * TTL-bounded cache over {@link verifyTrustExtension}, so a verified DID's trust-extension
 * checks are refreshed on a timer, not re-run against resolvers and manifests on every request
 * the gate verifies (spec §5.5: never per call).
 */
export function createTrustExtensionCache(deps: TrustExtensionDeps, options: TrustExtensionCacheOptions = {}): TrustExtensionCache {
	const now = options.now ?? Date.now;
	const ttl = options.ttlMs ?? DEFAULT_TTL_MS;
	const cache = new Map<string, { result: TrustExtensionResult; expiresAt: number }>();
	return {
		async get(canonicalDid, activation) {
			const key = `${canonicalDid}\u0000${JSON.stringify(activation)}`;
			const cached = cache.get(key);
			if (cached && cached.expiresAt > now()) return cached.result;
			const result = await verifyTrustExtension(canonicalDid, activation, deps);
			cache.set(key, { result, expiresAt: now() + ttl });
			return result;
		},
		clear() {
			cache.clear();
		},
	};
}
