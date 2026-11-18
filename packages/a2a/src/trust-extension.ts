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

/**
 * The trust extension's activation params, per spec §5.1.
 *
 * ⚠️ Design note (per-deployment vs. per-caller): in this codebase, a single `activation` value
 * is constructed once per deployment and shared across every caller - see `TrustExtensionGate`
 * in wrapper.ts, whose `enforce()` always calls `cache.get(user.verified.did, trustExtension.activation)`
 * with the SAME `activation` object regardless of which caller is being checked. `anchoredDid`'s
 * own doc comment below calls it "the caller's claimed anchored DID", which reads as per-caller,
 * but nothing here actually varies `activation` by caller: every caller passing through one gate
 * is checked against the exact same `anchoredDid` and `trustConfigRef`. That's fine for a
 * deployment fronting a single agent identity, but it is a latent mismatch between what the
 * field is documented to mean and how it is actually wired. If an integrator "fixes" the
 * apparent per-caller framing by building a fresh `TrustExtensionActivation` per request from
 * caller-supplied data (e.g. a request header naming the caller's own anchored DID), the
 * resolved-document-id binding and trustConfigRef-to-anchoredDid binding enforced below become
 * the ONLY thing stopping a caller from pointing this module at an arbitrary anchored DID and
 * trust-config manifest of their own choosing - do not build a per-request `activation` from
 * caller-supplied fields; derive `anchoredDid` only from something already cryptographically
 * bound to the caller (e.g. `user.verified.did`'s own linked documents), never from a
 * client-asserted value.
 */
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

export type TrustExtensionResult =
	{ readonly ok: true } | { readonly ok: false; readonly reasons: readonly string[] };

/**
 * Parse a DID-Linked Resource reference (`did:cheqd:...?resourceName=X&resourceType=Y`) into its
 * parts. Returns `undefined` on anything malformed - callers fail closed on that, same as every
 * other reason.
 */
function parseResourceRef(
	ref: string,
): { did: string; kind: ManifestKind; resourceName: string } | undefined {
	const match = /^(did:cheqd:(?:mainnet|testnet):[A-Za-z0-9_-]{16,64})\?(.+)$/.exec(ref);
	if (!match) return undefined;
	const [, did, query] = match;
	const params = new URLSearchParams(query);
	const resourceName = params.get('resourceName');
	const resourceType = params.get('resourceType');
	if (!did || !resourceName || !resourceType) return undefined;
	if (
		resourceType !== 'TrustConfigManifest' &&
		resourceType !== 'CapabilityManifest' &&
		resourceType !== 'ConformanceManifest'
	) {
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
		} else if (canonicalDoc.id !== canonicalDid || anchoredDoc.id !== activation.anchoredDid) {
			// Bind every resolved document to the DID we actually asked for, immediately after
			// resolving it - `resolveDidDocument` is an injected seam with no id-binding contract
			// enforced by this module itself. Without this, a lax/generic resolver (e.g. over
			// did:web) could return a document whose own `id` names the OTHER party's DID, and
			// `verifyReciprocalLinkage` - which only compares the two documents against each
			// other, never against what was actually requested - would be none the wiser.
			reasons.push('linkage_resolved_doc_id_mismatch');
		} else if (canonicalDoc.deactivated === true || anchoredDoc.deactivated === true) {
			reasons.push('linkage_did_deactivated');
		} else {
			const linkage = verifyReciprocalLinkage(canonicalDoc, anchoredDoc);
			if (!linkage.ok) reasons.push(...linkage.reasons.map((r) => `linkage_${r}`));
		}
	}

	if (activation.trustConfigRef) {
		const parsed = parseResourceRef(activation.trustConfigRef);
		if (!parsed) {
			reasons.push('malformed_trust_config_ref');
		} else if (parsed.did !== (activation.anchoredDid ?? canonicalDid)) {
			// The manifest must belong to the DID this check is actually being run for - the
			// caller's claimed anchored DID when declared, else the canonical DID itself.
			// Without this, a valid, correctly-checksummed manifest belonging to ANY did:cheqd
			// (not necessarily the caller's) would be accepted merely because it resolves and
			// its checksum matches - `resolveManifest`'s own collection-id binding only proves
			// the manifest belongs to `parsed.did`, never that `parsed.did` is the right DID.
			reasons.push('manifest_did_mismatch');
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
			if (status.revoked || !status.fresh)
				reasons.push(status.revoked ? 'status_revoked' : 'status_not_fresh');
		}
	}

	return reasons.length === 0 ? { ok: true } : { ok: false, reasons };
}

export interface TrustExtensionCacheOptions {
	/** TTL in milliseconds. Default 5 minutes, matching `createManifestCache`'s default (spec §5.5). */
	readonly ttlMs?: number;
	/**
	 * Hard cap on the number of distinct `(canonicalDid, activation)` entries kept at once.
	 * Default 10,000. The cache key is derived from the CALLER's own verified DID (`enforce()`
	 * in wrapper.ts always passes `user.verified.did` - the identity the request's proof was
	 * just checked against, never attacker-supplied independently of that), but minting a new
	 * DID is cheap (one keypair), and every lookup caches its result regardless of outcome - a
	 * caller presenting a fresh self-asserted DID on every request, which fails the trust check
	 * every time, would otherwise grow this Map forever. Once the cap is hit, the oldest entry
	 * (by insertion order, which `Map` preserves) is evicted to make room - not a full LRU, but
	 * enough to bound memory under sustained churn without adding a dependency.
	 */
	readonly maxEntries?: number;
	/** Epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

export interface TrustExtensionCache {
	get(canonicalDid: string, activation: TrustExtensionActivation): Promise<TrustExtensionResult>;
	clear(): void;
	/** Current number of cached entries. Exposed for tests/observability, not part of the trust decision. */
	size(): number;
}

const DEFAULT_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_ENTRIES = 10_000;

/**
 * TTL-bounded cache over {@link verifyTrustExtension}, so a verified DID's trust-extension
 * checks are refreshed on a timer, not re-run against resolvers and manifests on every request
 * the gate verifies (spec §5.5: never per call). Also size-bounded - see `maxEntries` above -
 * since the TTL alone does not stop the entry count itself from growing without bound between
 * expirations.
 */
export function createTrustExtensionCache(
	deps: TrustExtensionDeps,
	options: TrustExtensionCacheOptions = {},
): TrustExtensionCache {
	const now = options.now ?? Date.now;
	const ttl = options.ttlMs ?? DEFAULT_TTL_MS;
	const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
	const cache = new Map<string, { result: TrustExtensionResult; expiresAt: number }>();
	return {
		async get(canonicalDid, activation) {
			const key = `${canonicalDid}\u0000${JSON.stringify(activation)}`;
			const cached = cache.get(key);
			if (cached && cached.expiresAt > now()) return cached.result;
			const result = await verifyTrustExtension(canonicalDid, activation, deps);
			// A fresh lookup for an existing key must not grow the entry count, so evict (if
			// needed) only when this key is new - otherwise a cache at exactly maxEntries would
			// evict one entry on every refresh of an already-tracked DID for no reason.
			if (!cache.has(key) && cache.size >= maxEntries) {
				const oldest = cache.keys().next().value;
				if (oldest !== undefined) cache.delete(oldest);
			}
			cache.set(key, { result, expiresAt: now() + ttl });
			return result;
		},
		clear() {
			cache.clear();
		},
		size() {
			return cache.size;
		},
	};
}
