/**
 * Resolves a cheqd DID-Linked Resource manifest - `TrustConfigManifest`, `CapabilityManifest` or
 * `ConformanceManifest` (the three non-status-list artifact types this binding reads; see
 * docs/research/a2a-trust-binding-findings-2026-11.md and v1/spec.md §5.4 for why these three and
 * not others). Same trust model as `verifyLedgerAnchoredStatus`: the resolver's own checksum is
 * checked against the bytes it actually returned, multiple resolvers can be required to agree,
 * and every unreadable, stale or malformed case fails closed. DID-Linked Resources are read at
 * discovery and policy-refresh time only, per spec - never written to during a normal call, and
 * this module has no write path at all.
 *
 * Caching is per-kind, with a caller-supplied TTL (spec §5.5: "implementations MUST bound every
 * cache with an artifact-specific TTL"). `createManifestCache` wraps `resolveManifest` with that.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export type ManifestKind = 'TrustConfigManifest' | 'CapabilityManifest' | 'ConformanceManifest';

/** A resolver response: HTTP status and raw body bytes. */
export interface ManifestResolverResponse {
	readonly status: number;
	readonly body: Uint8Array;
}

export type ManifestFetch = (url: string) => Promise<ManifestResolverResponse>;

export interface ManifestPrimitives {
	/** Lower-case hex SHA-256 of the bytes. */
	sha256Hex(bytes: Uint8Array): Promise<string> | string;
	decodeUtf8(bytes: Uint8Array): string;
}

export interface ResolveManifestOptions {
	/** Resolver base URLs ending at `/1.0/identifiers`. */
	readonly resolvers: readonly string[];
	readonly fetch: ManifestFetch;
	readonly primitives: ManifestPrimitives;
	/** Epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
	/** Resolvers that must return the same answer. Default 1. */
	readonly minAgreement?: number;
	/** How far a resolver's `retrieved` time may differ from ours. Default 60 seconds. */
	readonly maxRetrievedSkewMs?: number;
	/** Cap on the resource body. Default 1 MiB - manifests are policy documents, not bulk data. */
	readonly maxBytes?: number;
	/** Permit http resolvers. For tests only. */
	readonly allowInsecureResolvers?: boolean;
}

export type ResolveManifestResult =
	| {
			readonly ok: true;
			readonly content: unknown;
			readonly resourceId: string;
			readonly checksum: string;
			readonly resourceVersion: string;
			readonly resolvers: readonly string[];
	  }
	| { readonly ok: false; readonly reasons: readonly string[] };

const DEFAULT_MAX_SKEW_MS = 60_000;
const DEFAULT_MAX_BYTES = 1024 * 1024;

class ManifestError extends Error {
	constructor(readonly reason: string) {
		super(reason);
	}
}

function fail(reason: string): never {
	throw new ManifestError(reason);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Resolve one manifest resource by DID, kind and resource name. Resolves with `ok: false` and
 * reasons rather than throwing, for every failure including a malformed input.
 */
export async function resolveManifest(
	did: string,
	kind: ManifestKind,
	resourceName: string,
	options: ResolveManifestOptions,
): Promise<ResolveManifestResult> {
	try {
		const minAgreement = options.minAgreement ?? 1;
		if (!Number.isInteger(minAgreement) || minAgreement < 1) fail('invalid_min_agreement');
		if (options.resolvers.length < minAgreement) fail('not_enough_resolvers');
		const bases = options.resolvers.map((base) => normaliseBase(base, options.allowInsecureResolvers === true));

		const settled = await Promise.allSettled(bases.map((base) => checkOne(base, did, kind, resourceName, options)));
		const agreed: { base: string; outcome: Outcome }[] = [];
		const reasons: string[] = [];
		settled.forEach((result, i) => {
			if (result.status === 'fulfilled') agreed.push({ base: bases[i] ?? '', outcome: result.value });
			else reasons.push(result.reason instanceof ManifestError ? result.reason.reason : 'resolver_error');
		});

		const first = agreed[0];
		if (first !== undefined && agreed.some((a) => !sameOutcome(a.outcome, first.outcome))) {
			return { ok: false, reasons: ['resolver_disagreement'] };
		}
		if (first === undefined || agreed.length < minAgreement) {
			return { ok: false, reasons: reasons.length > 0 ? unique(reasons) : ['no_resolver_answered'] };
		}
		return {
			ok: true,
			content: first.outcome.content,
			resourceId: first.outcome.resourceId,
			checksum: first.outcome.checksum,
			resourceVersion: first.outcome.resourceVersion,
			resolvers: agreed.map((a) => a.base),
		};
	} catch (error) {
		return { ok: false, reasons: [error instanceof ManifestError ? error.reason : 'unexpected_error'] };
	}
}

interface Outcome {
	readonly content: unknown;
	readonly resourceId: string;
	readonly checksum: string;
	readonly resourceVersion: string;
}

async function checkOne(
	base: string,
	did: string,
	kind: ManifestKind,
	resourceName: string,
	options: ResolveManifestOptions,
): Promise<Outcome> {
	const now = options.now ?? Date.now;
	const name = encodeURIComponent(resourceName);
	const type = encodeURIComponent(kind);

	const metaResponse = await options.fetch(`${base}/${did}?resourceName=${name}&resourceType=${type}&resourceMetadata=true`);
	if (metaResponse.status !== 200) fail('metadata_unavailable');
	const meta = parseJson(metaResponse.body, options.primitives);

	const dereferencing = isRecord(meta) ? meta['dereferencingMetadata'] : undefined;
	const retrieved = isRecord(dereferencing) ? Date.parse(String(dereferencing['retrieved'])) : Number.NaN;
	const skew = options.maxRetrievedSkewMs ?? DEFAULT_MAX_SKEW_MS;
	if (Number.isNaN(retrieved) || Math.abs(now() - retrieved) > skew) fail('resolver_stale');

	const content = isRecord(meta) ? meta['contentMetadata'] : undefined;
	const linked = isRecord(content) ? content['linkedResourceMetadata'] : undefined;
	if (!Array.isArray(linked) || linked.length !== 1) fail('ambiguous_or_missing_resource');
	const resource = linked[0];
	if (!isRecord(resource)) fail('malformed_metadata');
	if (resource['resourceType'] !== kind || resource['resourceName'] !== resourceName) fail('resource_mismatch');
	if (resource['nextVersionId'] !== null && resource['nextVersionId'] !== undefined) fail('not_latest_version');
	const resourceId = resource['resourceId'];
	const checksum = resource['checksum'];
	const resourceVersion = resource['resourceVersion'];
	if (typeof resourceId !== 'string' || !/^[0-9a-fA-F-]{36}$/.test(resourceId)) fail('malformed_metadata');
	if (typeof checksum !== 'string' || !/^[0-9a-fA-F]{64}$/.test(checksum)) fail('malformed_metadata');
	if (typeof resourceVersion !== 'string') fail('malformed_metadata');

	const dataResponse = await options.fetch(`${base}/${did}/resources/${resourceId}`);
	if (dataResponse.status !== 200) fail('resource_unavailable');
	if (dataResponse.body.length > (options.maxBytes ?? DEFAULT_MAX_BYTES)) fail('resource_too_large');
	const digest = await options.primitives.sha256Hex(dataResponse.body);
	if (digest.toLowerCase() !== checksum.toLowerCase()) fail('checksum_mismatch');

	const parsedContent = parseJson(dataResponse.body, options.primitives);
	return { content: parsedContent, resourceId, checksum: checksum.toLowerCase(), resourceVersion };
}

function sameOutcome(a: Outcome, b: Outcome): boolean {
	return a.resourceId === b.resourceId && a.checksum === b.checksum;
}

function unique(values: readonly string[]): string[] {
	return [...new Set(values)];
}

function normaliseBase(base: string, allowInsecure: boolean): string {
	const trimmed = base.replace(/\/+$/, '');
	if (!trimmed.startsWith('https://') && !(allowInsecure && trimmed.startsWith('http://'))) fail('resolver_not_https');
	return trimmed;
}

function parseJson(bytes: Uint8Array, primitives: ManifestPrimitives): unknown {
	try {
		return JSON.parse(primitives.decodeUtf8(bytes));
	} catch {
		return fail('invalid_json');
	}
}

// --- Caching, per spec §5.5: bound every cache with an artifact-specific TTL. -------------------

export interface ManifestCacheOptions extends ResolveManifestOptions {
	/** TTL in milliseconds per manifest kind. A kind not listed here uses `defaultTtlMs`. */
	readonly ttlMsByKind?: Partial<Record<ManifestKind, number>>;
	/** TTL for a kind not listed in `ttlMsByKind`. Default 5 minutes. */
	readonly defaultTtlMs?: number;
}

interface CacheEntry {
	readonly result: ResolveManifestResult;
	readonly expiresAt: number;
}

export interface ManifestCache {
	/** Returns the cached result if still fresh, otherwise resolves again and caches the result -
	 * including a failure, so a down resolver cannot be hammered every call within the TTL. */
	get(did: string, kind: ManifestKind, resourceName: string): Promise<ResolveManifestResult>;
	/** Drops every cached entry. */
	clear(): void;
}

const DEFAULT_TTL_MS = 5 * 60_000;

export function createManifestCache(options: ManifestCacheOptions): ManifestCache {
	const now = options.now ?? Date.now;
	const cache = new Map<string, CacheEntry>();
	return {
		async get(did, kind, resourceName) {
			const key = `${did}\u0000${kind}\u0000${resourceName}`;
			const cached = cache.get(key);
			if (cached && cached.expiresAt > now()) return cached.result;
			const result = await resolveManifest(did, kind, resourceName, options);
			const ttl = options.ttlMsByKind?.[kind] ?? options.defaultTtlMs ?? DEFAULT_TTL_MS;
			cache.set(key, { result, expiresAt: now() + ttl });
			return result;
		},
		clear() {
			cache.clear();
		},
	};
}
