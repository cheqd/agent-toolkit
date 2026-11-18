/**
 * A DID-backed `retrievePublicKey` callback for `@a2a-js/sdk`'s `verifyAgentCardSignature`.
 *
 * `verifyAgentCardSignature` passes the signer-supplied `jku` header straight to this callback.
 * A2A §8.4.3, as currently published, says to retrieve the key "using the `kid` and `jku`",
 * which lets a signer nominate its own trust root (CWE-863: a verifier that fetches `jku`
 * verifies against whatever key the ATTACKER serves there, not the key the caller actually
 * trusts). This implementation never reads `jku` - it is accepted only so the callback shape
 * matches the SDK's, and resolves strictly by `kid`, against DID documents it chooses to trust.
 *
 * Supports `did:web` (a real HTTPS fetch, injected) and `did:key` (Ed25519 only, pure
 * computation, no fetch). `did:cheqd` is opt-in only, via an injected resolver - this module has
 * no network dependency of its own for it.
 *
 * Fails closed - returns no key, never throws past its own boundary - on: an unsupported DID
 * method, a malformed DID, `kid` not matching `expectedDid` (when given), a `kid` the resolved
 * document does not publish, transport failure, invalid JSON, or a malformed DID document.
 *
 * `did:web` resolution has two further hardening measures, both found by review:
 *
 * 1. Segment charset validation. `didWebToUrl` percent-decodes each `:`-delimited segment of
 *    the DID (per the DID Web Method) and then concatenates the decoded value straight into a
 *    `https://${host}/...` template string. Decoding BEFORE validating, with no re-validation of
 *    what came out, lets a decoded segment contain characters that are structurally meaningful
 *    to a URL parser - `@`, `/`, `#`, backslash, control characters - changing what the
 *    resulting string actually means once a real URL parser (the one `fetch` itself uses) reads
 *    it. E.g. `did:web:good.example.com%40internal-host` decodes to the single segment
 *    `good.example.com@internal-host`; built naively into `https://good.example.com@internal-
 *    host/.well-known/did.json`, a URL parser reads `good.example.com` as discarded userinfo and
 *    `internal-host` as the REAL host contacted - an SSRF primitive that lets a `did:web` value
 *    which superficially names one host actually direct the fetch at a completely different
 *    one (an internal service, a metadata endpoint). `%23` (a literal `#`) is a milder version
 *    of the same root cause: it silently truncates the path the server actually receives, since
 *    `fetch` treats everything after `#` as a client-side-only fragment. Every decoded segment
 *    is now validated against a safe charset BEFORE being used to build the URL, rejecting
 *    anything that could be reinterpreted as new URL structure rather than plain host/path data.
 * 2. A fetch timeout and a response-size cap (enforced for the default fetch implementation;
 *    an injected `fetchDidWebDocument` is responsible for its own body-size bound, but the
 *    timeout wraps ANY implementation, default or injected) - a compromised or malicious
 *    `did:web` server could otherwise hang the request indefinitely or stream an unbounded
 *    response body to exhaust memory.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** The subset of a resolved DID document this module reads. */
export interface MinimalDidDocument {
	readonly id: string;
	readonly verificationMethod?: readonly MinimalVerificationMethod[];
	/**
	 * Ids (or embedded methods) of keys this DID actually signs with. `@kya-os/mcp` 1.23.0+'s
	 * `createStatusListProofVerifier` requires a status-list signing key to be listed here, not
	 * merely under `verificationMethod` - see `eddsa-jcs-status.ts`'s `createCheqdStatusChecker`.
	 * Not read by this module's own `kid`-based Agent Card key resolution.
	 */
	readonly assertionMethod?: readonly (string | MinimalVerificationMethod)[];
	/**
	 * The DID's resolution metadata says it is deactivated. A deactivated DID still resolves, so
	 * callers can show it as deactivated rather than as unknown, but none of its keys verify
	 * anything: {@link keyFromDocument} and {@link assertionMethodKeyFromDocument} refuse it with
	 * `did_deactivated`.
	 */
	readonly deactivated?: boolean;
}

export interface MinimalVerificationMethod {
	readonly id: string;
	/**
	 * Required by `@kya-os/mcp` 1.23.0+'s `assertionMethod` lookup (W3C Controlled Identifiers v1.0
	 * §3.3 step 8: a retrieved method must have a non-empty `id`, `type` and `controller`) - not
	 * read by this module's own Agent Card key resolution.
	 */
	readonly type?: string;
	readonly controller?: string;
	readonly publicKeyJwk?: Record<string, unknown>;
	readonly publicKeyMultibase?: string;
	readonly publicKeyBase58?: string;
}

/** The shape `verifyAgentCardSignature` accepts back - a plain JWK needs no `jose` dependency. */
export type PublicKeyJwk = Record<string, unknown> & { kty: string };

export interface RetrievePublicKeyOptions {
	/** If set, a `kid` whose DID part is not this is rejected before any resolution is attempted. */
	expectedDid?: string;
	/** Fetches a `did:web` document. Defaults to the global `fetch`. Injected so this module has
	 * no hard dependency on a particular HTTP stack, and so tests never hit the network. */
	fetchDidWebDocument?: (url: string) => Promise<{ status: number; json(): Promise<unknown> }>;
	/** Opt-in `did:cheqd` resolution. Omit to reject every `did:cheqd` `kid` (fail-closed default -
	 * this module does not assume a trusted cheqd resolver endpoint on the caller's behalf).
	 * For a deactivated DID, return its document with `deactivated: true`, so its keys are
	 * refused with `did_deactivated`. `createDidCheqdResolver` does this; a custom resolver (for
	 * example one backed by a Credo agent's `DidsApi`) must copy
	 * `didDocumentMetadata.deactivated` onto the document itself. */
	resolveDidCheqd?: (did: string) => Promise<MinimalDidDocument | null>;
	/** Milliseconds to wait for a `did:web` fetch (default or injected) before giving up.
	 * Default 5000. */
	didWebFetchTimeoutMs?: number;
	/** Maximum `did:web` response body size in bytes, enforced only by the DEFAULT fetch
	 * implementation - an injected `fetchDidWebDocument` is responsible for its own bound.
	 * Default 1_000_000 (1 MB): generous for a DID document, small enough to bound memory
	 * against a compromised or malicious server streaming an unbounded body. */
	didWebMaxResponseBytes?: number;
}

const DEFAULT_DID_WEB_FETCH_TIMEOUT_MS = 5000;
const DEFAULT_DID_WEB_MAX_RESPONSE_BYTES = 1_000_000;

class KeyResolutionError extends Error {}

function fail(reason: string): never {
	throw new KeyResolutionError(reason);
}

/**
 * Build a `retrievePublicKey(kid, jku)` callback for `verifyAgentCardSignature`. `jku` is
 * accepted for shape compatibility and never read.
 */
export function createRetrievePublicKey(
	options: RetrievePublicKeyOptions = {},
): (kid: string, jku?: string) => Promise<PublicKeyJwk> {
	return async function retrievePublicKey(kid: string, _jku?: string): Promise<PublicKeyJwk> {
		const hash = kid.indexOf('#');
		if (hash < 0) fail('kid_missing_fragment');
		const did = kid.slice(0, hash);
		if (options.expectedDid !== undefined && did !== options.expectedDid) fail('kid_wrong_did');

		if (did.startsWith('did:key:')) return resolveDidKey(did, kid);
		if (did.startsWith('did:web:')) {
			return resolveDidWeb(
				did,
				kid,
				options.fetchDidWebDocument ??
					defaultFetchDidWeb(options.didWebMaxResponseBytes ?? DEFAULT_DID_WEB_MAX_RESPONSE_BYTES),
				options.didWebFetchTimeoutMs ?? DEFAULT_DID_WEB_FETCH_TIMEOUT_MS,
			);
		}
		if (did.startsWith('did:cheqd:')) {
			if (!options.resolveDidCheqd) fail('did_cheqd_resolution_not_configured');
			const document = await options.resolveDidCheqd(did);
			if (document === null) fail('did_cheqd_unresolvable');
			return keyFromDocument(document, kid);
		}
		fail('unsupported_did_method');
	};
}

function defaultFetchDidWeb(
	maxResponseBytes: number,
): (url: string) => Promise<{ status: number; json(): Promise<unknown> }> {
	return async function fetchDidWeb(url: string) {
		// `redirect: 'error'` - NOT the default ('follow') - makes `fetch` itself fail a request
		// whose response is a redirect, instead of transparently chasing it. A did:web host that
		// returns a 3xx could otherwise redirect this request to an arbitrary other host
		// (including plain http://, which `fetch` does not block as an https-to-http downgrade),
		// bypassing the #42 SSRF hardening - the segment-charset check and the https-only URL
		// built by `didWebToUrl` only constrain where the FIRST request goes, not where a
		// redirect response sends it next.
		const response = await fetch(url, { redirect: 'error' });
		return {
			status: response.status,
			async json(): Promise<unknown> {
				const text = await readBoundedText(response, maxResponseBytes);
				return JSON.parse(text);
			},
		};
	};
}

/** Reads `response`'s body as text, aborting (and releasing the underlying connection) as soon
 * as more than `maxBytes` has been read - never buffering an unbounded body in memory first and
 * checking its size only afterwards. */
async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
	if (response.body === null) return response.text();
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				await reader.cancel();
				fail('did_web_response_too_large');
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}
	return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8');
}

/** Exported for reuse by other modules that already hold a resolved DID document and a `kid`
 * (e.g. `@cheqd/agent-identity-ap2`'s generic DataIntegrityProof verifier) - avoids re-deriving
 * the same publicKeyJwk/Multibase/Base58 dispatch logic a second time. */
export function keyFromDocument(document: MinimalDidDocument, kid: string): PublicKeyJwk {
	if (document.deactivated === true) fail('did_deactivated');
	const method = (document.verificationMethod ?? []).find(
		(candidate) => methodId(candidate, document.id) === kid,
	);
	if (!method) fail('kid_not_in_document');
	if (method.publicKeyJwk) {
		const jwk = method.publicKeyJwk;
		if (typeof jwk.kty !== 'string') fail('malformed_public_key_jwk');
		return jwk as PublicKeyJwk;
	}
	if (method.publicKeyMultibase) return jwkFromEd25519Multibase(method.publicKeyMultibase);
	if (method.publicKeyBase58) return jwkFromEd25519Base58(method.publicKeyBase58);
	fail('unsupported_key_encoding');
}

/** A verification method's absolute id - DID documents may write it relative (`#key-1`). */
function methodId(method: MinimalVerificationMethod, did: string): string {
	return method.id.startsWith('#') ? `${did}${method.id}` : method.id;
}

/**
 * Resolves `kid` as a key the DID document's `assertionMethod` relationship actually publishes -
 * not merely present somewhere in `verificationMethod` - per W3C Controlled Identifiers v1.0
 * §3.3 step 8 (a retrieved method must have a non-empty `id`, `type` and `controller`) and step
 * 10 (`controller` must be the DID). A key listed only under `verificationMethod`, or under
 * another relationship such as `authentication`, does not resolve here, even if it resolves via
 * {@link keyFromDocument}. Use this, never `keyFromDocument`, wherever a proof's own stated
 * purpose is `assertionMethod` (an assertion by the DID's subject, e.g. a status list or a
 * payment-key credential) - `keyFromDocument` remains correct for this module's own Agent Card
 * key resolution, which has no such relationship requirement to begin with.
 */
export function assertionMethodKeyFromDocument(document: MinimalDidDocument, kid: string): PublicKeyJwk {
	if (document.deactivated === true) fail('did_deactivated');
	const relationship = document.assertionMethod ?? [];
	const matched = relationship.find((entry) =>
		typeof entry === 'string'
			? (entry.startsWith('#') ? `${document.id}${entry}` : entry) === kid
			: methodId(entry, document.id) === kid,
	);
	if (!matched) fail('kid_not_in_assertion_method');
	// A string entry names a method the document must also publish under verificationMethod; an
	// embedded entry carries its own fields directly and needs no further lookup.
	const method =
		typeof matched === 'string'
			? (document.verificationMethod ?? []).find((candidate) => methodId(candidate, document.id) === kid)
			: matched;
	if (!method) fail('kid_not_in_document');
	if (!method.type || !method.controller) fail('malformed_verification_method');
	if (method.controller !== document.id) fail('controller_mismatch');
	if (method.publicKeyJwk) {
		const jwk = method.publicKeyJwk;
		if (typeof jwk.kty !== 'string') fail('malformed_public_key_jwk');
		return jwk as PublicKeyJwk;
	}
	if (method.publicKeyMultibase) return jwkFromEd25519Multibase(method.publicKeyMultibase);
	if (method.publicKeyBase58) return jwkFromEd25519Base58(method.publicKeyBase58);
	fail('unsupported_key_encoding');
}

async function resolveDidWeb(
	did: string,
	kid: string,
	fetchDidWebDocument: (url: string) => Promise<{ status: number; json(): Promise<unknown> }>,
	fetchTimeoutMs: number,
): Promise<PublicKeyJwk> {
	const url = didWebToUrl(did);
	let response: { status: number; json(): Promise<unknown> };
	try {
		response = await withTimeout(fetchDidWebDocument(url), fetchTimeoutMs, 'did_web_fetch_timeout');
	} catch (error) {
		if (error instanceof KeyResolutionError) throw error;
		fail('did_web_fetch_failed');
	}
	if (response.status !== 200) fail('did_web_fetch_failed');
	let document: unknown;
	try {
		document = await response.json();
	} catch (error) {
		if (error instanceof KeyResolutionError) throw error; // e.g. did_web_response_too_large
		fail('did_web_invalid_json');
	}
	if (!isMinimalDidDocument(document) || document.id !== did) fail('did_web_document_mismatch');
	return keyFromDocument(document, kid);
}

/** Rejects with `reason` once `timeoutMs` elapses, whichever comes first - applies uniformly to
 * ANY `fetchDidWebDocument` implementation, default or injected, closing the "a compromised
 * server just never responds" window regardless of how the fetch itself is performed. Does not
 * cancel `promise` - for the default implementation that's fine (the fetch's own eventual
 * settlement is simply ignored), since the goal is bounding how long THIS call waits, not
 * guaranteeing the underlying connection closes instantly. */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, reason: string): Promise<T> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new KeyResolutionError(reason)), timeoutMs);
		promise.then(
			(value) => {
				clearTimeout(timer);
				resolve(value);
			},
			(error) => {
				clearTimeout(timer);
				reject(error);
			},
		);
	});
}

/** `did:web:example.com` -> `https://example.com/.well-known/did.json`;
 * `did:web:example.com:a:b` -> `https://example.com/a/b/did.json` (DID Web Method, §Read).
 * Each decoded segment is validated against a safe charset - see the class doc comment for why
 * skipping this (building the URL directly from whatever a percent-decode produces) is an SSRF
 * primitive, not merely a cosmetic concern. */
function didWebToUrl(did: string): string {
	const rest = did.slice('did:web:'.length);
	if (rest.length === 0) fail('malformed_did_web');
	const segments = rest.split(':').map((segment) => {
		let decoded: string;
		try {
			decoded = decodeURIComponent(segment);
		} catch {
			fail('malformed_did_web');
		}
		if (!isSafeDidWebSegment(decoded)) fail('malformed_did_web');
		if (!isAllowedDidWebSegmentValue(decoded)) fail('malformed_did_web');
		return decoded;
	});
	const host = segments[0];
	if (host === undefined || host.length === 0) fail('malformed_did_web');
	const path = segments.slice(1);
	return path.length === 0
		? `https://${host}/.well-known/did.json`
		: `https://${host}/${path.join('/')}/did.json`;
}

/** Forbids every character that is structurally meaningful to a URL parser - `@` (authority/
 * userinfo separator - the SSRF-enabling case), `/` and `\` (path/authority separators), `#`
 * (fragment separator - silently truncates what the server actually receives), `?` (query
 * separator), and any ASCII control character or space. A decoded segment containing any of
 * these could be reinterpreted as new URL structure rather than plain host/path data once it
 * reaches `https://${host}/...`'s own URL parser - exactly the class of bug this guards against.
 * Deliberately permissive otherwise (Unicode letters in an IDN host, say, are left to whatever
 * the actual HTTP client does with them) - this is not a hostname-syntax validator, only a
 * guard against URL-structuring characters slipping through a decode. */
function isSafeDidWebSegment(segment: string): boolean {
	for (const char of segment) {
		const code = char.codePointAt(0) ?? 0;
		if (code <= 0x20 || code === 0x7f) return false;
	}
	return !/[@/\\#?]/.test(segment);
}

/** Rejects a decoded segment that is empty, `.`, or `..` (review finding #8, the did:web part).
 * `isSafeDidWebSegment` only forbids characters a URL parser would reinterpret as new URL
 * structure - it does not forbid a segment that a URL/path NORMALIZER later collapses or
 * discards. A `..` segment survives that charset check (every character in it is plain ASCII)
 * yet `did:web:host:users:bob:..:alice` builds `https://host/users/bob/../alice/did.json`, which
 * normalizes to `https://host/users/alice/did.json` - fetching alice's path while the DID string
 * superficially named bob's. An empty segment (two adjacent `:`s, or `%3A%3A`) is rejected for
 * the same reason: it is not meaningful path/host data either. */
function isAllowedDidWebSegmentValue(segment: string): boolean {
	return segment.length > 0 && segment !== '.' && segment !== '..';
}

function isMinimalDidDocument(value: unknown): value is MinimalDidDocument {
	return (
		typeof value === 'object' &&
		value !== null &&
		typeof (value as { id?: unknown }).id === 'string' &&
		((value as { verificationMethod?: unknown }).verificationMethod === undefined ||
			Array.isArray((value as { verificationMethod?: unknown }).verificationMethod))
	);
}

/** `did:key` is self-certifying: the DID itself IS the key, under an Ed25519 multicodec prefix
 * (varint 0xed01), base58btc-encoded with a leading `z`. No document fetch needed or possible. */
function resolveDidKey(did: string, kid: string): PublicKeyJwk {
	const multibase = did.slice('did:key:'.length);
	// A bare did:key names one implicit verificationMethod, conventionally fragmented with its
	// own multibase value; anything else is a kid this method does not publish.
	if (kid !== `${did}#${multibase}`) fail('kid_not_in_document');
	return jwkFromEd25519Multibase(multibase);
}

function jwkFromEd25519Multibase(multibase: string): PublicKeyJwk {
	if (!multibase.startsWith('z')) fail('unsupported_multibase_encoding');
	const bytes = base58Decode(multibase.slice(1), MAX_DID_KEY_BASE58_LEN);
	// Multicodec varint for Ed25519 public key: 0xed 0x01 (two bytes, this prefix needs no
	// multi-byte varint continuation since 0xed01 < 0x4000).
	if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) fail('unsupported_key_type');
	const x = base64UrlEncode(bytes.slice(2));
	return { kty: 'OKP', crv: 'Ed25519', x };
}

/** `publicKeyBase58` (the `Ed25519VerificationKey2018` legacy encoding, no multicodec prefix,
 * no `z` multibase marker - plain base58btc over the raw 32-byte Ed25519 public key). Still
 * published by real DIDs on the public cheqd testnet resolver as of November 2026, alongside the
 * newer `publicKeyMultibase`/`publicKeyJwk` forms. */
function jwkFromEd25519Base58(encoded: string): PublicKeyJwk {
	const bytes = base58Decode(encoded, MAX_DID_KEY_BASE58_LEN);
	if (bytes.length !== 32) fail('unsupported_key_type');
	const x = base64UrlEncode(bytes);
	return { kty: 'OKP', crv: 'Ed25519', x };
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_ALPHABET_MAP = new Map(Array.from(BASE58_ALPHABET).map((char, i) => [char, i]));

/** The longest a base58btc string legitimately needed here can be: 34 bytes (the Ed25519
 * multicodec-prefixed `publicKeyMultibase` form) base58-encodes to at most
 * ceil(34 * 8 / log2(58)) = 47 characters; the 32-byte raw `publicKeyBase58` form needs fewer.
 * 50 leaves a small margin, same rationale as `eddsa-jcs-2022.ts`'s `MAX_PROOF_VALUE_BASE58_LEN`. */
const MAX_DID_KEY_BASE58_LEN = 50;

function base58Decode(encoded: string, maxLen: number): Uint8Array {
	// Review finding #3: this decode is a BigInt multiply-accumulate, quadratic in input length.
	// `kid` (and therefore the did:key multibase value decoded here) is attacker-controlled -
	// `kid === did#multibase` is trivially satisfied - and the SAME decoder also handles
	// `publicKeyMultibase`/`publicKeyBase58` from a fetched did:web/did:cheqd document. Bounding
	// the input BEFORE the loop, not after, is what keeps an oversized value cheap to reject.
	if (encoded.length > maxLen) fail('base58_too_long');
	if (encoded.length === 0) return new Uint8Array(0);
	let num = 0n;
	for (const char of encoded) {
		const value = BASE58_ALPHABET_MAP.get(char);
		if (value === undefined) fail('invalid_base58');
		num = num * 58n + BigInt(value);
	}
	let hex = num === 0n ? '' : num.toString(16);
	if (hex.length % 2 === 1) hex = `0${hex}`;
	let leadingZeros = 0;
	for (const char of encoded) {
		if (char !== '1') break;
		leadingZeros++;
	}
	const out = new Uint8Array(leadingZeros + hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		out[leadingZeros + i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return out;
}

function base64UrlEncode(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
