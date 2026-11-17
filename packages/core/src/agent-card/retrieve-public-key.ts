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
	 * this module does not assume a trusted cheqd resolver endpoint on the caller's behalf). */
	resolveDidCheqd?: (did: string) => Promise<MinimalDidDocument | null>;
}

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
		if (did.startsWith('did:web:')) return resolveDidWeb(did, kid, options.fetchDidWebDocument ?? defaultFetchDidWeb);
		if (did.startsWith('did:cheqd:')) {
			if (!options.resolveDidCheqd) fail('did_cheqd_resolution_not_configured');
			const document = await options.resolveDidCheqd(did);
			if (document === null) fail('did_cheqd_unresolvable');
			return keyFromDocument(document, kid);
		}
		fail('unsupported_did_method');
	};
}

async function defaultFetchDidWeb(url: string) {
	return fetch(url);
}

/** Exported for reuse by other modules that already hold a resolved DID document and a `kid`
 * (e.g. `@cheqd/agent-identity-ap2`'s generic DataIntegrityProof verifier) - avoids re-deriving
 * the same publicKeyJwk/Multibase/Base58 dispatch logic a second time. */
export function keyFromDocument(document: MinimalDidDocument, kid: string): PublicKeyJwk {
	const method = (document.verificationMethod ?? []).find((candidate) => methodId(candidate, document.id) === kid);
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
	const relationship = document.assertionMethod ?? [];
	const matched = relationship.find((entry) =>
		typeof entry === 'string' ? (entry.startsWith('#') ? `${document.id}${entry}` : entry) === kid : methodId(entry, document.id) === kid,
	);
	if (!matched) fail('kid_not_in_assertion_method');
	// A string entry names a method the document must also publish under verificationMethod; an
	// embedded entry carries its own fields directly and needs no further lookup.
	const method = typeof matched === 'string' ? (document.verificationMethod ?? []).find((candidate) => methodId(candidate, document.id) === kid) : matched;
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
): Promise<PublicKeyJwk> {
	const url = didWebToUrl(did);
	let response: { status: number; json(): Promise<unknown> };
	try {
		response = await fetchDidWebDocument(url);
	} catch {
		fail('did_web_fetch_failed');
	}
	if (response.status !== 200) fail('did_web_fetch_failed');
	let document: unknown;
	try {
		document = await response.json();
	} catch {
		fail('did_web_invalid_json');
	}
	if (!isMinimalDidDocument(document) || document.id !== did) fail('did_web_document_mismatch');
	return keyFromDocument(document, kid);
}

/** `did:web:example.com` -> `https://example.com/.well-known/did.json`;
 * `did:web:example.com:a:b` -> `https://example.com/a/b/did.json` (DID Web Method, §Read). */
function didWebToUrl(did: string): string {
	const rest = did.slice('did:web:'.length);
	if (rest.length === 0) fail('malformed_did_web');
	const segments = rest.split(':').map((segment) => {
		try {
			return decodeURIComponent(segment);
		} catch {
			fail('malformed_did_web');
		}
	});
	const host = segments[0];
	if (host === undefined || host.length === 0) fail('malformed_did_web');
	const path = segments.slice(1);
	return path.length === 0
		? `https://${host}/.well-known/did.json`
		: `https://${host}/${path.join('/')}/did.json`;
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
	const bytes = base58Decode(multibase.slice(1));
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
	const bytes = base58Decode(encoded);
	if (bytes.length !== 32) fail('unsupported_key_type');
	const x = base64UrlEncode(bytes);
	return { kty: 'OKP', crv: 'Ed25519', x };
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_ALPHABET_MAP = new Map(Array.from(BASE58_ALPHABET).map((char, i) => [char, i]));

function base58Decode(encoded: string): Uint8Array {
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
