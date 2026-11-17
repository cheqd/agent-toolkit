// SPDX-License-Identifier: Apache-2.0
// Tests for the DID-backed retrievePublicKey callback. did:key is pure computation, checked
// against a real generated Ed25519 keypair encoded by hand (no external test vector trusted
// blindly). did:web uses an injected fetch, so no network call is made.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createRetrievePublicKey } from '../dist/index.js';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
	if (bytes.length === 0) return '';
	let num = 0n;
	for (const byte of bytes) num = num * 256n + BigInt(byte);
	let out = '';
	while (num > 0n) {
		out = BASE58_ALPHABET[Number(num % 58n)] + out;
		num /= 58n;
	}
	for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out;
	return out;
}

function multibaseFor(publicKeyBytes) {
	const prefixed = new Uint8Array(2 + publicKeyBytes.length);
	prefixed[0] = 0xed;
	prefixed[1] = 0x01;
	prefixed.set(publicKeyBytes, 2);
	return `z${base58Encode(prefixed)}`;
}
function didKeyFor(publicKeyBytes) {
	return `did:key:${multibaseFor(publicKeyBytes)}`;
}

function rawEd25519PublicKey() {
	const { publicKey } = generateKeyPairSync('ed25519');
	const jwk = publicKey.export({ format: 'jwk' });
	return { raw: Buffer.from(jwk.x, 'base64url'), jwkX: jwk.x };
}

test('did:key resolves to the correct JWK, computed from the DID itself', async () => {
	const { raw, jwkX } = rawEd25519PublicKey();
	const did = didKeyFor(raw);
	const retrieve = createRetrievePublicKey();
	const jwk = await retrieve(`${did}#${multibaseFor(raw)}`);
	assert.equal(jwk.kty, 'OKP');
	assert.equal(jwk.crv, 'Ed25519');
	assert.equal(jwk.x, jwkX);
});

test('did:key with a malformed fragment is rejected', async () => {
	const { raw } = rawEd25519PublicKey();
	const did = didKeyFor(raw);
	const retrieve = createRetrievePublicKey();
	await assert.rejects(() => retrieve(`${did}#not-the-right-fragment`));
});

test('an attacker-supplied jku is never read', async () => {
	const { raw, jwkX } = rawEd25519PublicKey();
	const did = didKeyFor(raw);
	const retrieve = createRetrievePublicKey();
	const kid = `${did}#${did.slice('did:key:'.length)}`;
	const jwk = await retrieve(kid, 'https://attacker.example/jwks.json');
	assert.equal(jwk.x, jwkX);
});

test('a kid belonging to a different DID than expectedDid is rejected before any resolution', async () => {
	const { raw } = rawEd25519PublicKey();
	const did = didKeyFor(raw);
	const retrieve = createRetrievePublicKey({ expectedDid: 'did:key:someone-else' });
	await assert.rejects(() => retrieve(`${did}#${did.slice('did:key:'.length)}`));
});

test('did:web fetches the well-known document via the injected fetch, never the network', async () => {
	const { raw, jwkX } = rawEd25519PublicKey();
	const did = 'did:web:example.com';
	const kid = `${did}#key-1`;
	let fetchedUrl;
	const fetchDidWebDocument = async (url) => {
		fetchedUrl = url;
		return {
			status: 200,
			async json() {
				return {
					id: did,
					verificationMethod: [{ id: kid, controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwkX } }],
				};
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	const jwk = await retrieve(kid);
	assert.equal(fetchedUrl, 'https://example.com/.well-known/did.json');
	assert.equal(jwk.x, jwkX);
});

test('did:web with a path component builds the path-based URL (DID Web Method)', async () => {
	const did = 'did:web:example.com:users:alice';
	let fetchedUrl;
	const fetchDidWebDocument = async (url) => {
		fetchedUrl = url;
		return { status: 200, async json() { return { id: did, verificationMethod: [] }; } };
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`)); // no matching method, but the URL build is what's under test
	assert.equal(fetchedUrl, 'https://example.com/users/alice/did.json');
});

test('a did:web document whose id does not match the requested DID is rejected', async () => {
	const did = 'did:web:example.com';
	const fetchDidWebDocument = async () => ({
		status: 200,
		async json() { return { id: 'did:web:attacker.example', verificationMethod: [] }; },
	});
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
});

test('did:web host with a percent-encoded port resolves to host:port (DID Web Method)', async () => {
	const did = 'did:web:example.com%3A3000';
	let fetchedUrl;
	const fetchDidWebDocument = async (url) => {
		fetchedUrl = url;
		return { status: 200, async json() { return { id: did, verificationMethod: [] }; } };
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`)); // no matching method; the URL build is what's under test
	assert.equal(fetchedUrl, 'https://example.com:3000/.well-known/did.json');
});

// Regression: the decoded host segment used to be inserted into the fetch URL with no
// validation. `%3A443%40` decodes to `:443@`, so this DID's "host" segment becomes
// `trusted.example:443@attacker.example` - a real HTTP client (per URL authority syntax) sends
// the request to attacker.example, treating everything before the unescaped `@` as userinfo,
// while the raw DID string still reads as if it names trusted.example. Confirm the attack is
// mechanically real (the resulting URL's actual host is attacker.example, not trusted.example),
// then confirm the fix rejects it before ever attempting a fetch.
test('a did:web host that decodes to an authority-confusing string (userinfo "@") is rejected before any fetch', async () => {
	const confusingUrl = 'https://trusted.example:443@attacker.example/.well-known/did.json';
	assert.equal(new URL(confusingUrl).hostname, 'attacker.example'); // the attack is real: this is who actually gets contacted

	const did = 'did:web:trusted.example%3A443%40attacker.example';
	let fetchCalled = false;
	const fetchDidWebDocument = async () => {
		fetchCalled = true;
		return { status: 200, async json() { return {}; } };
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(fetchCalled, false, 'must reject before ever attempting to fetch the attacker-controlled host');
});

test('a did:web host that decodes to a path-like string ("/") is rejected before any fetch', async () => {
	const did = 'did:web:example.com%2Fattacker.example';
	let fetchCalled = false;
	const fetchDidWebDocument = async () => {
		fetchCalled = true;
		return { status: 200, async json() { return {}; } };
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(fetchCalled, false);
});

// Both size-cap tests below use a document that is otherwise entirely well-formed and would
// resolve successfully if read in full (padded past the 1 MiB cap with an extra field) - not a
// malformed or truncated one. This is deliberate: it isolates the size cap as the only possible
// reason for rejection. A test using a too-small or malformed oversized body would "pass" even
// against the pre-fix code for the wrong reason (rejected for being malformed, not for being
// too large) - exactly the false-positive this shape rules out.
function oversizedButOtherwiseValidDidWebDocument(did, kid, jwkX) {
	return JSON.stringify({
		id: did,
		verificationMethod: [{ id: kid, controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwkX } }],
		padding: 'x'.repeat(2 * 1024 * 1024), // pushes the whole JSON body to ~2 MiB, over the 1 MiB cap
	});
}

test('the default did:web fetch rejects an oversized response even when its Content-Length is accurate', async () => {
	const { jwkX } = rawEd25519PublicKey();
	const did = 'did:web:example.com';
	const kid = `${did}#key-1`;
	const body = oversizedButOtherwiseValidDidWebDocument(did, kid, jwkX);
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => new Response(body, { status: 200, headers: { 'content-length': String(body.length) } });
	try {
		const retrieve = createRetrievePublicKey();
		await assert.rejects(() => retrieve(kid));
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test('the default did:web fetch rejects an oversized response with no (or a lying, too-small) Content-Length, by counting actual bytes read', async () => {
	const { jwkX } = rawEd25519PublicKey();
	const did = 'did:web:example.com';
	const kid = `${did}#key-1`;
	const body = oversizedButOtherwiseValidDidWebDocument(did, kid, jwkX);
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => new Response(body, { status: 200 }); // no content-length header at all
	try {
		const retrieve = createRetrievePublicKey();
		await assert.rejects(() => retrieve(kid));
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test('a did:web fetch failure (non-200) is rejected, not treated as no key', async () => {
	const did = 'did:web:example.com';
	const fetchDidWebDocument = async () => ({ status: 404, async json() { return {}; } });
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
});

test('did:cheqd is rejected by default (no resolver configured) - fails closed', async () => {
	const retrieve = createRetrievePublicKey();
	await assert.rejects(() => retrieve('did:cheqd:testnet:abc#key-1'));
});

test('did:cheqd resolves via the injected resolver when configured', async () => {
	const did = 'did:cheqd:testnet:abc';
	const kid = `${did}#key-1`;
	const resolveDidCheqd = async (requested) =>
		requested === did
			? { id: did, verificationMethod: [{ id: kid, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' } }] }
			: null;
	const retrieve = createRetrievePublicKey({ resolveDidCheqd });
	const jwk = await retrieve(kid);
	assert.equal(jwk.x, 'abc');
});

test('did:cheqd resolves a legacy Ed25519VerificationKey2018 publicKeyBase58 verification method', async () => {
	// The real public cheqd testnet resolver still serves this format on at least one live DID
	// (did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede, checked 4 November 2026) - not a
	// hypothetical shape.
	const { raw, jwkX } = rawEd25519PublicKey();
	const did = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
	const kid = `${did}#key-1`;
	const resolveDidCheqd = async (requested) =>
		requested === did
			? {
					id: did,
					verificationMethod: [{ id: kid, type: 'Ed25519VerificationKey2018', controller: did, publicKeyBase58: base58Encode(raw) }],
				}
			: null;
	const retrieve = createRetrievePublicKey({ resolveDidCheqd });
	const jwk = await retrieve(kid);
	assert.equal(jwk.kty, 'OKP');
	assert.equal(jwk.crv, 'Ed25519');
	assert.equal(jwk.x, jwkX);
});

test('did:cheqd rejects a publicKeyBase58 that does not decode to a 32-byte Ed25519 key', async () => {
	const did = 'did:cheqd:testnet:abc';
	const kid = `${did}#key-1`;
	const resolveDidCheqd = async () => ({
		id: did,
		verificationMethod: [{ id: kid, publicKeyBase58: base58Encode(new Uint8Array(16)) }],
	});
	const retrieve = createRetrievePublicKey({ resolveDidCheqd });
	await assert.rejects(() => retrieve(kid));
});

test('an unsupported DID method is rejected', async () => {
	const retrieve = createRetrievePublicKey();
	await assert.rejects(() => retrieve('did:example:123#key-1'));
});

test('a kid with no fragment is rejected', async () => {
	const retrieve = createRetrievePublicKey();
	await assert.rejects(() => retrieve('did:web:example.com'));
});
