// SPDX-License-Identifier: Apache-2.0
// Tests for the DID-backed retrievePublicKey callback. did:key is pure computation, checked
// against a real generated Ed25519 keypair encoded by hand (no external test vector trusted
// blindly). did:web uses an injected fetch, so no network call is made.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import http from 'node:http';
import { createRetrievePublicKey } from '../dist/index.js';

function startServer(handler) {
	return new Promise((resolve) => {
		const server = http.createServer(handler);
		server.listen(0, '127.0.0.1', () => resolve(server));
	});
}

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
					verificationMethod: [
						{ id: kid, controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwkX } },
					],
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
		return {
			status: 200,
			async json() {
				return { id: did, verificationMethod: [] };
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`)); // no matching method, but the URL build is what's under test
	assert.equal(fetchedUrl, 'https://example.com/users/alice/did.json');
});

test('a did:web document whose id does not match the requested DID is rejected', async () => {
	const did = 'did:web:example.com';
	const fetchDidWebDocument = async () => ({
		status: 200,
		async json() {
			return { id: 'did:web:attacker.example', verificationMethod: [] };
		},
	});
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
});

test('a did:web fetch failure (non-200) is rejected, not treated as no key', async () => {
	const did = 'did:web:example.com';
	const fetchDidWebDocument = async () => ({
		status: 404,
		async json() {
			return {};
		},
	});
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
					verificationMethod: [
						{
							id: kid,
							type: 'Ed25519VerificationKey2018',
							controller: did,
							publicKeyBase58: base58Encode(raw),
						},
					],
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

// Regression: didWebToUrl used to percent-decode each segment and concatenate it straight into
// a URL template with no re-validation. A decoded segment containing '@' is read by a real URL
// parser as an authority separator: `good.example.com@internal-host` becomes userinfo
// `good.example.com` (discarded) plus host `internal-host` - an SSRF primitive letting a
// did:web value that superficially names one host actually direct the fetch at a different one.
test('a did:web segment that decodes to an @ is rejected, not built into a host-confusing URL', async () => {
	const did = 'did:web:good.example.com%40internal-host';
	let called = false;
	const fetchDidWebDocument = async () => {
		called = true;
		return {
			status: 200,
			async json() {
				return { id: did, verificationMethod: [] };
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(called, false, 'must be rejected before any fetch is attempted');
});

// Regression: a decoded '#' is a fragment separator to a real URL parser - it silently
// truncates the path actually sent to the server, a corruption of the same root cause. Asserts
// the fetch is never even attempted (not merely that the overall call rejects), so this cannot
// pass for the unrelated reason that an otherwise-successful fetch returns no matching key.
test('a did:web segment that decodes to a # is rejected, not built into a truncating URL', async () => {
	const did = 'did:web:example.com:a%23b';
	let called = false;
	const fetchDidWebDocument = async () => {
		called = true;
		return {
			status: 200,
			async json() {
				return { id: did, verificationMethod: [] };
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(called, false, 'must be rejected before any fetch is attempted');
});

// Regression: a decoded '/' blurs the host/path boundary the same way.
test('a did:web segment that decodes to a / is rejected, not built into a boundary-blurring URL', async () => {
	const did = 'did:web:example.com%2Fattacker-path';
	let called = false;
	const fetchDidWebDocument = async () => {
		called = true;
		return {
			status: 200,
			async json() {
				return { id: did, verificationMethod: [] };
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(called, false, 'must be rejected before any fetch is attempted');
});

test('a did:web fetch that never resolves is rejected once the timeout elapses, not hung forever', async () => {
	const did = 'did:web:example.com';
	const fetchDidWebDocument = () => new Promise(() => {}); // never settles
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument, didWebFetchTimeoutMs: 20 });
	await assert.rejects(() => retrieve(`${did}#key-1`));
});

// Regression (review finding #3): base58Decode did the BigInt multiply-accumulate over the
// WHOLE input before any length check, and the kid is attacker-controlled (kid === did#multibase
// is trivially satisfied for did:key). Decode cost is quadratic in input length, so an oversized
// multibase value ties up the event loop. Asserts both the exact failure mode (eventually
// rejected) and the exact symptom the review measured (wall-clock time), not merely that the call
// rejects - a slow-but-eventually-correct rejection would still be the vulnerability.
test('a did:key with a huge base58 multibase payload is rejected quickly, not decoded character-by-character (CPU DoS)', async () => {
	// 'z' is base58's highest-value digit (57) - repeating it forces the accumulator to grow on
	// every character, the worst case for the BigInt multiply-accumulate's quadratic cost.
	const hugeEncoded = 'z'.repeat(50_000);
	const multibase = `z${hugeEncoded}`;
	const did = `did:key:${multibase}`;
	const retrieve = createRetrievePublicKey();
	const started = performance.now();
	await assert.rejects(() => retrieve(`${did}#${multibase}`));
	const elapsedMs = performance.now() - started;
	assert.ok(
		elapsedMs < 200,
		`expected the oversized payload to be rejected in well under 200ms, took ${elapsedMs}ms`,
	);
});

// Regression (review finding #5): the default fetch implementation called `fetch(url)` with no
// `redirect` option, i.e. the default `redirect: 'follow'`. A did:web host that returns a 3xx can
// therefore redirect the verifier's request to an arbitrary other host (including plain http://),
// bypassing the #42 SSRF hardening (the segment-charset check and https-only URL only constrain
// the FIRST request, not where a redirect sends it). Demonstrates the real default fetch
// implementation (no injected fetchDidWebDocument), against two real local HTTP servers, so this
// cannot be satisfied by an injected test double.
test('the default did:web fetch does not follow a redirect to a different host (SSRF hardening)', async () => {
	let attackerServerHit = false;
	const attackerServer = await startServer((_req, res) => {
		attackerServerHit = true;
		res.writeHead(200, { 'content-type': 'application/json' });
		res.end(JSON.stringify({ id: 'did:web:attacker-controlled', verificationMethod: [] }));
	});
	const attackerPort = attackerServer.address().port;

	const originServer = await startServer((_req, res) => {
		res.writeHead(302, { location: `http://127.0.0.1:${attackerPort}/evil.json` });
		res.end();
	});
	const originPort = originServer.address().port;

	const originalFetch = globalThis.fetch;
	// didWebToUrl always builds an https:// URL (the #42 hardening). Rewriting the scheme to
	// http:// here lets this test run against real plain-HTTP local servers instead of needing a
	// TLS certificate - it changes nothing about what's under test, since the vulnerability is
	// about whether the REDIRECT the first response points to is followed, not the scheme of the
	// first request itself.
	globalThis.fetch = (url, init) => originalFetch(String(url).replace('https://', 'http://'), init);

	try {
		const did = `did:web:127.0.0.1%3A${originPort}`;
		const retrieve = createRetrievePublicKey();
		await assert.rejects(() => retrieve(`${did}#key-1`));
		assert.equal(attackerServerHit, false, 'the redirect must not be followed to a different host/port');
	} finally {
		globalThis.fetch = originalFetch;
		originServer.close();
		attackerServer.close();
	}
});

// Regression (part of review finding #8 that belongs to this file: the did:web variant).
// didWebToUrl did not reject '.' / '..' / empty segments, so a did:web value with a '..' segment
// is built into a URL a real URL parser (or an upstream server) normalizes away, letting
// `did:web:host:users:bob:..:alice` actually address alice's path while superficially naming
// bob's - a path-traversal/identity-confusion primitive on top of the #42 character denylist.
test('a did:web path containing a .. segment is rejected, not used to traverse to a different path', async () => {
	const did = 'did:web:example.com:users:bob:..:alice';
	let called = false;
	const fetchDidWebDocument = async () => {
		called = true;
		return {
			status: 200,
			async json() {
				return { id: did, verificationMethod: [] };
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(called, false, 'must be rejected before any fetch is attempted');
});

test('a did:web path containing a lone . segment is rejected', async () => {
	const did = 'did:web:example.com:users:.:alice';
	let called = false;
	const fetchDidWebDocument = async () => {
		called = true;
		return {
			status: 200,
			async json() {
				return { id: did, verificationMethod: [] };
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(called, false, 'must be rejected before any fetch is attempted');
});

test('a did:web path containing an empty segment is rejected', async () => {
	const did = 'did:web:example.com:users::alice';
	let called = false;
	const fetchDidWebDocument = async () => {
		called = true;
		return {
			status: 200,
			async json() {
				return { id: did, verificationMethod: [] };
			},
		};
	};
	const retrieve = createRetrievePublicKey({ fetchDidWebDocument });
	await assert.rejects(() => retrieve(`${did}#key-1`));
	assert.equal(called, false, 'must be rejected before any fetch is attempted');
});

test('a did:web response body over the configured byte cap is rejected, not buffered whole', async () => {
	// Exercises the DEFAULT fetch implementation's own bound via a real streamed Response body,
	// not the injected json() shortcut other tests use (an injected fetchDidWebDocument is
	// responsible for its own bound - see the module doc comment).
	const did = 'did:web:example.com';
	const hugeBody = JSON.stringify({ id: did, verificationMethod: [], padding: 'x'.repeat(1000) });
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async () => new Response(hugeBody, { status: 200 });
	try {
		const retrieve = createRetrievePublicKey({ didWebMaxResponseBytes: 10 });
		await assert.rejects(() => retrieve(`${did}#key-1`));
	} finally {
		globalThis.fetch = originalFetch;
	}
});
