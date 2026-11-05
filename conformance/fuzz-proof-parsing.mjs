// Fuzzing over proof/covered-request/mandate parsing (WS6's "focused fuzzing over proof
// parsers" deliverable). Feeds structurally-malformed, type-confused and adversarial input into
// every untrusted-input entry point this programme owns, and asserts the ONE property that
// matters for all of them: fail closed, never throw past the function's own documented
// boundary, never hang. A deterministic seed (default: current date) makes a failure
// reproducible - re-run with FUZZ_SEED=<n> to replay exactly.
//
// Run after `npm run build`: node conformance/fuzz-proof-parsing.mjs
//
// SPDX-License-Identifier: Apache-2.0
import { coveredRequest, createVerifyingUserBuilder, createVerifyingGrpcUserBuilder } from '@cheqd/agent-identity-a2a';
import { CheckoutMandateChain, verifyOpenPaymentMandatePresentation, verifyTransactionDataBinding } from '@cheqd/agent-identity-ap2';
import { verifyEddsaJcs2022, createCheqdStatusChecker } from '@cheqd/agent-identity';

const SEED = Number(process.env.FUZZ_SEED ?? new Date().toISOString().slice(0, 10).replaceAll('-', ''));
const ITERATIONS = Number(process.env.FUZZ_ITERATIONS ?? 300);
const PER_CALL_TIMEOUT_MS = 500;

// mulberry32 - small, deterministic, good enough for adversarial-shape generation (not for
// anything cryptographic).
function mulberry32(seed) {
	let a = seed >>> 0;
	return function next() {
		a |= 0;
		a = (a + 0x6d2b79f5) | 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}
const rng = mulberry32(SEED);
const pick = (arr) => arr[Math.floor(rng() * arr.length)];
const int = (max) => Math.floor(rng() * max);

// Every target here receives its input after JSON decoding (express.json(), a protobuf-to-JSON
// mapping, or JSON.parse) - so the realistic adversarial space is JSON-safe values, not
// arbitrary JS values. Symbols, functions and BigInts can never arrive on the wire; including
// them just produces noise (structuredClone/JSON.stringify reject them for reasons that have
// nothing to do with this programme's own parsing logic). `undefined` is kept: it is what a
// missing JSON key decodes to when read through plain property access.
const SCALARS = [undefined, null, true, false, 0, -1, NaN, Infinity, '', 'x', '__proto__', 'constructor', '🜁', 'a'.repeat(5000), {}, []];

function randomScalar() {
	return pick(SCALARS);
}

function randomValue(depth = 0) {
	if (depth > 4 || rng() < 0.4) return randomScalar();
	const shape = pick(['object', 'array', 'string-looks-like-json', 'nested-prototype']);
	if (shape === 'array') return Array.from({ length: int(6) }, () => randomValue(depth + 1));
	if (shape === 'string-looks-like-json') return pick(['{', '{}', '[1,2', 'null', '"unterminated', '{"a":}', JSON.stringify(randomScalar())]);
	if (shape === 'nested-prototype') return { __proto__: { polluted: true }, constructor: { prototype: {} }, [randomKey()]: randomValue(depth + 1) };
	const obj = {};
	for (let i = 0; i < int(5); i++) obj[randomKey()] = randomValue(depth + 1);
	return obj;
}
function randomKey() {
	return pick(['method', 'params', 'message', 'metadata', 'id', 'kid', 'did', 'proof', 'cnf', 'jwk', 'vct', '__proto__', 'toString', randomString()]);
}
function randomString(max = 40) {
	const len = int(max);
	let s = '';
	for (let i = 0; i < len; i++) s += String.fromCharCode(int(0x10ffff));
	return s;
}

let failures = 0;
let ran = 0;

async function withTimeout(promise, label) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(`${label}: exceeded ${PER_CALL_TIMEOUT_MS}ms - treated as a hang`)), PER_CALL_TIMEOUT_MS);
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

/** Runs `fn(input)`, which MUST resolve/return without throwing for any input (the function's
 * own documented fail-closed contract) - a thrown error or a hang is the finding. */
async function fuzzNeverThrows(label, fn, input) {
	ran++;
	try {
		await withTimeout(Promise.resolve().then(() => fn(input)), label);
	} catch (error) {
		failures++;
		console.log(`FAIL ${label}: threw/hung on input ${truncate(input)}`);
		console.log(`  seed=${SEED} error=${error instanceof Error ? error.message : String(error)}`);
	}
}

/** Runs `fn(input)` which MAY throw/reject (it's a "verify or throw" API), but MUST do so
 * promptly - a hang is still a finding, a throw is not. */
async function fuzzMayThrowButNeverHangs(label, fn, input) {
	ran++;
	try {
		await withTimeout(
			Promise.resolve()
				.then(() => fn(input))
				.catch(() => undefined),
			label,
		);
	} catch (error) {
		failures++;
		console.log(`FAIL ${label}: hung on input ${truncate(input)}`);
		console.log(`  seed=${SEED} error=${error instanceof Error ? error.message : String(error)}`);
	}
}

function truncate(value) {
	const s = JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), undefined, 0) ?? String(value);
	return s.length > 200 ? `${s.slice(0, 200)}…` : s;
}

const resolveDidDocument = async () => null;
const resolveDidCheqd = async () => null;
const resolveKey = () => {
	throw new Error('no such kid');
};
const resolveDidKeys = () => [];
const nonceCache = new Map();
const deps = { resolveKey, resolveDidKeys, expectedAudience: 'did:web:server.example', consumeNonceIfFresh: async (n) => (nonceCache.has(n) ? false : (nonceCache.set(n, true), true)) };
const userBuilder = createVerifyingUserBuilder(deps);
const grpcUserBuilder = createVerifyingGrpcUserBuilder(deps);
const statusChecker = createCheqdStatusChecker({ resolveDidCheqd, fetch: async () => ({ ok: false, status: 404, async json() { return {}; } }) });

for (let i = 0; i < ITERATIONS; i++) {
	const garbage = randomValue();
	await fuzzNeverThrows('coveredRequest', (v) => coveredRequest(pick(['SendMessage', 'SendStreamingMessage', randomString(10)]), v), garbage);
	await fuzzNeverThrows('userBuilder (JSON-RPC/REST)', (v) => userBuilder(v), garbage);
	await fuzzNeverThrows('grpcUserBuilder', (v) => grpcUserBuilder(v), garbage);
	await fuzzNeverThrows('verifyEddsaJcs2022', (v) => verifyEddsaJcs2022(v, resolveDidDocument), garbage);
	await fuzzNeverThrows('statusChecker (BitstringRevocationChecker)', (v) => statusChecker(v), garbage);
	await fuzzNeverThrows('CheckoutMandateChain.verify', (v) => {
		const chain = CheckoutMandateChain.parse([{ vct: 'mandate.checkout.open.1', constraints: [], cnf: { jwk: {} } }, { vct: 'mandate.checkout.1', checkout_jwt: typeof v === 'string' ? v : 'not-a-string', checkout_hash: 'x' }]);
		return chain.verify(typeof v === 'string' ? v : 'not-a-string');
	}, garbage);
	await fuzzNeverThrows('verifyTransactionDataBinding', (v) => verifyTransactionDataBinding({ aud: 'x', nonce: 'y', iat: 0, transaction_data: Array.isArray(v) ? v : undefined }, v), garbage);
	await fuzzMayThrowButNeverHangs('verifyOpenPaymentMandatePresentation', (v) =>
		verifyOpenPaymentMandatePresentation({ token: typeof v === 'string' ? v : randomString(80), issuerPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }, expectedAudience: 'did:web:x', expectedNonce: 'n' }),
	garbage);
}

// A handful of specifically prototype-pollution-shaped inputs, beyond what the random generator
// happens to produce, since this is a named, well-known attack class worth checking directly.
const pollutionShapes = [
	JSON.parse('{"__proto__":{"polluted":true}}'),
	JSON.parse('{"constructor":{"prototype":{"polluted":true}}}'),
	{ message: { metadata: { __proto__: { polluted: true } } } },
];
for (const shape of pollutionShapes) {
	await fuzzNeverThrows('coveredRequest (prototype pollution)', (v) => coveredRequest('SendMessage', v), shape);
	await fuzzNeverThrows('userBuilder (prototype pollution)', (v) => userBuilder({ body: v }), shape);
}
if (Object.prototype.polluted === true) {
	failures++;
	console.log('FAIL: Object.prototype was polluted by one of the fuzz inputs above');
}

console.log(`\n${ran} fuzz calls across ${ITERATIONS} iterations (seed=${SEED}), ${failures} failures.`);
if (failures > 0) process.exit(1);
