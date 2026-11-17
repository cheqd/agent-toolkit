// Real TS<->Python wire-level conformance for the AP2 open-mandate SD-JWT-VC + Key Binding JWT
// presentation - the same kind of gap D18 closed for A2A (a real cross-language round trip, not
// just each side's own round trip), but for AP2: has anyone ever proven that `@sd-jwt/core` (TS)
// and the `sd-jwt` PyPI package (Python, decision D11's stand-in for `@sd-jwt/core`) actually
// produce and accept the same compact SD-JWT-VC + KB-JWT wire format? Until this script, no.
//
// Two modes, each a half of one of the two cross-language directions. The counterpart Python
// script is python/packages/ap2/conformance_cross_language.py - same two modes, same shapes,
// the same fixed CLOSED_PAYMENT content so both sides compute the same transaction_data hash.
//
//   mint   - acts as a real TS issuer+holder: issues an OpenPaymentMandate SD-JWT-VC with
//            @sd-jwt/core's own SDJwtInstance.issue, then presents it with a real Ed25519 Key
//            Binding JWT bound to transactionDataHash(CLOSED_PAYMENT), via SDJwtInstance.present
//            - the exact wire compact-serialization form a real TS issuer/holder produces.
//            Prints { token, issuerPublicJwk, holderPublicJwk, aud, nonce } to stdout.
//   verify - acts as a real TS verifier: reads that JSON from stdin (either this script's own
//            mint output, or the Python script's), calls the real
//            verifyOpenPaymentMandatePresentation + verifyTransactionDataBinding against
//            CLOSED_PAYMENT. Prints { ok: true, cnfJwk } and exits 0 on success; prints
//            { ok: false, error } to stderr and exits 1 otherwise.
//
// Run from the repository root so `@sd-jwt/core` resolves via node_modules and
// `../packages/ap2/dist/index.js` is built (`npm run build` first).
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { SDJwtInstance } from '@sd-jwt/core';
import {
	sha256Hasher,
	verifyOpenPaymentMandatePresentation,
	verifyTransactionDataBinding,
	transactionDataHash,
} from '../packages/ap2/dist/index.js';

const AUD = 'did:web:merchant.example';
const NONCE = 'cross-language-conformance-nonce';

// Shared with python/packages/ap2/conformance_cross_language.py's CLOSED_PAYMENT, byte for byte
// (both sides json.dumps/JSON.stringify this exact object to compute the same transaction_data
// hash) - a real divergence in key order or number formatting between the two languages would
// show up here as a hash mismatch, which is exactly the kind of thing worth proving doesn't happen.
const CLOSED_PAYMENT = {
	vct: 'mandate.payment.1',
	transaction_id: 'tx-1',
	payee: { id: 'm1', name: 'Acme' },
	payment_amount: { amount: 1999, currency: 'USD' },
	payment_instrument: { id: 'card-1', type: 'card' },
};

async function readStdin() {
	const chunks = [];
	for await (const chunk of process.stdin) chunks.push(chunk);
	return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function ed25519Keypair() {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const jwk = publicKey.export({ format: 'jwk' });
	return { publicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, privateKey };
}

function signer(privateKey) {
	return (data) => cryptoSign(null, Buffer.from(data, 'utf8'), privateKey).toString('base64url');
}

async function mint() {
	const issuer = ed25519Keypair();
	const holder = ed25519Keypair();

	const issuerInstance = new SDJwtInstance({
		hasher: sha256Hasher,
		saltGenerator: (length) => Buffer.from(crypto.getRandomValues(new Uint8Array(length))).toString('base64url'),
		signer: signer(issuer.privateKey),
		signAlg: 'EdDSA',
	});
	const issued = await issuerInstance.issue({
		vct: 'mandate.payment.open.1',
		constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 5000 }],
		cnf: { jwk: holder.publicJwk },
	});

	const presenterInstance = new SDJwtInstance({
		hasher: sha256Hasher,
		saltGenerator: (length) => Buffer.from(crypto.getRandomValues(new Uint8Array(length))).toString('base64url'),
		kbSigner: signer(holder.privateKey),
		kbSignAlg: 'EdDSA',
	});
	const token = await presenterInstance.present(issued, undefined, {
		kb: {
			payload: {
				iat: Math.floor(Date.now() / 1000),
				aud: AUD,
				nonce: NONCE,
				transaction_data: [transactionDataHash(CLOSED_PAYMENT)],
			},
		},
	});

	process.stdout.write(
		JSON.stringify({ token, issuerPublicJwk: issuer.publicJwk, holderPublicJwk: holder.publicJwk, aud: AUD, nonce: NONCE }),
	);
}

async function verify() {
	const input = await readStdin();
	try {
		const result = await verifyOpenPaymentMandatePresentation({
			token: input.token,
			issuerPublicJwk: input.issuerPublicJwk,
			expectedAudience: input.aud,
			expectedNonce: input.nonce,
		});
		if (JSON.stringify(result.cnfJwk) !== JSON.stringify(input.holderPublicJwk)) {
			throw new Error('cnf_jwk_mismatch: verified cnf.jwk does not match the minting script\'s holder key');
		}
		if (!verifyTransactionDataBinding(result.keyBinding, CLOSED_PAYMENT)) {
			throw new Error('transaction_data_binding_failed');
		}
		process.stdout.write(JSON.stringify({ ok: true, cnfJwk: result.cnfJwk }));
	} catch (error) {
		process.stderr.write(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
		process.exit(1);
	}
}

const mode = process.argv[2];
if (mode === 'mint') await mint();
else if (mode === 'verify') await verify();
else {
	process.stderr.write('usage: node cross-language-ap2-sd-jwt.mjs <mint|verify>\n');
	process.exit(2);
}
