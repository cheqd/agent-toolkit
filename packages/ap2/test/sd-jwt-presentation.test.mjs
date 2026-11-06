// SPDX-License-Identifier: Apache-2.0
// End-to-end test: mint a REAL OpenPaymentMandate SD-JWT-VC with @sd-jwt/core's own issuance
// API, present it with a real Key Binding JWT (Ed25519, transaction_data bound to a specific
// closed PaymentMandate), and verify the whole thing through verifyOpenPaymentMandatePresentation
// + verifyTransactionDataBinding - exercising the real library end to end, not a stub.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { SDJwtInstance } from '@sd-jwt/core';
import {
	sha256Hasher,
	jwkVerifier,
	verifyOpenPaymentMandatePresentation,
	verifyTransactionDataBinding,
	transactionDataHash,
} from '../dist/index.js';

function ed25519Keypair() {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const jwk = publicKey.export({ format: 'jwk' });
	return { publicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, privateKey };
}

function signer(privateKey) {
	return (data) => cryptoSign(null, Buffer.from(data, 'utf8'), privateKey).toString('base64url');
}

const CLOSED_PAYMENT = {
	vct: 'mandate.payment.1',
	transaction_id: 'tx-1',
	payee: { id: 'm1', name: 'Acme' },
	payment_amount: { amount: 1999, currency: 'USD' },
	payment_instrument: { id: 'card-1', type: 'card' },
};

async function buildPresentation({ issuer, holder, aud, nonce }) {
	const issuerInstance = new SDJwtInstance({
		hasher: sha256Hasher,
		saltGenerator: (length) => Buffer.from(crypto.getRandomValues(new Uint8Array(length))).toString('base64url'),
		signer: signer(issuer.privateKey),
		signAlg: 'EdDSA',
	});
	const openMandatePayload = {
		vct: 'mandate.payment.open.1',
		constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 5000 }],
		cnf: { jwk: holder.publicJwk },
	};
	const issued = await issuerInstance.issue(openMandatePayload);

	const presenterInstance = new SDJwtInstance({
		hasher: sha256Hasher,
		saltGenerator: (length) => Buffer.from(crypto.getRandomValues(new Uint8Array(length))).toString('base64url'),
		kbSigner: signer(holder.privateKey),
		kbSignAlg: 'EdDSA',
	});
	return presenterInstance.present(issued, undefined, {
		kb: { payload: { iat: Math.floor(Date.now() / 1000), aud, nonce, transaction_data: [transactionDataHash(CLOSED_PAYMENT)] } },
	});
}

test('a real SD-JWT-VC + KB-JWT presentation verifies end to end', async () => {
	const issuer = ed25519Keypair();
	const holder = ed25519Keypair();
	const token = await buildPresentation({ issuer, holder, aud: 'did:web:merchant.example', nonce: 'n-123' });

	const result = await verifyOpenPaymentMandatePresentation({
		token,
		issuerPublicJwk: issuer.publicJwk,
		expectedAudience: 'did:web:merchant.example',
		expectedNonce: 'n-123',
	});

	assert.equal(result.payload.vct, 'mandate.payment.open.1');
	assert.deepEqual(result.cnfJwk, holder.publicJwk);
	assert.equal(verifyTransactionDataBinding(result.keyBinding, CLOSED_PAYMENT), true);
});

test('a presentation bound to the wrong transaction is rejected by the binding check', async () => {
	const issuer = ed25519Keypair();
	const holder = ed25519Keypair();
	const token = await buildPresentation({ issuer, holder, aud: 'did:web:merchant.example', nonce: 'n-456' });

	const result = await verifyOpenPaymentMandatePresentation({
		token,
		issuerPublicJwk: issuer.publicJwk,
		expectedAudience: 'did:web:merchant.example',
		expectedNonce: 'n-456',
	});

	const differentPayment = { ...CLOSED_PAYMENT, transaction_id: 'tx-DIFFERENT' };
	assert.equal(verifyTransactionDataBinding(result.keyBinding, differentPayment), false);
});

test('a presentation signed by the wrong holder key fails verification', async () => {
	const issuer = ed25519Keypair();
	const holder = ed25519Keypair();
	const impostor = ed25519Keypair();

	// Issue the open mandate bound to `holder`'s key, but sign the KB-JWT with `impostor`'s key.
	const issuerInstance = new SDJwtInstance({
		hasher: sha256Hasher,
		saltGenerator: (length) => Buffer.from(crypto.getRandomValues(new Uint8Array(length))).toString('base64url'),
		signer: signer(issuer.privateKey),
		signAlg: 'EdDSA',
	});
	const issued = await issuerInstance.issue({
		vct: 'mandate.payment.open.1',
		constraints: [],
		cnf: { jwk: holder.publicJwk },
	});
	const presenterInstance = new SDJwtInstance({
		hasher: sha256Hasher,
		saltGenerator: (length) => Buffer.from(crypto.getRandomValues(new Uint8Array(length))).toString('base64url'),
		kbSigner: signer(impostor.privateKey),
		kbSignAlg: 'EdDSA',
	});
	const token = await presenterInstance.present(issued, undefined, {
		kb: { payload: { iat: Math.floor(Date.now() / 1000), aud: 'did:web:merchant.example', nonce: 'n-789' } },
	});

	await assert.rejects(() =>
		verifyOpenPaymentMandatePresentation({
			token,
			issuerPublicJwk: issuer.publicJwk,
			expectedAudience: 'did:web:merchant.example',
			expectedNonce: 'n-789',
		}),
	);
});

test('jwkVerifier rejects a tampered issuer-signed payload', async () => {
	const issuer = ed25519Keypair();
	const verify = jwkVerifier(issuer.publicJwk);
	const data = 'header.payload';
	const sig = signer(issuer.privateKey)(data);
	assert.equal(await verify(data, sig), true);
	assert.equal(await verify('header.TAMPERED', sig), false);
});
