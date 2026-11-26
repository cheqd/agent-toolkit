// SPDX-License-Identifier: Apache-2.0
// signAgentCard, both key paths (in-process private JWK, external signer), verified by
// @a2a-js/sdk's own verifyAgentCardSignature with @cheqd/agent-identity's DID key resolution.
// Covers the scenarios of the agent-card tests that lived in the cheqd/credo-ts fork's
// packages/cheqd (removed from there), plus the deactivated-DID rejection added to that fork's
// verifier in credo-ts#50.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { verifyAgentCardSignature } from '@a2a-js/sdk';
import { createDidCheqdResolver, createRetrievePublicKey } from '@cheqd/agent-identity';
import { signAgentCard } from '../dist/index.js';

const DID = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
const OTHER_DID = 'did:cheqd:testnet:5a1e7c0d-3b2f-4e8a-9c6d-1f0e2d3c4b5a';

const card = (name = 'Agent card signing test') => ({
	name,
	description: 'An agent whose card is signed with a DID key',
	version: '1.0.0',
	supportedInterfaces: [
		{ url: 'https://agent.example.com/a2a', protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' },
	],
	capabilities: { extensions: [], streaming: false, pushNotifications: false },
	securitySchemes: {},
	securityRequirements: [],
	defaultInputModes: ['text/plain'],
	defaultOutputModes: ['text/plain'],
	skills: [],
	signatures: [],
});

const decodeHeader = (signature) =>
	JSON.parse(Buffer.from(signature.protected, 'base64url').toString('utf8'));

/** A key pair for `curve`, exported as JWKs, plus an external signer over the same private key. */
function keyPair(curve) {
	const { privateKey, publicKey } =
		curve === 'Ed25519' ? generateKeyPairSync('ed25519') : generateKeyPairSync('ec', { namedCurve: 'P-256' });
	const alg = curve === 'Ed25519' ? 'EdDSA' : 'ES256';
	return {
		alg,
		privateJwk: privateKey.export({ format: 'jwk' }),
		publicJwk: publicKey.export({ format: 'jwk' }),
		// The JOSE form: raw r||s for ES256 (ieee-p1363), not DER - what a KMS signer must return
		signer: {
			alg,
			sign: async (data) =>
				new Uint8Array(
					curve === 'Ed25519'
						? nodeSign(null, data, privateKey)
						: nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }),
				),
		},
	};
}

/** A did:cheqd resolver over fixed documents, through the real createDidCheqdResolver. */
function resolverFor(documents, metadata = {}) {
	return createDidCheqdResolver({
		resolverUrl: 'https://resolver.test/1.0/identifiers',
		fetch: async (url) => {
			const did = url.slice(url.lastIndexOf('/') + 1);
			const didDocument = documents[did];
			return didDocument
				? { status: 200, json: async () => ({ didDocument, didDocumentMetadata: metadata[did] ?? {} }) }
				: { status: 404, json: async () => ({}) };
		},
	});
}

const documentFor = (did, publicJwk) => ({
	id: did,
	verificationMethod: [
		{ id: `${did}#key-1`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicJwk },
	],
});

const verifierFor = (documents, options = {}) =>
	verifyAgentCardSignature(
		createRetrievePublicKey({
			resolveDidCheqd: resolverFor(documents, options.metadata),
			expectedDid: options.expectedDid,
		}),
	);

for (const curve of ['Ed25519', 'P-256']) {
	for (const path of ['privateJwk', 'signer']) {
		test(`${curve}, ${path}: signs with the key's algorithm and the DID URL as kid, verified by the A2A SDK`, async () => {
			const keys = keyPair(curve);
			const signed = await signAgentCard(card(), { did: DID, kid: '#key-1', [path]: keys[path] });

			assert.equal(signed.signatures.length, 1);
			assert.deepEqual(decodeHeader(signed.signatures[0]), {
				alg: keys.alg,
				kid: `${DID}#key-1`,
				typ: 'JWT',
			});
			await verifierFor({ [DID]: documentFor(DID, keys.publicJwk) }, { expectedDid: DID })(signed);
		});

		test(`${curve}, ${path}: a card changed after signing is rejected`, async () => {
			const keys = keyPair(curve);
			const signed = await signAgentCard(card(), { did: DID, kid: '#key-1', [path]: keys[path] });
			const changed = { ...signed, name: 'Evil agent' };
			await assert.rejects(
				verifierFor({ [DID]: documentFor(DID, keys.publicJwk) })(changed),
				/No valid signatures/,
			);
		});
	}
}

test('both paths build the same JWS: Ed25519 is deterministic, so the signatures are byte-identical', async () => {
	const keys = keyPair('Ed25519');
	const viaSdk = await signAgentCard(card(), { did: DID, kid: '#key-1', privateJwk: keys.privateJwk });
	const viaSigner = await signAgentCard(card(), { did: DID, kid: '#key-1', signer: keys.signer });
	assert.equal(viaSigner.signatures[0].protected, viaSdk.signatures[0].protected);
	assert.equal(viaSigner.signatures[0].signature, viaSdk.signatures[0].signature);
});

test('an ES256 signer that returns DER is refused, rather than producing a card nobody can verify', async () => {
	const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
	const derSigner = {
		alg: 'ES256',
		sign: async (data) => new Uint8Array(nodeSign('sha256', data, privateKey)),
	};
	await assert.rejects(
		signAgentCard(card(), { did: DID, kid: '#key-1', signer: derSigner }),
		/must be 64 bytes \(raw r\|\|s for ES256, not DER\)/,
	);
});

test('an unsupported signer algorithm is refused', async () => {
	await assert.rejects(
		signAgentCard(card(), {
			did: DID,
			kid: '#key-1',
			signer: { alg: 'RS256', sign: async () => new Uint8Array(64) },
		}),
		/unsupported agent card signing algorithm/,
	);
});

test('existing signatures are kept', async () => {
	const first = keyPair('P-256');
	const second = keyPair('Ed25519');
	const once = await signAgentCard(card(), { did: DID, kid: '#key-1', signer: first.signer });
	const twice = await signAgentCard(once, { did: OTHER_DID, kid: '#key-1', signer: second.signer });
	assert.equal(twice.signatures.length, 2);
	assert.equal(twice.signatures[0].signature, once.signatures[0].signature);
});

test("a signature re-labelled with another DID's kid is rejected (by expectedDid, and by the other DID's key)", async () => {
	const signerKeys = keyPair('P-256');
	const otherKeys = keyPair('P-256');
	const signed = await signAgentCard(card(), { did: DID, kid: '#key-1', signer: signerKeys.signer });
	const header = decodeHeader(signed.signatures[0]);
	const relabelled = {
		...signed,
		signatures: [
			{
				...signed.signatures[0],
				protected: Buffer.from(JSON.stringify({ ...header, kid: `${OTHER_DID}#key-1` })).toString(
					'base64url',
				),
			},
		],
	};
	const documents = {
		[DID]: documentFor(DID, signerKeys.publicJwk),
		[OTHER_DID]: documentFor(OTHER_DID, otherKeys.publicJwk),
	};
	await assert.rejects(verifierFor(documents, { expectedDid: DID })(relabelled), /No valid signatures/);
	await assert.rejects(verifierFor(documents)(relabelled), /No valid signatures/);
});

test('a card signed by a key of a DID that has since been deactivated is rejected', async () => {
	const keys = keyPair('P-256');
	const signed = await signAgentCard(card(), { did: DID, kid: '#key-1', signer: keys.signer });
	const documents = { [DID]: documentFor(DID, keys.publicJwk) };
	await verifierFor(documents, { expectedDid: DID })(signed);
	await assert.rejects(
		verifierFor(documents, { expectedDid: DID, metadata: { [DID]: { deactivated: true } } })(signed),
		/No valid signatures/,
	);
});
