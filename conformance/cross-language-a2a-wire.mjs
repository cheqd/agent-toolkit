// Real TS<->Python wire-level conformance for the A2A SendMessage request proof - the one gap
// docs/design-decisions.md D15's "Revisit-if" left open: whether gate.py/client.py's dict-based
// design, once wired to the real a2a-sdk via proto_bridge.py, actually survives a real
// TypeScript-client-to-Python-server (or reverse) wire round trip, not just a Python-proto-to-
// Python-gate one (which test_proto_bridge.py already covers).
//
// Two modes, each a half of one of the two cross-language directions. The counterpart Python
// script is python/packages/a2a/conformance_cross_language.py - same two modes, same shapes.
//
//   mint   - acts as a real TS client (client.ts's own code path, unmodified): mints a request
//            proof with @kya-os/mcp's real ed25519SignerFromJwk + createProofInterceptor, then
//            serializes the final request through @a2a-js/sdk's real SendMessageRequest.toJSON
//            - the exact wire JSON a real TS client sends. Prints { wire, clientDid, clientKid,
//            clientPublicJwk, serverDid } to stdout.
//   verify - acts as a real TS server (user-builder.ts's own code path, unmodified): reads that
//            JSON from stdin (either this script's own mint output, or the Python script's),
//            round-trips it through SendMessageRequest.fromJSON/toJSON (the same proto-shape
//            coercion a real TS dispatcher applies to any incoming wire body - mirroring
//            Python's ParseDict/MessageToDict round trip on its side), then calls the real
//            createVerifyingUserBuilder. Exits 0 and prints the verified DID on success; exits 1
//            otherwise.
//
// Run from the repository root so `@a2a-js/sdk` and `@kya-os/mcp` resolve via node_modules and
// `../packages/a2a/dist/index.js` is built (`npm run build` first).
import { generateKeyPair, exportJWK } from 'jose';
import { SendMessageRequest } from '@a2a-js/sdk';
import { ed25519SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';
import {
	NodeCryptoProvider,
	SystemClockProvider,
	MemoryNonceCacheProvider,
	RuntimeFetchProvider,
} from '@kya-os/mcp/providers';
import { createProofInterceptor, createVerifyingUserBuilder } from '../packages/a2a/dist/index.js';

const CLIENT_DID = 'did:web:client.example';
const CLIENT_KID = `${CLIENT_DID}#key-1`;
const SERVER_DID = 'did:web:server.example';
const EXT_URI = 'https://cheqd.io/a2a/ext/trust/v1';

async function readStdin() {
	const chunks = [];
	for await (const chunk of process.stdin) chunks.push(chunk);
	return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function mint() {
	const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	const priv = await exportJWK(privateKey);
	const pub = { kty: 'OKP', crv: 'Ed25519', x: priv.x };
	const signer = await ed25519SignerFromJwk({ did: CLIENT_DID, kid: CLIENT_KID, privateJwk: priv });

	const { interceptor } = createProofInterceptor({
		signer,
		serverDid: SERVER_DID,
		clientDid: CLIENT_DID,
		// Only before() is exercised here (the request-proof direction); the response-proof
		// check that would need a real server key is covered by smoke-test.mjs/test_proto_bridge.py.
		serverPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'unused', kid: `${SERVER_DID}#key-1` },
		extensionUri: EXT_URI,
		cryptoProvider: new NodeCryptoProvider(),
		clockProvider: new SystemClockProvider(),
		nonceCacheProvider: new MemoryNonceCacheProvider(),
		fetchProvider: new RuntimeFetchProvider(),
	});

	// Build via fromJSON, not a hand-built literal: SendMessageRequest's internal shape stores
	// `Part.content` as a `{ $case, value }` union, not the wire's bare `text` field - exactly
	// the kind of real-SDK-shape detail a hand-rolled stand-in would miss.
	const value = SendMessageRequest.fromJSON({
		message: { parts: [{ text: 'hello from a real TS client' }] },
	});
	const args = {
		input: { method: 'sendMessage', value },
		options: { serviceParameters: {} },
	};
	await interceptor.before(args);
	const wire = SendMessageRequest.toJSON(args.input.value);
	process.stdout.write(
		JSON.stringify({
			wire,
			clientDid: CLIENT_DID,
			clientKid: CLIENT_KID,
			clientPublicJwk: pub,
			serverDid: SERVER_DID,
		}),
	);
}

async function verify() {
	const input = await readStdin();
	const requestProto = SendMessageRequest.fromJSON(input.wire);
	const wire = SendMessageRequest.toJSON(requestProto);

	const nonceCache = new InMemoryNonceCache();
	const userBuilder = createVerifyingUserBuilder({
		resolveKey: async (kid) => {
			if (kid !== input.clientKid) throw new Error(`unexpected kid ${kid}`);
			return input.clientPublicJwk;
		},
		resolveDidKeys: async (did) => (did === input.clientDid ? [input.clientPublicJwk] : []),
		expectedAudience: input.serverDid,
		consumeNonceIfFresh: nonceCache.consume,
	});

	const user = await userBuilder({ body: { method: 'SendMessage', params: wire } });
	if (!user.isAuthenticated || !user.verified) {
		process.stderr.write(JSON.stringify({ ok: false, rejection: user.rejection }));
		process.exit(1);
	}
	process.stdout.write(JSON.stringify({ ok: true, did: user.verified.did }));
}

const mode = process.argv[2];
if (mode === 'mint') await mint();
else if (mode === 'verify') await verify();
else {
	process.stderr.write('usage: node cross-language-a2a-wire.mjs <mint|verify>\n');
	process.exit(2);
}
