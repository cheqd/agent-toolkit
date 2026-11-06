// Smoke test: @cheqd/agent-identity's createRetrievePublicKey wired into @a2a-js/sdk's real
// verifyAgentCardSignature/generateAgentCardSignature - the same scenarios as
// evidence/spikes/spike-card-signature.mjs, now against the production resolver instead of an
// inline stub, over both did:key (pure computation) and did:web (a fake fetch, no network).
import { generateAgentCardSignature, verifyAgentCardSignature } from '@a2a-js/sdk';
import { generateKeyPairSync } from 'node:crypto';
import { createRetrievePublicKey } from '../core/dist/index.js';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  if (bytes.length === 0) return '';
  let num = 0n;
  for (const byte of bytes) num = num * 256n + BigInt(byte);
  let out = '';
  while (num > 0n) { out = BASE58_ALPHABET[Number(num % 58n)] + out; num /= 58n; }
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out;
  return out;
}
function multibaseFor(raw) {
  const prefixed = new Uint8Array(2 + raw.length);
  prefixed[0] = 0xed; prefixed[1] = 0x01; prefixed.set(raw, 2);
  return `z${base58Encode(prefixed)}`;
}

const agentCard = (url) => ({
  name: 'Agent card key resolver smoke test', description: 'x', version: '1.0.0', provider: undefined, documentationUrl: '',
  supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: '1.0' }],
  capabilities: { extensions: [], streaming: true, pushNotifications: false },
  securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
  skills: [{ id: 's', name: 's', description: 's', tags: [], examples: [], inputModes: ['text/plain'], outputModes: ['text/plain'], securityRequirements: [] }],
  signatures: [],
});

const line = (s) => console.log(s);
const attempt = async (label, verify, card) => {
  try { await verify(card); line(`${label}: ACCEPTED`); }
  catch (e) { line(`${label}: rejected (${e.message.slice(0, 80)})`); }
};

// --- did:key ---------------------------------------------------------------------------------
{
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const did = `did:key:${multibaseFor(Buffer.from(jwk.x, 'base64url'))}`;
  const kid = `${did}#${multibaseFor(Buffer.from(jwk.x, 'base64url'))}`;

  const sign = generateAgentCardSignature(privateKey, { alg: 'EdDSA', kid, typ: 'JOSE' });
  const retrieve = createRetrievePublicKey({ expectedDid: did });
  const verify = verifyAgentCardSignature(retrieve);
  const card = agentCard('https://agent.example/a2a');

  await attempt('did:key, signed by the right key', verify, await sign(card));
  await attempt('did:key, attacker jku header (never read)', verify, await sign(card, { jku: 'https://attacker.example/jwks.json' }));
  await attempt('did:key, card tampered after signing', verify, { ...(await sign(card)), name: 'Evil agent' });

  const { privateKey: otherKey } = generateKeyPairSync('ed25519');
  const forged = generateAgentCardSignature(otherKey, { alg: 'EdDSA', kid, typ: 'JOSE' });
  await attempt('did:key, signed by a DIFFERENT key claiming this kid', verify, await forged(card));
}

// --- did:web, real @a2a-js/sdk verification, fake fetch (no network) --------------------------
{
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const did = 'did:web:agent.example';
  const kid = `${did}#key-1`;

  const sign = generateAgentCardSignature(privateKey, { alg: 'EdDSA', kid, typ: 'JOSE' });
  let fetched = 0;
  const fetchDidWebDocument = async (url) => {
    fetched++;
    return { status: 200, async json() {
      return { id: did, verificationMethod: [{ id: kid, controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } }] };
    } };
  };
  const retrieve = createRetrievePublicKey({ expectedDid: did, fetchDidWebDocument });
  const verify = verifyAgentCardSignature(retrieve);
  const card = agentCard('https://agent.example/a2a');

  await attempt('did:web, signed by the right key', verify, await sign(card));
  line(`did:web fetches made: ${fetched} (document fetched by this module, no live network call)`);

  const { privateKey: otherKey } = generateKeyPairSync('ed25519');
  const wrongDid = 'did:web:attacker.example';
  const retrieveWrongExpectation = createRetrievePublicKey({ expectedDid: wrongDid, fetchDidWebDocument });
  await attempt('did:web, expectedDid pinned to a different DID than the kid', verifyAgentCardSignature(retrieveWrongExpectation), await sign(card));
}
