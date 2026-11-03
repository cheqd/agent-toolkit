// ES256 support, alg/key-type mismatch rejection (§4.3), and cnf.jkt fusion to L3 vs L3-minus
// (§4.6 steps 6 and 8). Same did:web in-memory setup as slice-both.mjs, but no A2A SDK / HTTP:
// calls buildCardProof / verifyCardProof directly against a fixed covered request, since the
// claim under test is about the proof layer, not wire plumbing (already covered elsewhere).
import { randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK } from 'jose';
import { buildCardProof, verifyCardProof, ed25519SignerFromJwk, es256SignerFromJwk, InMemoryNonceCache } from '@kya-os/mcp/card';

const SERVER_DID = 'did:web:server.example';
const CLIENT_DID = 'did:web:client.example';

async function newEdKey(did) {
  const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const priv = await exportJWK(privateKey);
  return { did, kid: `${did}#key-1`, priv, pub: { kty: 'OKP', crv: 'Ed25519', x: priv.x } };
}
async function newEcKey(did) {
  const { privateKey } = await generateKeyPair('ES256', { crv: 'P-256', extractable: true });
  const priv = await exportJWK(privateKey);
  return { did, kid: `${did}#key-1`, priv, pub: { kty: 'EC', crv: 'P-256', x: priv.x, y: priv.y } };
}

const req = { method: 'SendMessage', params: { message: { messageId: 'm1', parts: [{ text: 'hi' }] } } };
const nonceCache = new InMemoryNonceCache();
let seq = 0;
const freshNonce = () => randomBytes(16).toString('base64url') + (seq++);

async function verify(proof, deps = {}) {
  return verifyCardProof(proof, req, {
    resolveKey: deps.resolveKey, resolveDidKeys: deps.resolveDidKeys,
    expectedAudience: SERVER_DID, consumeNonceIfFresh: nonceCache.consume,
    tokenCnfJkt: deps.tokenCnfJkt,
  });
}

// 1. ES256 end to end: a P-256 client key, resolved as an EC key, verifies.
{
  const client = await newEcKey(CLIENT_DID);
  const signer = await es256SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
  const proofWrap = await buildCardProof(req, signer, { audience: SERVER_DID, nonce: freshNonce() });
  const proof = proofWrap['org.kya-os/request-proof'];
  const resolveKey = (kid) => { if (kid !== client.kid) throw new Error('no such kid'); return client.pub; };
  const resolveDidKeys = (did) => (did === client.did ? [client.pub] : []);
  const r = await verify(proof, { resolveKey, resolveDidKeys });
  console.log(`1. ES256 proof, EC key resolved -> ok=${r.ok} level=${r.level} alg=${proof.alg} reasons=${r.reasons}`);
}

// 2. alg/key mismatch: an ES256-signed proof, but resolveKey returns the client's Ed25519 key
//    instead of its real P-256 key (e.g. a verifier or DID document bug).
{
  const client = await newEcKey(CLIENT_DID);
  const wrongKeyShape = await newEdKey(CLIENT_DID);
  const signer = await es256SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
  const proofWrap = await buildCardProof(req, signer, { audience: SERVER_DID, nonce: freshNonce() });
  const proof = proofWrap['org.kya-os/request-proof'];
  const resolveKey = () => wrongKeyShape.pub; // OKP/Ed25519, not EC/P-256
  const resolveDidKeys = () => [wrongKeyShape.pub];
  const r = await verify(proof, { resolveKey, resolveDidKeys });
  console.log(`2. alg=ES256 but resolved key is Ed25519 -> ok=${r.ok} reasons=${r.reasons}`);
}

// 3. cnf fusion: proof carries cnf.jkt (the signer's own thumbprint). Verifier given the
//    MATCHING token cnf.jkt -> L3. Verifier given no token cnf.jkt -> L3-minus (not fatal).
//    Verifier given a DIFFERENT token cnf.jkt (sender-constraint downgrade attack) -> rejected.
{
  const client = await newEdKey(CLIENT_DID);
  const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
  const resolveKey = () => client.pub;
  const resolveDidKeys = () => [client.pub];

  const proofWrap1 = await buildCardProof(req, signer, { audience: SERVER_DID, nonce: freshNonce() });
  const proof1 = proofWrap1['org.kya-os/request-proof'];
  const matchingTokenJkt = proof1.cnf?.jkt;
  const r1 = await verify(proof1, { resolveKey, resolveDidKeys, tokenCnfJkt: matchingTokenJkt });
  console.log(`3a. cnf present, token cnf.jkt matches -> ok=${r1.ok} level=${r1.level} warnings=${r1.warnings ?? []}`);

  const proofWrap2 = await buildCardProof(req, signer, { audience: SERVER_DID, nonce: freshNonce() });
  const proof2 = proofWrap2['org.kya-os/request-proof'];
  const r2 = await verify(proof2, { resolveKey, resolveDidKeys }); // no tokenCnfJkt given
  console.log(`3b. cnf present, verifier given no token cnf.jkt -> ok=${r2.ok} level=${r2.level} warnings=${r2.warnings ?? []}`);

  const proofWrap3 = await buildCardProof(req, signer, { audience: SERVER_DID, nonce: freshNonce() });
  const proof3 = proofWrap3['org.kya-os/request-proof'];
  const r3 = await verify(proof3, { resolveKey, resolveDidKeys, tokenCnfJkt: 'not-the-real-thumbprint' });
  console.log(`3c. cnf present, token cnf.jkt DIFFERS (downgrade attempt) -> ok=${r3.ok} reasons=${r3.reasons}`);
}

// 4. explicit cnf.jkt override at mint time (ctx.cnfJkt), e.g. binding to an RFC 9449 DPoP
//    token's thumbprint rather than the signer's own key.
{
  const client = await newEdKey(CLIENT_DID);
  const signer = await ed25519SignerFromJwk({ did: client.did, kid: client.kid, privateJwk: client.priv });
  const resolveKey = () => client.pub;
  const resolveDidKeys = () => [client.pub];
  const dpopJkt = 'dpop-token-thumbprint-abc';
  const proofWrap = await buildCardProof(req, signer, { audience: SERVER_DID, nonce: freshNonce(), cnfJkt: dpopJkt });
  const proof = proofWrap['org.kya-os/request-proof'];
  const r = await verify(proof, { resolveKey, resolveDidKeys, tokenCnfJkt: dpopJkt });
  console.log(`4. explicit cnf.jkt override (DPoP-style) -> cnf.jkt==signer.jkt? ${proof.cnf?.jkt === dpopJkt}; ok=${r.ok} level=${r.level} reasons=${r.reasons}`);
}
