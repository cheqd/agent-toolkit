// Prototype for did-provider-cheqd#657: an independent `DataIntegrityProof` / `eddsa-jcs-2022`
// signer, built by reading @kya-os/mcp's VERIFIER (status-list-proof.js) rather than any signer
// it ships (it ships none for this suite — the issue's "needs custom code" claim stands). Proves
// an issuer who signs this way interoperates with KYA-OS's ready `createStatusListProofVerifier`,
// using real `encodedList` bits pulled from the live testnet resource probed in probe.sh. Uses a
// TEST key, not cheqd's real issuer key — this is a proof-of-concept, not a deployment.
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { createStatusListProofVerifier, createRevocationChecker } from '@kya-os/mcp/card';

const RESOLVER = 'https://resolver.cheqd.net/1.0/identifiers';
const DID = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
const KID = `${DID}#key-1`;

// --- the signer: mirrors status-list-proof.js's verification algorithm exactly ------------------
function sha256(bytes) {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  if (bytes.length === 0) return '';
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = '';
  while (num > 0n) { out = BASE58_ALPHABET[Number(num % 58n)] + out; num /= 58n; }
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out;
  return out;
}
function signEddsaJcs2022(document, { kid, privateKey }) {
  const proofOptions = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: new Date().toISOString(), verificationMethod: kid, proofPurpose: 'assertionMethod' };
  const unsecured = { ...document };
  delete unsecured.proof;
  const options = { ...proofOptions };
  // Mirror the verifier exactly: when the proof carries no @context of its own, the document's
  // @context is folded into `options` before hashing (status-list-proof.js's `startsWith` branch).
  if (unsecured['@context'] !== undefined) options['@context'] = unsecured['@context'];
  const encoder = new TextEncoder();
  const proofHash = sha256(encoder.encode(canonicalize(options)));
  const documentHash = sha256(encoder.encode(canonicalize(unsecured)));
  const hashData = new Uint8Array(proofHash.length + documentHash.length);
  hashData.set(proofHash, 0);
  hashData.set(documentHash, proofHash.length);
  const signature = cryptoSign(null, hashData, privateKey); // Ed25519: no separate digest algorithm
  return { ...document, proof: { ...proofOptions, proofValue: `z${base58Encode(signature)}` } };
}

// --- a test issuer key (NOT cheqd's real key) and a fake DID resolver serving it -----------------
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyJwk = publicKey.export({ format: 'jwk' });
const didResolver = { async resolve(did) {
  if (did !== DID) return null;
  return { id: DID, verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: DID, publicKeyJwk }] };
} };

const line = (s) => console.log(s);

// --- pull real encodedList bits from the live testnet resource, wrap as a proper VC -------------
const base = `${RESOLVER}/${DID}?resourceName=cheqd-employee-credentials-unencrypted&resourceType=StatusList2021Revocation`;
const raw = await (await fetch(base)).json();
const encodedList = raw.StatusList2021.encodedList;
line(`fetched real encodedList (${encodedList.length} chars) from the testnet resource`);

const unsignedVc = {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
  id: `${DID}/resources/1a79a313-8fc3-421c-af3d-34730fa046d1`,
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  issuer: DID,
  issuanceDate: new Date().toISOString(),
  credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation', encodedList },
};

const signedVc = signEddsaJcs2022(unsignedVc, { kid: KID, privateKey });
line(`signed: proof.type=${signedVc.proof.type}, cryptosuite=${signedVc.proof.cryptosuite}, proofValue length=${signedVc.proof.proofValue.length}`);

// --- verify with KYA-OS's own ready verifier, unmodified ----------------------------------------
const verifyStatusList = createStatusListProofVerifier({ didResolver });
line(`1. KYA-OS's createStatusListProofVerifier on our signed VC -> ${await verifyStatusList(signedVc)}`);

const tampered = structuredClone(signedVc);
tampered.credentialSubject.encodedList = tampered.credentialSubject.encodedList.slice(0, -4) + 'AAAA';
line(`2. tampered encodedList after signing -> ${await verifyStatusList(tampered)} (expected false)`);

const wrongIssuer = structuredClone(signedVc);
wrongIssuer.issuer = 'did:cheqd:testnet:aaaaaaaa-0000-0000-0000-000000000000';
line(`3. issuer swapped post-signing -> ${await verifyStatusList(wrongIssuer)} (expected false)`);

const otherKey = generateKeyPairSync('ed25519');
const forged = signEddsaJcs2022(unsignedVc, { kid: KID, privateKey: otherKey.privateKey }); // signed by a DIFFERENT key, same claimed kid
line(`4. signed by a key not in the resolved DID document -> ${await verifyStatusList(forged)} (expected false)`);

// --- full pipeline: createRevocationChecker fetches, verifies the proof, then reads the bit -----
const fakeFetch = async (url) => (url === signedVc.id ? { ok: true, status: 200, json: async () => signedVc } : { ok: false, status: 404, json: async () => ({}) });
const checker = createRevocationChecker({ fetch: fakeFetch, verifyStatusList });
const entry = { type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListCredential: signedVc.id, statusListIndex: '0' };
const result = await checker(entry);
line(`5. full pipeline (fetch -> verify proof -> inflate -> read bit) -> ${JSON.stringify(result)}`);

const uncheckedChecker = createRevocationChecker({ fetch: fakeFetch }); // no verifyStatusList: SPEC requires fail-closed only once it's mandatory (2.0); today it is optional
const uncheckedResult = await uncheckedChecker(entry);
line(`6. same pipeline with NO verifyStatusList wired (today's optional default) -> ${JSON.stringify(uncheckedResult)}`);

// 7. The point of wiring verifyStatusList at all: without it, a TAMPERED credential's bit is
//    read and trusted anyway, because nothing checked the proof before reading it.
const tamperedBit = structuredClone(signedVc);
tamperedBit.credentialSubject.encodedList = Buffer.from(
  (await (async () => { const z = await import('node:zlib'); return z.gzipSync(Buffer.from([0xff, 0xff, 0xff, 0xff])); })())
).toString('base64url');
const fetchTampered = async () => ({ ok: true, status: 200, json: async () => tamperedBit });
const uncheckedOnTampered = await createRevocationChecker({ fetch: fetchTampered })(entry);
const checkedOnTampered = await createRevocationChecker({ fetch: fetchTampered, verifyStatusList })(entry);
line(`7. a tampered credential (bits flipped, proof now invalid): unchecked -> ${JSON.stringify(uncheckedOnTampered)}, checked -> ${JSON.stringify(checkedOnTampered)}`);
