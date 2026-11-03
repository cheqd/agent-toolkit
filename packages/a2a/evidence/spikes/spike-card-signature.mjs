// Spike D: Agent Card signature verified through a DID-backed resolver that ignores `jku`
// and pins the DID the caller expects. Uses the SDK's own generate/verify helpers.
import { generateAgentCardSignature, verifyAgentCardSignature } from '@a2a-js/sdk';
import { newKey, agentCard, SERVER_DID } from './harness.mjs';

const attackerDid = 'did:web:attacker.example';
const server = await newKey(SERVER_DID);
const attacker = await newKey(attackerDid);
const fetched = [];

// The verifier-side policy: the caller names the DID it expects. jku is ignored, never fetched.
const makeResolver = (expectedDid, didDocs) => async (kid, jku) => {
  if (jku) fetched.push(`jku offered, not used: ${jku}`);
  const did = kid.split('#')[0];
  if (did !== expectedDid) throw new Error(`kid belongs to ${did}, expected ${expectedDid}`);
  const key = (didDocs[did] ?? []).find((k) => k.kid === kid);
  if (!key) throw new Error('kid not in the DID document');
  return key.pub;
};
const docs = { [SERVER_DID]: [server], [attackerDid]: [attacker] };
const verify = verifyAgentCardSignature(makeResolver(SERVER_DID, docs));

const sign = (key, kid, extra = {}) => generateAgentCardSignature(key.priv, { alg: 'EdDSA', kid, typ: 'JOSE', ...extra });
const card = agentCard('https://server.example/a2a');
const attempt = async (label, c) => { try { await verify(c); console.log(`${label}: ACCEPTED`); } catch (e) { console.log(`${label}: rejected (${e.message.slice(0, 60)})`); } };

console.log('D. Agent Card signature with a DID-backed resolver');
await attempt('card signed by the server key', await sign(server, server.kid)(card));
await attempt('same, with an attacker jku header', await sign(server, server.kid, { jku: 'https://attacker.example/jwks.json' })(card));
await attempt('attacker key claiming the server kid (jku points at attacker keys)', await sign(attacker, server.kid, { jku: 'https://attacker.example/jwks.json' })(card));
await attempt('attacker signing as itself', await sign(attacker, attacker.kid)(card));
const tampered = await sign(server, server.kid)(card);
await attempt('server-signed card, then name changed', { ...tampered, name: 'Evil agent' });
await attempt('card with no signature', card);
const double = await sign(attacker, attacker.kid)(await sign(server, server.kid)(card));
await attempt('two signatures, one valid', double);
const ext = await sign(server, server.kid)(card);
await attempt('server-signed card, extension params altered after signing', { ...ext, capabilities: { ...ext.capabilities, extensions: [{ uri: 'x', description: 'x', required: false, params: { id: 'did:web:evil' } }] } });
console.log(`jku values offered and ignored: ${fetched.length}; network fetches made: 0`);

// Are extension params covered by the signature? (the spec draft says they are not)
const withExt = { ...card, capabilities: { ...card.capabilities, extensions: [{ uri: 'https://kya-os.org/a2a/ext/entity-card/v1', description: 'd', required: false, params: { id: SERVER_DID, entityType: 'agent' } }] } };
const signedExt = await sign(server, server.kid)(withExt);
const changeParams = (p) => ({ ...signedExt, capabilities: { ...signedExt.capabilities, extensions: [{ ...signedExt.capabilities.extensions[0], params: p }] } });
await attempt('extension params changed (id swapped)', changeParams({ id: 'did:web:evil.example', entityType: 'agent' }));
await attempt('extension params: added a new key', changeParams({ id: SERVER_DID, entityType: 'agent', extra: 'x' }));
await attempt('extension params: emptied', changeParams({}));
await attempt('extension description changed', { ...signedExt, capabilities: { ...signedExt.capabilities, extensions: [{ ...signedExt.capabilities.extensions[0], description: 'changed' }] } });
await attempt('unknown top-level field added', { ...signedExt, evilField: 'x' });
