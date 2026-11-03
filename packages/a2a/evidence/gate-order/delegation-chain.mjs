// Delegation chain enforcement (§4.6 step 9): maxChainLength, scope attenuation, audience
// binding, cycle detection, ancestor cascading revocation, trustedRootIssuers, and whether the
// originating principal survives a multi-hop chain. Calls validateDelegationChain directly
// (chain-enforcement.js) with a stub per-credential verifier (structural checks only — real
// Ed25519 VC-proof verification is covered by the card-proof tests elsewhere) and a stub
// revocation checker, since the chain-walk logic under test is independent of both.
import { validateDelegationChain } from '@kya-os/mcp/delegation';
import { wrapDelegationAsVC } from '@kya-os/mcp/types';

const SERVER_DID = 'did:web:server.example';
const USER_DID = 'did:web:user.example';         // originating principal
const AGENT_A_DID = 'did:web:agent-a.example';
const AGENT_B_DID = 'did:web:agent-b.example';

function credential({ id, issuerDid, subjectDid, scopes, audience, parentId, userDid, notAfter }) {
  return wrapDelegationAsVC(
    { id, issuerDid, subjectDid, constraints: { scopes, audience, notAfter }, status: 'active', parentId },
    { scopes, userDid },
  );
}

const root = credential({ id: 'd-root', issuerDid: USER_DID, subjectDid: AGENT_A_DID, scopes: ['read', 'write'], audience: [SERVER_DID], userDid: USER_DID });
const child = credential({ id: 'd-child', issuerDid: AGENT_A_DID, subjectDid: AGENT_B_DID, scopes: ['read'], audience: [SERVER_DID], parentId: 'd-root' });

const stubVerifier = {
  async verifyDelegationCredential(cred) {
    if (cred.__forceInvalid) return { valid: false, reason: 'forced_invalid' };
    const exp = cred.expirationDate ? Date.parse(cred.expirationDate) : undefined;
    if (exp !== undefined && exp < Date.now()) return { valid: false, reason: 'expired' };
    return { valid: true };
  },
};

function chainResolverFor(ancestorsById) {
  return async (leaf) => {
    const parentId = leaf.credentialSubject.delegation.parentId;
    if (!parentId) return [];
    const out = [];
    let cur = ancestorsById.get(parentId);
    const seen = new Set();
    while (cur) {
      if (seen.has(cur.credentialSubject.delegation.id)) break; // let validateDelegationChain's own cycle check fire
      seen.add(cur.credentialSubject.delegation.id);
      out.unshift(cur);
      const pid = cur.credentialSubject.delegation.parentId;
      cur = pid ? ancestorsById.get(pid) : undefined;
      if (out.length > 50) break; // test-harness safety bound, not the thing under test
    }
    return out;
  };
}

const baseDeps = (overrides = {}) => ({
  serverDid: SERVER_DID,
  verifier: stubVerifier,
  statusListConfigured: false,
  ...overrides,
});

const line = (s) => console.log(s);

// 1. Valid 2-hop chain: root grants read+write, child narrows to read.
{
  const ancestors = new Map([['d-root', root]]);
  const r = await validateDelegationChain(child, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors) }));
  line(`1. valid 2-hop, scope narrowed read+write -> read -> valid=${r.valid} ${r.reason ?? ''}`);
}

// 2. Scope escalation: child claims a scope ("admin") the parent never granted.
{
  const escalated = credential({ id: 'd-child-esc', issuerDid: AGENT_A_DID, subjectDid: AGENT_B_DID, scopes: ['read', 'admin'], audience: [SERVER_DID], parentId: 'd-root' });
  const ancestors = new Map([['d-root', root]]);
  const r = await validateDelegationChain(escalated, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors) }));
  line(`2. scope escalation (child claims 'admin', parent never granted it) -> valid=${r.valid} ${r.reason ?? ''}`);
}

// 3. maxChainLength: cap at 1, but resolving the leaf needs root+child = 2 credentials.
{
  const ancestors = new Map([['d-root', root]]);
  const r = await validateDelegationChain(child, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors), maxChainLength: 1 }));
  line(`3. maxChainLength=1 on a 2-credential chain -> valid=${r.valid} ${r.reason ?? ''}`);
}

// 4. Audience binding: child's constraints name a different server than the one verifying it.
{
  const wrongAudience = credential({ id: 'd-child-aud', issuerDid: AGENT_A_DID, subjectDid: AGENT_B_DID, scopes: ['read'], audience: ['did:web:other-server.example'], parentId: 'd-root' });
  const ancestors = new Map([['d-root', root]]);
  const r = await validateDelegationChain(wrongAudience, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors) }));
  line(`4. leaf's audience excludes the verifying server -> valid=${r.valid} ${r.reason ?? ''}`);
}

// 5. Cycle: child claims root as its parent, and root (maliciously) claims child as ITS parent.
{
  const cyclicRoot = credential({ id: 'd-root-cyc', issuerDid: AGENT_B_DID, subjectDid: AGENT_A_DID, scopes: ['read', 'write'], audience: [SERVER_DID], parentId: 'd-child-cyc' });
  const cyclicChild = credential({ id: 'd-child-cyc', issuerDid: AGENT_A_DID, subjectDid: AGENT_B_DID, scopes: ['read'], audience: [SERVER_DID], parentId: 'd-root-cyc' });
  const ancestors = new Map([['d-root-cyc', cyclicRoot], ['d-child-cyc', cyclicChild]]);
  const r = await validateDelegationChain(cyclicChild, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors) }));
  line(`5. parent cycle (root's parent is the child) -> valid=${r.valid} ${r.reason ?? ''}`);
}

// 6. Ancestor cascading revocation: the leaf's OWN credentialStatus bit is clear, but the
//    revocationChecker reports an ancestor as revoked (the E3.1 fix chain-enforcement.d.ts notes).
{
  const ancestors = new Map([['d-root', root]]);
  const revocationChecker = { async isRevoked(id) {
    if (id === 'd-root') return { revoked: true, reason: 'ancestor_revoked', revokedAncestor: 'd-root' };
    return { revoked: false };
  } };
  const r = await validateDelegationChain(child, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors), revocationChecker }));
  line(`6. ancestor revoked (leaf's own status bit untouched) -> valid=${r.valid} ${r.reason ?? ''}`);
}

// 7. trustedRootIssuers: the chain's root was NOT issued by an allow-listed Responsible Party.
{
  const ancestors = new Map([['d-root', root]]);
  const r = await validateDelegationChain(child, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors), trustedRootIssuers: ['did:web:someone-else.example'] }));
  line(`7. root issuer not in trustedRootIssuers -> valid=${r.valid} ${r.reason ?? ''}`);
}

// 8. Originating principal survives the hop: root's userDid (the human/principal) is still
//    reachable from the resolved ancestor after a valid 2-hop validation.
{
  const ancestors = new Map([['d-root', root]]);
  const r = await validateDelegationChain(child, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors) }));
  const resolvedAncestors = await chainResolverFor(ancestors)(child);
  const principal = resolvedAncestors[0]?.credentialSubject?.delegation?.userDid;
  line(`8. principal threaded through a valid chain -> valid=${r.valid}, root.userDid=${principal} (expected ${USER_DID})`);
}

// 9. statusListConfigured: false, but the leaf carries a credentialStatus entry anyway.
{
  const withStatus = credential({ id: 'd-child-status', issuerDid: AGENT_A_DID, subjectDid: AGENT_B_DID, scopes: ['read'], audience: [SERVER_DID], parentId: 'd-root' });
  withStatus.credentialStatus = { type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: 'https://example.com/sl' };
  const ancestors = new Map([['d-root', root]]);
  const r = await validateDelegationChain(withStatus, baseDeps({ resolveDelegationChain: chainResolverFor(ancestors), statusListConfigured: false }));
  line(`9. credentialStatus present but no status resolver configured -> valid=${r.valid} ${r.reason ?? ''}`);
}
