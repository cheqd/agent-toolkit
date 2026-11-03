// Tests whether KYA-OS's upstream CheqdStatusListResolver (ledger-anchored: pinned issuer +
// Ed25519Signature2020 proof check against the on-chain DID document) can verify the real
// testnet resource probed in probe.sh - off the shelf, if it works, with no custom adapter
// needed for status-list integrity checking against a cheqd-anchored list.
import {
  createCheqdStatusListResolver,
  createDidCheqdResolver,
} from '@kya-os/mcp/cheqd';
import { RuntimeFetchProvider } from '@kya-os/mcp/providers';
import { NodeCryptoProvider } from '@kya-os/mcp/providers';
import { gunzipSync } from 'node:zlib';

const DID = 'did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede';
const RESOLVER_URL = 'https://resolver.cheqd.net/1.0/identifiers';
const STATUS_LIST_URL = `${RESOLVER_URL}/${DID}?resourceName=cheqd-employee-credentials-unencrypted&resourceType=StatusList2021Revocation`;

const fetchProvider = new RuntimeFetchProvider();
const cryptoProvider = new NodeCryptoProvider();
const didResolver = createDidCheqdResolver(fetchProvider, { resolverUrl: RESOLVER_URL });

const resolver = createCheqdStatusListResolver({
  fetchProvider,
  didResolver,
  cryptoProvider,
  expectedIssuerDid: DID,
  decompressor: (bytes) => gunzipSync(bytes),
});

const scenarios = [
  { name: 'real resource, index 0', statusListCredential: STATUS_LIST_URL, statusListIndex: '0' },
  { name: 'wrong expected issuer (separate resolver instance)', custom: true },
  { name: 'out-of-range index', statusListCredential: STATUS_LIST_URL, statusListIndex: '999999999' },
  { name: 'non-https URL', statusListCredential: STATUS_LIST_URL.replace('https://', 'http://'), statusListIndex: '0' },
];

for (const s of scenarios) {
  try {
    let result;
    if (s.custom) {
      const wrongResolver = createCheqdStatusListResolver({
        fetchProvider,
        didResolver,
        cryptoProvider,
        expectedIssuerDid: 'did:cheqd:testnet:aaaaaaaa-0000-0000-0000-000000000000',
        decompressor: (bytes) => gunzipSync(bytes),
      });
      result = await wrongResolver.checkStatus({
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListCredential: STATUS_LIST_URL,
        statusListIndex: '0',
      });
    } else {
      result = await resolver.checkStatus({
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListCredential: s.statusListCredential,
        statusListIndex: s.statusListIndex,
      });
    }
    console.log(`${s.name.padEnd(45)} -> revoked=${result}`);
  } catch (err) {
    console.log(`${s.name.padEnd(45)} -> THREW: ${err.message}`);
  }
}
