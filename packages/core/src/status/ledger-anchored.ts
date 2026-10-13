/**
 * Ledger-anchored status checks for cheqd Bitstring status lists.
 *
 * cheqd signs a `BitstringStatusListCredential` before `encodedList` is attached, and updates never
 * re-sign it, so the issuer's proof does not cover the bits. Integrity comes from the ledger
 * instead: the list is a DID-Linked Resource written into the issuer's own collection. This module
 * reads the latest version from resolvers the verifier chose, checks the resolver's checksum
 * against the bytes it returned, and refuses anything it cannot prove. It never trusts a URL
 * supplied by a credential, only the DID inside it.
 *
 * Trust rests on the resolver (and the chain behind it), as it does for resolving the DID
 * document. The checksum comes from the same resolver, so it shows the body matches the metadata,
 * not that the resolver is honest. Use `minAgreement` of two or more to guard against that.
 *
 * Fail-closed: every unreadable, stale, inconsistent or unsupported case returns `ok: false`.
 * A result never says "not revoked" unless a bit was actually read.
 *
 * Supported: unencrypted lists with one bit per entry (`statusSize` 1). cheqd's default of two bits
 * per entry is rejected, because the bit order inside a multi-bit value is not specified well
 * enough to read safely, and KYA-OS reads one bit per entry.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** A resolver response: HTTP status and raw body bytes. */
export interface StatusListResponse {
  readonly status: number;
  readonly body: Uint8Array;
}

/** Fetches a URL and returns the raw response. Supplied by the caller so this module has no runtime dependency. */
export type StatusListFetch = (url: string) => Promise<StatusListResponse>;

/** The few primitives this module needs, supplied by the caller (Node, browser or test double). */
export interface StatusListPrimitives {
  /** Lower-case hex SHA-256 of the bytes. */
  sha256Hex(bytes: Uint8Array): Promise<string> | string;
  /** Inflates a gzip stream, failing if the output would exceed `maxBytes`. */
  gunzip(bytes: Uint8Array, maxBytes: number): Promise<Uint8Array> | Uint8Array;
  /** Decodes UTF-8 bytes to a string. */
  decodeUtf8(bytes: Uint8Array): string;
}

export interface LedgerAnchoredStatusOptions {
  /** Resolver base URLs ending at `/1.0/identifiers`. Never taken from a credential. */
  readonly resolvers: readonly string[];
  readonly fetch: StatusListFetch;
  readonly primitives: StatusListPrimitives;
  /** Epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Resolvers that must return the same answer. Default 1. Any disagreement fails regardless. */
  readonly minAgreement?: number;
  /** How far a resolver's `retrieved` time may differ from ours. Default 60 seconds. */
  readonly maxRetrievedSkewMs?: number;
  /** Cap on the inflated bitstring. Default 16 MiB. */
  readonly maxListBytes?: number;
  /** Cap on the resource body as returned. Default 8 MiB. */
  readonly maxResourceBytes?: number;
  /** Minimum list length in entries. Default 131,072, the specification's privacy floor. */
  readonly minListEntries?: number;
  /** Permit http resolvers. For tests only. */
  readonly allowInsecureResolvers?: boolean;
}

export interface StatusEntry {
  /** The entry's `statusListCredential`. Only the `did:cheqd` DID URL inside it is used. */
  readonly statusListCredential: string;
  /** Canonical non-negative decimal. */
  readonly statusListIndex: string;
  readonly statusPurpose: 'revocation' | 'suspension';
  /** If the entry declares one, it must be 1. */
  readonly statusSize?: number;
}

export type LedgerAnchoredStatusResult =
  | {
      readonly ok: true;
      readonly revoked: boolean;
      readonly resourceId: string;
      readonly checksum: string;
      readonly resourceVersion: string;
      readonly resolvers: readonly string[];
    }
  | { readonly ok: false; readonly reasons: readonly string[] };

export const LEDGER_LIST_RESOURCE_TYPE = 'BitstringStatusListCredential';

const DEFAULT_MAX_SKEW_MS = 60_000;
const DEFAULT_MAX_LIST_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_RESOURCE_BYTES = 8 * 1024 * 1024;
const DEFAULT_MIN_ENTRIES = 131_072;

class StatusError extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

interface Outcome {
  readonly revoked: boolean;
  readonly resourceId: string;
  readonly checksum: string;
  readonly resourceVersion: string;
}

interface ListRef {
  readonly did: string;
  readonly collectionId: string;
  readonly resourceName: string;
}

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function fail(reason: string): never {
  throw new StatusError(reason);
}

/**
 * Check one status entry against the ledger. Resolves with `ok: false` and reasons rather than
 * throwing, for every failure including a malformed input.
 */
export async function verifyLedgerAnchoredStatus(
  entry: StatusEntry,
  expectedIssuerDid: string,
  options: LedgerAnchoredStatusOptions,
): Promise<LedgerAnchoredStatusResult> {
  try {
    const minAgreement = options.minAgreement ?? 1;
    if (!Number.isInteger(minAgreement) || minAgreement < 1) fail('invalid_min_agreement');
    if (options.resolvers.length < minAgreement) fail('not_enough_resolvers');
    const bases = options.resolvers.map((base) => normaliseBase(base, options.allowInsecureResolvers === true));

    const index = parseIndex(entry.statusListIndex);
    if (entry.statusSize !== undefined && entry.statusSize !== 1) fail('unsupported_status_size');
    const ref = parseListRef(entry.statusListCredential, expectedIssuerDid);

    const settled = await Promise.allSettled(bases.map((base) => checkOne(base, ref, entry, index, options)));
    const agreed: { base: string; outcome: Outcome }[] = [];
    const reasons: string[] = [];
    settled.forEach((result, i) => {
      if (result.status === 'fulfilled') agreed.push({ base: bases[i] ?? '', outcome: result.value });
      else reasons.push(result.reason instanceof StatusError ? result.reason.reason : 'resolver_error');
    });

    const first = agreed[0];
    if (first !== undefined && agreed.some((a) => !sameOutcome(a.outcome, first.outcome))) {
      return { ok: false, reasons: ['resolver_disagreement'] };
    }
    if (first === undefined || agreed.length < minAgreement) {
      return { ok: false, reasons: reasons.length > 0 ? unique(reasons) : ['no_resolver_answered'] };
    }
    return {
      ok: true,
      revoked: first.outcome.revoked,
      resourceId: first.outcome.resourceId,
      checksum: first.outcome.checksum,
      resourceVersion: first.outcome.resourceVersion,
      resolvers: agreed.map((a) => a.base),
    };
  } catch (error) {
    return { ok: false, reasons: [error instanceof StatusError ? error.reason : 'unexpected_error'] };
  }
}

async function checkOne(
  base: string,
  ref: ListRef,
  entry: StatusEntry,
  index: number,
  options: LedgerAnchoredStatusOptions,
): Promise<Outcome> {
  const now = options.now ?? Date.now;
  const name = encodeURIComponent(ref.resourceName);
  const type = encodeURIComponent(LEDGER_LIST_RESOURCE_TYPE);

  // 1. Metadata for the latest version, including the resolver's own retrieval time.
  const metaResponse = await options.fetch(
    `${base}/${ref.did}?resourceName=${name}&resourceType=${type}&resourceMetadata=true`,
  );
  if (metaResponse.status !== 200) fail('metadata_unavailable');
  const meta = parseJson(metaResponse.body, options.primitives);

  const dereferencing = isRecord(meta) ? meta['dereferencingMetadata'] : undefined;
  const retrieved = isRecord(dereferencing) ? Date.parse(String(dereferencing['retrieved'])) : Number.NaN;
  const skew = options.maxRetrievedSkewMs ?? DEFAULT_MAX_SKEW_MS;
  if (Number.isNaN(retrieved) || Math.abs(now() - retrieved) > skew) fail('resolver_stale');

  const content = isRecord(meta) ? meta['contentMetadata'] : undefined;
  const linked = isRecord(content) ? content['linkedResourceMetadata'] : undefined;
  if (!Array.isArray(linked) || linked.length !== 1) fail('ambiguous_or_missing_resource');
  const resource = linked[0];
  if (!isRecord(resource)) fail('malformed_metadata');
  if (resource['resourceCollectionId'] !== ref.collectionId) fail('collection_mismatch');
  if (resource['resourceType'] !== LEDGER_LIST_RESOURCE_TYPE || resource['resourceName'] !== ref.resourceName) {
    fail('resource_mismatch');
  }
  if (resource['nextVersionId'] !== null && resource['nextVersionId'] !== undefined) fail('not_latest_version');
  const resourceId = resource['resourceId'];
  const checksum = resource['checksum'];
  const resourceVersion = resource['resourceVersion'];
  if (typeof resourceId !== 'string' || !/^[0-9a-fA-F-]{36}$/.test(resourceId)) fail('malformed_metadata');
  if (typeof checksum !== 'string' || !/^[0-9a-fA-F]{64}$/.test(checksum)) fail('malformed_metadata');
  if (typeof resourceVersion !== 'string') fail('malformed_metadata');

  // 2. The data, which must hash to the checksum the metadata names.
  const dataResponse = await options.fetch(`${base}/${ref.did}/resources/${resourceId}`);
  if (dataResponse.status !== 200) fail('resource_unavailable');
  if (dataResponse.body.length > (options.maxResourceBytes ?? DEFAULT_MAX_RESOURCE_BYTES)) fail('resource_too_large');
  const digest = await options.primitives.sha256Hex(dataResponse.body);
  if (digest.toLowerCase() !== checksum.toLowerCase()) fail('checksum_mismatch');

  // 3. The record and the credential inside it.
  const record = parseJson(dataResponse.body, options.primitives);
  if (!isRecord(record)) fail('malformed_resource');
  const metadata = record['metadata'];
  const credential = record['bitstringStatusListCredential'];
  if (!isRecord(credential) || !isRecord(metadata)) fail('malformed_resource');
  if (metadata['encrypted'] === true) fail('encrypted_list_unsupported');
  if (!includes(credential['type'], LEDGER_LIST_RESOURCE_TYPE)) fail('not_a_status_list');
  if (issuerOf(credential) !== ref.did) fail('issuer_mismatch');

  const subject = credential['credentialSubject'];
  if (!isRecord(subject) || !includes(subject['type'], 'BitstringStatusList')) fail('not_a_status_list');
  if (subject['statusPurpose'] !== entry.statusPurpose) fail('purpose_mismatch');
  for (const declared of [subject['statusSize'], metadata['statusSize']]) {
    if (declared !== undefined && declared !== 1) fail('unsupported_status_size');
  }
  const until = credential['validUntil'] ?? credential['expirationDate'];
  if (until !== undefined && (typeof until !== 'string' || Date.parse(until) <= now())) fail('list_expired');

  // 4. The bit.
  const encoded = subject['encodedList'];
  if (typeof encoded !== 'string' || encoded.length === 0) fail('malformed_resource');
  const maxBytes = options.maxListBytes ?? DEFAULT_MAX_LIST_BYTES;
  const bits = await options.primitives.gunzip(base64urlDecode(encoded.startsWith('u') ? encoded.slice(1) : encoded), maxBytes);
  if (bits.length > maxBytes) fail('list_too_large');
  if (bits.length * 8 < (options.minListEntries ?? DEFAULT_MIN_ENTRIES)) fail('list_too_short');
  const byte = bits[Math.floor(index / 8)];
  if (byte === undefined) fail('index_out_of_range');
  return { revoked: (byte & (0x80 >> index % 8)) !== 0, resourceId, checksum: checksum.toLowerCase(), resourceVersion };
}

function sameOutcome(a: Outcome, b: Outcome): boolean {
  return a.resourceId === b.resourceId && a.checksum === b.checksum && a.revoked === b.revoked;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function normaliseBase(base: string, allowInsecure: boolean): string {
  const trimmed = base.replace(/\/+$/, '');
  if (!trimmed.startsWith('https://') && !(allowInsecure && trimmed.startsWith('http://'))) fail('resolver_not_https');
  return trimmed;
}

function parseIndex(raw: string): number {
  if (!/^[0-9]+$/.test(raw)) fail('invalid_status_list_index');
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) fail('invalid_status_list_index');
  return value;
}

/** Extract the did:cheqd DID and list name from a status list URL, ignoring any host or fragment. */
function parseListRef(statusListCredential: string, expectedIssuerDid: string): ListRef {
  const start = statusListCredential.indexOf('did:cheqd:');
  if (start < 0) fail('not_a_cheqd_list');
  const didUrl = statusListCredential.slice(start).split('#')[0] ?? '';
  const match = /^(did:cheqd:(?:mainnet|testnet):([A-Za-z0-9_-]{16,64}))\?(.+)$/.exec(didUrl);
  if (match === null) fail('unsupported_list_reference');
  const did = match[1] ?? '';
  if (did !== expectedIssuerDid) fail('issuer_mismatch');
  const params = new Map<string, string>();
  for (const pair of (match[3] ?? '').split('&')) {
    const [key, value] = pair.split('=');
    if (key === undefined || value === undefined) continue;
    try {
      params.set(decodeURIComponent(key), decodeURIComponent(value));
    } catch {
      fail('unsupported_list_reference');
    }
  }
  const resourceName = params.get('resourceName');
  if (resourceName === undefined || resourceName.length === 0) fail('unsupported_list_reference');
  const type = params.get('resourceType');
  if (type !== undefined && type !== LEDGER_LIST_RESOURCE_TYPE) fail('unsupported_list_reference');
  return { did, collectionId: match[2] ?? '', resourceName };
}

function parseJson(bytes: Uint8Array, primitives: StatusListPrimitives): unknown {
  try {
    return JSON.parse(primitives.decodeUtf8(bytes));
  } catch {
    return fail('invalid_json');
  }
}

function includes(value: unknown, wanted: string): boolean {
  return value === wanted || (Array.isArray(value) && value.includes(wanted));
}

function issuerOf(credential: Json): string | undefined {
  const issuer = credential['issuer'];
  if (typeof issuer === 'string') return issuer;
  return isRecord(issuer) && typeof issuer['id'] === 'string' ? issuer['id'] : undefined;
}

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function base64urlDecode(input: string): Uint8Array {
  const clean = input.replace(/=+$/, '');
  if (!/^[A-Za-z0-9_-]*$/.test(clean) || clean.length % 4 === 1) fail('invalid_encoded_list');
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let accumulator = 0;
  let bits = 0;
  let position = 0;
  for (let i = 0; i < clean.length; i++) {
    accumulator = (accumulator << 6) | BASE64URL.indexOf(clean.charAt(i));
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[position++] = (accumulator >> bits) & 0xff;
      accumulator &= (1 << bits) - 1;
    }
  }
  return out;
}
