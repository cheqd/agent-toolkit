"""Ledger-anchored status checks for cheqd Bitstring status lists.

cheqd signs a `BitstringStatusListCredential` before `encodedList` is attached, and updates
never re-sign it, so the issuer's proof does not cover the bits. Integrity comes from the
ledger instead: the list is a DID-Linked Resource written into the issuer's own collection.
This module reads the latest version from resolvers the verifier chose, checks the resolver's
checksum against the bytes it returned, and refuses anything it cannot prove. It never trusts a
URL supplied by a credential, only the DID inside it.

Trust rests on the resolver (and the chain behind it), as it does for resolving the DID
document. The checksum comes from the same resolver, so it shows the body matches the metadata,
not that the resolver is honest. Use `min_agreement` of two or more to guard against that.

Fail-closed: every unreadable, stale, inconsistent or unsupported case returns `ok=False`. A
result never says "not revoked" unless a bit was actually read.

Supported: unencrypted lists with one bit per entry (`statusSize` 1). cheqd's default of two
bits per entry is rejected, because the bit order inside a multi-bit value is not specified well
enough to read safely, and KYA-OS reads one bit per entry.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Literal, Optional, Sequence, Union
from urllib.parse import quote, unquote

LEDGER_LIST_RESOURCE_TYPE = "BitstringStatusListCredential"

_DEFAULT_MAX_SKEW_MS = 60_000
_DEFAULT_MAX_LIST_BYTES = 16 * 1024 * 1024
_DEFAULT_MAX_RESOURCE_BYTES = 8 * 1024 * 1024
_DEFAULT_MIN_ENTRIES = 131_072

_RESOURCE_ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
_CHECKSUM_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_LIST_REF_RE = re.compile(r"^(did:cheqd:(?:mainnet|testnet):([A-Za-z0-9_-]{16,64}))\?(.+)$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class StatusListResponse:
    status: int
    body: bytes


StatusListFetch = Callable[[str], Awaitable[StatusListResponse]]


@dataclass(frozen=True)
class StatusListPrimitives:
    """The few primitives this module needs, supplied by the caller."""

    sha256_hex: Callable[[bytes], Union[str, Awaitable[str]]]
    gunzip: Callable[[bytes, int], Union[bytes, Awaitable[bytes]]]
    decode_utf8: Callable[[bytes], str]


@dataclass(frozen=True)
class LedgerAnchoredStatusOptions:
    resolvers: Sequence[str]
    fetch: StatusListFetch
    primitives: StatusListPrimitives
    now: Callable[[], float] = field(default=lambda: datetime.now(timezone.utc).timestamp() * 1000)
    min_agreement: int = 1
    max_retrieved_skew_ms: int = _DEFAULT_MAX_SKEW_MS
    max_list_bytes: int = _DEFAULT_MAX_LIST_BYTES
    max_resource_bytes: int = _DEFAULT_MAX_RESOURCE_BYTES
    min_list_entries: int = _DEFAULT_MIN_ENTRIES
    allow_insecure_resolvers: bool = False


@dataclass(frozen=True)
class StatusEntry:
    status_list_credential: str
    status_list_index: str
    status_purpose: Literal["revocation", "suspension"]
    status_size: Optional[int] = None


@dataclass(frozen=True)
class LedgerAnchoredStatusOk:
    revoked: bool
    resource_id: str
    checksum: str
    resource_version: str
    resolvers: Sequence[str]
    ok: bool = True


@dataclass(frozen=True)
class LedgerAnchoredStatusFailed:
    reasons: Sequence[str]
    ok: bool = False


LedgerAnchoredStatusResult = Union[LedgerAnchoredStatusOk, LedgerAnchoredStatusFailed]


class _StatusError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _fail(reason: str) -> None:
    raise _StatusError(reason)


@dataclass(frozen=True)
class _Outcome:
    revoked: bool
    resource_id: str
    checksum: str
    resource_version: str


@dataclass(frozen=True)
class _ListRef:
    did: str
    collection_id: str
    resource_name: str


async def verify_ledger_anchored_status(
    entry: StatusEntry,
    expected_issuer_did: str,
    options: LedgerAnchoredStatusOptions,
) -> LedgerAnchoredStatusResult:
    """Check one status entry against the ledger. Returns `ok=False` and reasons rather than
    raising, for every failure including a malformed input.
    """
    try:
        min_agreement = options.min_agreement
        if min_agreement < 1:
            _fail("invalid_min_agreement")
        if len(options.resolvers) < min_agreement:
            _fail("not_enough_resolvers")
        bases = [_normalise_base(base, options.allow_insecure_resolvers) for base in options.resolvers]

        index = _parse_index(entry.status_list_index)
        if entry.status_size is not None and entry.status_size != 1:
            _fail("unsupported_status_size")
        ref = _parse_list_ref(entry.status_list_credential, expected_issuer_did)

        results = await asyncio.gather(
            *(_check_one(base, ref, entry, index, options) for base in bases), return_exceptions=True
        )
        agreed: list[tuple[str, _Outcome]] = []
        reasons: list[str] = []
        for base, result in zip(bases, results):
            if isinstance(result, _Outcome):
                agreed.append((base, result))
            elif isinstance(result, BaseException):
                reasons.append(result.reason if isinstance(result, _StatusError) else "resolver_error")

        first = agreed[0] if agreed else None
        if first is not None and any(not _same_outcome(outcome, first[1]) for _, outcome in agreed):
            return LedgerAnchoredStatusFailed(reasons=("resolver_disagreement",))
        if first is None or len(agreed) < min_agreement:
            unique_reasons = tuple(dict.fromkeys(reasons))
            return LedgerAnchoredStatusFailed(reasons=unique_reasons or ("no_resolver_answered",))
        return LedgerAnchoredStatusOk(
            revoked=first[1].revoked,
            resource_id=first[1].resource_id,
            checksum=first[1].checksum,
            resource_version=first[1].resource_version,
            resolvers=tuple(base for base, _ in agreed),
        )
    except _StatusError as error:
        return LedgerAnchoredStatusFailed(reasons=(error.reason,))
    except Exception:
        return LedgerAnchoredStatusFailed(reasons=("unexpected_error",))


async def _maybe_await(value: Any) -> Any:
    return await value if asyncio.iscoroutine(value) else value


async def _check_one(
    base: str,
    ref: _ListRef,
    entry: StatusEntry,
    index: int,
    options: LedgerAnchoredStatusOptions,
) -> _Outcome:
    now = options.now()
    name = quote(ref.resource_name, safe="")
    type_ = quote(LEDGER_LIST_RESOURCE_TYPE, safe="")

    # 1. Metadata for the latest version, including the resolver's own retrieval time.
    meta_url = f"{base}/{ref.did}?resourceName={name}&resourceType={type_}&resourceMetadata=true"
    meta_response = await options.fetch(meta_url)
    if meta_response.status != 200:
        _fail("metadata_unavailable")
    meta = _parse_json(meta_response.body, options.primitives)

    dereferencing = meta.get("dereferencingMetadata") if isinstance(meta, dict) else None
    retrieved = _parse_date(dereferencing.get("retrieved")) if isinstance(dereferencing, dict) else None
    skew = options.max_retrieved_skew_ms
    if retrieved is None or abs(now - retrieved) > skew:
        _fail("resolver_stale")

    content = meta.get("contentMetadata") if isinstance(meta, dict) else None
    linked = content.get("linkedResourceMetadata") if isinstance(content, dict) else None
    if not isinstance(linked, list) or len(linked) != 1:
        _fail("ambiguous_or_missing_resource")
    resource = linked[0]
    if not isinstance(resource, dict):
        _fail("malformed_metadata")
    if resource.get("resourceCollectionId") != ref.collection_id:
        _fail("collection_mismatch")
    type_matches = resource.get("resourceType") == LEDGER_LIST_RESOURCE_TYPE
    name_matches = resource.get("resourceName") == ref.resource_name
    if not type_matches or not name_matches:
        _fail("resource_mismatch")
    if resource.get("nextVersionId") is not None:
        _fail("not_latest_version")
    resource_id = resource.get("resourceId")
    checksum = resource.get("checksum")
    resource_version = resource.get("resourceVersion")
    if not isinstance(resource_id, str) or not _RESOURCE_ID_RE.match(resource_id):
        _fail("malformed_metadata")
    if not isinstance(checksum, str) or not _CHECKSUM_RE.match(checksum):
        _fail("malformed_metadata")
    if not isinstance(resource_version, str):
        _fail("malformed_metadata")

    # 2. The data, which must hash to the checksum the metadata names.
    data_response = await options.fetch(f"{base}/{ref.did}/resources/{resource_id}")
    if data_response.status != 200:
        _fail("resource_unavailable")
    if len(data_response.body) > options.max_resource_bytes:
        _fail("resource_too_large")
    digest = await _maybe_await(options.primitives.sha256_hex(data_response.body))
    if digest.lower() != checksum.lower():
        _fail("checksum_mismatch")

    # 3. The record and the credential inside it.
    record = _parse_json(data_response.body, options.primitives)
    if not isinstance(record, dict):
        _fail("malformed_resource")
    metadata = record.get("metadata")
    credential = record.get("bitstringStatusListCredential")
    if not isinstance(credential, dict) or not isinstance(metadata, dict):
        _fail("malformed_resource")
    if metadata.get("encrypted") is True:
        _fail("encrypted_list_unsupported")
    if not _includes(credential.get("type"), LEDGER_LIST_RESOURCE_TYPE):
        _fail("not_a_status_list")
    if _issuer_of(credential) != ref.did:
        _fail("issuer_mismatch")

    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict) or not _includes(subject.get("type"), "BitstringStatusList"):
        _fail("not_a_status_list")
    if subject.get("statusPurpose") != entry.status_purpose:
        _fail("purpose_mismatch")
    for declared in (subject.get("statusSize"), metadata.get("statusSize")):
        if declared is not None and declared != 1:
            _fail("unsupported_status_size")
    until = credential.get("validUntil") or credential.get("expirationDate")
    if until is not None:
        parsed_until = _parse_date(until) if isinstance(until, str) else None
        if parsed_until is None or parsed_until <= now:
            _fail("list_expired")

    # 4. The bit.
    encoded = subject.get("encodedList")
    if not isinstance(encoded, str) or len(encoded) == 0:
        _fail("malformed_resource")
    max_bytes = options.max_list_bytes
    raw = _base64url_decode(encoded[1:] if encoded.startswith("u") else encoded)
    bits = await _maybe_await(options.primitives.gunzip(raw, max_bytes))
    if len(bits) > max_bytes:
        _fail("list_too_large")
    if len(bits) * 8 < options.min_list_entries:
        _fail("list_too_short")
    byte_index = index // 8
    if byte_index >= len(bits):
        _fail("index_out_of_range")
    byte = bits[byte_index]
    return _Outcome(
        revoked=(byte & (0x80 >> (index % 8))) != 0,
        resource_id=resource_id,
        checksum=checksum.lower(),
        resource_version=resource_version,
    )


def _same_outcome(a: _Outcome, b: _Outcome) -> bool:
    return a.resource_id == b.resource_id and a.checksum == b.checksum and a.revoked == b.revoked


def _normalise_base(base: str, allow_insecure: bool) -> str:
    trimmed = base.rstrip("/")
    if not trimmed.startswith("https://") and not (allow_insecure and trimmed.startswith("http://")):
        _fail("resolver_not_https")
    return trimmed


def _parse_index(raw: str) -> int:
    if not re.match(r"^[0-9]+$", raw):
        _fail("invalid_status_list_index")
    value = int(raw)
    if value > 2**53 - 1:
        _fail("invalid_status_list_index")
    return value


def _parse_list_ref(status_list_credential: str, expected_issuer_did: str) -> _ListRef:
    """Extract the did:cheqd DID and list name from a status list URL, ignoring any host or
    fragment.
    """
    start = status_list_credential.find("did:cheqd:")
    if start < 0:
        _fail("not_a_cheqd_list")
    did_url = status_list_credential[start:].split("#")[0]
    match = _LIST_REF_RE.match(did_url)
    if match is None:
        _fail("unsupported_list_reference")
    did = match.group(1)
    if did != expected_issuer_did:
        _fail("issuer_mismatch")
    params: dict[str, str] = {}
    for pair in match.group(3).split("&"):
        parts = pair.split("=")
        if len(parts) != 2:
            continue
        key, value = parts
        try:
            params[unquote(key)] = unquote(value)
        except Exception:
            _fail("unsupported_list_reference")
    resource_name = params.get("resourceName")
    if not resource_name:
        _fail("unsupported_list_reference")
    type_ = params.get("resourceType")
    if type_ is not None and type_ != LEDGER_LIST_RESOURCE_TYPE:
        _fail("unsupported_list_reference")
    return _ListRef(did=did, collection_id=match.group(2), resource_name=resource_name)


def _parse_json(data: bytes, primitives: StatusListPrimitives) -> Any:
    try:
        return json.loads(primitives.decode_utf8(data))
    except Exception:
        _fail("invalid_json")


def _includes(value: Any, wanted: str) -> bool:
    return value == wanted or (isinstance(value, list) and wanted in value)


def _issuer_of(credential: dict[str, Any]) -> Optional[str]:
    issuer = credential.get("issuer")
    if isinstance(issuer, str):
        return issuer
    return issuer.get("id") if isinstance(issuer, dict) and isinstance(issuer.get("id"), str) else None


def _parse_date(value: Any) -> Optional[float]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        try:
            return parsedate_to_datetime(value).timestamp() * 1000
        except Exception:
            return None


_BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _base64url_decode(data: str) -> bytes:
    clean = data.rstrip("=")
    if not _BASE64URL_RE.match(clean) or len(clean) % 4 == 1:
        _fail("invalid_encoded_list")
    out = bytearray((len(clean) * 6) // 8)
    accumulator = 0
    bits = 0
    position = 0
    for char in clean:
        accumulator = (accumulator << 6) | _BASE64URL.index(char)
        bits += 6
        if bits >= 8:
            bits -= 8
            out[position] = (accumulator >> bits) & 0xFF
            position += 1
            accumulator &= (1 << bits) - 1
    return bytes(out)
