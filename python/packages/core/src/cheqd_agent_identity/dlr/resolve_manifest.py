"""Resolves a cheqd DID-Linked Resource manifest - `TrustConfigManifest`, `CapabilityManifest`
or `ConformanceManifest`. Same trust model as `verify_ledger_anchored_status`: the resolver's
own checksum is checked against the bytes it actually returned, multiple resolvers can be
required to agree, and every unreadable, stale or malformed case fails closed. DID-Linked
Resources are read at discovery and policy-refresh time only - this module has no write path.

Caching is per-kind, with a caller-supplied TTL. `create_manifest_cache` wraps
`resolve_manifest` with that.

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
from urllib.parse import quote

ManifestKind = Literal["TrustConfigManifest", "CapabilityManifest", "ConformanceManifest"]

_DEFAULT_MAX_SKEW_MS = 60_000
_DEFAULT_MAX_BYTES = 1024 * 1024
_DEFAULT_TTL_MS = 5 * 60_000

_RESOURCE_ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
_CHECKSUM_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class ManifestResolverResponse:
    status: int
    body: bytes


ManifestFetch = Callable[[str], Awaitable[ManifestResolverResponse]]


@dataclass(frozen=True)
class ManifestPrimitives:
    sha256_hex: Callable[[bytes], Union[str, Awaitable[str]]]
    decode_utf8: Callable[[bytes], str]


@dataclass(frozen=True)
class ResolveManifestOptions:
    resolvers: Sequence[str]
    fetch: ManifestFetch
    primitives: ManifestPrimitives
    now: Callable[[], float] = field(default=lambda: datetime.now(timezone.utc).timestamp() * 1000)
    min_agreement: int = 1
    max_retrieved_skew_ms: int = _DEFAULT_MAX_SKEW_MS
    max_bytes: int = _DEFAULT_MAX_BYTES
    allow_insecure_resolvers: bool = False


@dataclass(frozen=True)
class ResolveManifestOk:
    content: Any
    resource_id: str
    checksum: str
    resource_version: str
    resolvers: Sequence[str]
    ok: bool = True


@dataclass(frozen=True)
class ResolveManifestFailed:
    reasons: Sequence[str]
    ok: bool = False


ResolveManifestResult = Union[ResolveManifestOk, ResolveManifestFailed]


class _ManifestError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _fail(reason: str) -> None:
    raise _ManifestError(reason)


@dataclass(frozen=True)
class _Outcome:
    content: Any
    resource_id: str
    checksum: str
    resource_version: str


async def resolve_manifest(
    did: str,
    kind: ManifestKind,
    resource_name: str,
    options: ResolveManifestOptions,
) -> ResolveManifestResult:
    """Resolve one manifest resource by DID, kind and resource name. Returns `ok=False` and
    reasons rather than raising, for every failure including a malformed input.
    """
    try:
        min_agreement = options.min_agreement
        if min_agreement < 1:
            _fail("invalid_min_agreement")
        if len(options.resolvers) < min_agreement:
            _fail("not_enough_resolvers")
        bases = [_normalise_base(base, options.allow_insecure_resolvers) for base in options.resolvers]

        results = await asyncio.gather(
            *(_check_one(base, did, kind, resource_name, options) for base in bases), return_exceptions=True
        )
        agreed: list[tuple[str, _Outcome]] = []
        reasons: list[str] = []
        for base, result in zip(bases, results):
            if isinstance(result, _Outcome):
                agreed.append((base, result))
            elif isinstance(result, BaseException):
                reasons.append(result.reason if isinstance(result, _ManifestError) else "resolver_error")

        first = agreed[0] if agreed else None
        if first is not None and any(not _same_outcome(outcome, first[1]) for _, outcome in agreed):
            return ResolveManifestFailed(reasons=("resolver_disagreement",))
        if first is None or len(agreed) < min_agreement:
            return ResolveManifestFailed(reasons=tuple(dict.fromkeys(reasons)) or ("no_resolver_answered",))
        return ResolveManifestOk(
            content=first[1].content,
            resource_id=first[1].resource_id,
            checksum=first[1].checksum,
            resource_version=first[1].resource_version,
            resolvers=tuple(base for base, _ in agreed),
        )
    except _ManifestError as error:
        return ResolveManifestFailed(reasons=(error.reason,))
    except Exception:
        return ResolveManifestFailed(reasons=("unexpected_error",))


async def _check_one(
    base: str,
    did: str,
    kind: ManifestKind,
    resource_name: str,
    options: ResolveManifestOptions,
) -> _Outcome:
    now = options.now()
    name = quote(resource_name, safe="")
    type_ = quote(kind, safe="")

    meta_url = f"{base}/{did}?resourceName={name}&resourceType={type_}&resourceMetadata=true"
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
    if resource.get("resourceType") != kind or resource.get("resourceName") != resource_name:
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

    data_response = await options.fetch(f"{base}/{did}/resources/{resource_id}")
    if data_response.status != 200:
        _fail("resource_unavailable")
    if len(data_response.body) > options.max_bytes:
        _fail("resource_too_large")
    digest = await _maybe_await(options.primitives.sha256_hex(data_response.body))
    if digest.lower() != checksum.lower():
        _fail("checksum_mismatch")

    parsed_content = _parse_json(data_response.body, options.primitives)
    return _Outcome(
        content=parsed_content,
        resource_id=resource_id,
        checksum=checksum.lower(),
        resource_version=resource_version,
    )


async def _maybe_await(value: Any) -> Any:
    return await value if asyncio.iscoroutine(value) else value


def _same_outcome(a: _Outcome, b: _Outcome) -> bool:
    return a.resource_id == b.resource_id and a.checksum == b.checksum


def _normalise_base(base: str, allow_insecure: bool) -> str:
    trimmed = base.rstrip("/")
    if not trimmed.startswith("https://") and not (allow_insecure and trimmed.startswith("http://")):
        _fail("resolver_not_https")
    return trimmed


def _parse_json(data: bytes, primitives: ManifestPrimitives) -> Any:
    try:
        return json.loads(primitives.decode_utf8(data))
    except Exception:
        _fail("invalid_json")


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


# --- Caching: bound every cache with an artifact-specific TTL. --------------------------------


@dataclass(frozen=True)
class ManifestCacheOptions(ResolveManifestOptions):
    ttl_ms_by_kind: Optional[dict[ManifestKind, int]] = None
    default_ttl_ms: int = _DEFAULT_TTL_MS


@dataclass(frozen=True)
class _CacheEntry:
    result: ResolveManifestResult
    expires_at: float


class ManifestCache:
    def __init__(self, options: ManifestCacheOptions) -> None:
        self._options = options
        self._cache: dict[str, _CacheEntry] = {}

    async def get(self, did: str, kind: ManifestKind, resource_name: str) -> ResolveManifestResult:
        """Returns the cached result if still fresh, otherwise resolves again and caches the
        result - including a failure, so a down resolver cannot be hammered every call within
        the TTL.
        """
        key = f"{did}\x00{kind}\x00{resource_name}"
        now = self._options.now()
        cached = self._cache.get(key)
        if cached is not None and cached.expires_at > now:
            return cached.result
        result = await resolve_manifest(did, kind, resource_name, self._options)
        ttl = (self._options.ttl_ms_by_kind or {}).get(kind, self._options.default_ttl_ms)
        self._cache[key] = _CacheEntry(result=result, expires_at=now + ttl)
        return result

    def clear(self) -> None:
        self._cache.clear()


def create_manifest_cache(options: ManifestCacheOptions) -> ManifestCache:
    return ManifestCache(options)
