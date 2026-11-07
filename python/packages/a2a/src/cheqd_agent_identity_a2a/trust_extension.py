"""The `https://cheqd.io/a2a/ext/trust/v1` extension's per-DID checks (spec §5.2 steps 5-7):
reciprocal `alsoKnownAs` linkage, DID-Linked Resource manifest resolution, and credential
status - composed from building blocks `cheqd_agent_identity` already ships
(`verify_reciprocal_linkage`, `ManifestCache`), not reimplemented here.

These are discovery-time checks, refreshed on a TTL, never per call (spec §5.5) - so this
module caches a verdict per canonical DID, rather than resolving a manifest or a status list on
every proof it verifies.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Literal, Optional, Sequence, Union
from urllib.parse import parse_qs

from cheqd_agent_identity.dlr.resolve_manifest import ManifestCache, ManifestKind
from cheqd_agent_identity.linkage.reciprocal_linkage import LinkageDidDocument, verify_reciprocal_linkage

_RESOURCE_REF_RE = re.compile(r"^(did:cheqd:(?:mainnet|testnet):[A-Za-z0-9_-]{16,64})\?(.+)$")
_MANIFEST_KINDS = {"TrustConfigManifest", "CapabilityManifest", "ConformanceManifest"}


@dataclass(frozen=True)
class TrustExtensionActivation:
    """The trust extension's activation params, per spec §5.1."""

    anchored_did: Optional[str] = None
    """The caller's claimed anchored `did:cheqd`, if any. Reciprocal linkage is required when
    present."""
    trust_config_ref: Optional[str] = None
    """`did:cheqd:...?resourceName=...&resourceType=TrustConfigManifest|CapabilityManifest|
    ConformanceManifest`."""
    status_check: Optional[Literal["required", "optional"]] = None


ResolveDidDocument = Callable[[str], Awaitable[Optional[LinkageDidDocument]]]
CheckStatus = Callable[[str], Awaitable[tuple[bool, bool]]]


@dataclass(frozen=True)
class TrustExtensionDeps:
    resolve_did_document: ResolveDidDocument
    """Resolves a `did:web` or `did:cheqd` document for the linkage check. Fails closed
    (returns `None`) on any error."""
    manifest_cache: ManifestCache
    check_status: Optional[CheckStatus] = None
    """Required when any activation can set `status_check='required'`. Fails closed if
    omitted."""


@dataclass(frozen=True)
class TrustExtensionOk:
    ok: bool = True


@dataclass(frozen=True)
class TrustExtensionFailed:
    reasons: Sequence[str]
    ok: bool = False


TrustExtensionResult = Union[TrustExtensionOk, TrustExtensionFailed]


@dataclass(frozen=True)
class _ResourceRef:
    did: str
    kind: ManifestKind
    resource_name: str


def _parse_resource_ref(ref: str) -> Optional[_ResourceRef]:
    """Parse a DID-Linked Resource reference (`did:cheqd:...?resourceName=X&resourceType=Y`)
    into its parts. Returns `None` on anything malformed - callers fail closed on that, same
    as every other reason.
    """
    match = _RESOURCE_REF_RE.match(ref)
    if match is None:
        return None
    did, query = match.group(1), match.group(2)
    params = parse_qs(query)
    resource_name = (params.get("resourceName") or [None])[0]
    resource_type = (params.get("resourceType") or [None])[0]
    if not did or not resource_name or not resource_type:
        return None
    if resource_type not in _MANIFEST_KINDS:
        return None
    return _ResourceRef(did=did, kind=resource_type, resource_name=resource_name)  # type: ignore[arg-type]


async def verify_trust_extension(
    canonical_did: str, activation: TrustExtensionActivation, deps: TrustExtensionDeps
) -> TrustExtensionResult:
    """Run the trust extension's per-DID checks (spec §5.2 steps 5-7) for `canonical_did`
    under the given activation params. Fails closed: a declared check that cannot be
    completed (malformed ref, missing dependency, resolver failure) is a failure, never a
    skip.
    """
    reasons: list[str] = []

    if activation.anchored_did:
        canonical_doc, anchored_doc = await asyncio.gather(
            deps.resolve_did_document(canonical_did), deps.resolve_did_document(activation.anchored_did)
        )
        if not canonical_doc or not anchored_doc:
            reasons.append("linkage_resolution_failed")
        else:
            linkage = verify_reciprocal_linkage(canonical_doc, anchored_doc)
            if not linkage.ok:
                reasons.extend(f"linkage_{r}" for r in linkage.reasons)

    if activation.trust_config_ref:
        parsed = _parse_resource_ref(activation.trust_config_ref)
        if parsed is None:
            reasons.append("malformed_trust_config_ref")
        else:
            manifest = await deps.manifest_cache.get(parsed.did, parsed.kind, parsed.resource_name)
            if not manifest.ok:
                reasons.extend(f"manifest_{r}" for r in manifest.reasons)

    if activation.status_check == "required":
        if deps.check_status is None:
            reasons.append("status_check_unavailable")
        else:
            revoked, fresh = await deps.check_status(canonical_did)
            if revoked or not fresh:
                reasons.append("status_revoked" if revoked else "status_not_fresh")

    return TrustExtensionOk() if not reasons else TrustExtensionFailed(reasons=tuple(reasons))


_DEFAULT_TTL_MS = 5 * 60_000


@dataclass(frozen=True)
class _CacheEntry:
    result: TrustExtensionResult
    expires_at: float


class TrustExtensionCache:
    """TTL-bounded cache over `verify_trust_extension`, so a verified DID's trust-extension
    checks are refreshed on a timer, not re-run against resolvers and manifests on every
    request the gate verifies (spec §5.5: never per call).
    """

    def __init__(
        self,
        deps: TrustExtensionDeps,
        *,
        ttl_ms: int = _DEFAULT_TTL_MS,
        now: Callable[[], float] = lambda: datetime.now(timezone.utc).timestamp() * 1000,
    ) -> None:
        self._deps = deps
        self._ttl_ms = ttl_ms
        self._now = now
        self._cache: dict[str, _CacheEntry] = {}

    async def get(self, canonical_did: str, activation: TrustExtensionActivation) -> TrustExtensionResult:
        key = f"{canonical_did}\x00{json.dumps(activation.__dict__, sort_keys=True)}"
        now = self._now()
        cached = self._cache.get(key)
        if cached is not None and cached.expires_at > now:
            return cached.result
        result = await verify_trust_extension(canonical_did, activation, self._deps)
        self._cache[key] = _CacheEntry(result=result, expires_at=now + self._ttl_ms)
        return result

    def clear(self) -> None:
        self._cache.clear()


def create_trust_extension_cache(
    deps: TrustExtensionDeps, *, ttl_ms: int = _DEFAULT_TTL_MS, now: Optional[Callable[[], float]] = None
) -> TrustExtensionCache:
    kwargs = {"ttl_ms": ttl_ms}
    if now is not None:
        kwargs["now"] = now
    return TrustExtensionCache(deps, **kwargs)
