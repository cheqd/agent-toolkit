# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from datetime import datetime, timezone

from cheqd_agent_identity.dlr.resolve_manifest import (
    ManifestCacheOptions,
    ManifestPrimitives,
    ManifestResolverResponse,
    ResolveManifestOptions,
    create_manifest_cache,
    resolve_manifest,
)

NOW = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1000
DID = "did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede"
COLLECTION = "0c3581f0-011f-4263-b1ca-15ad70d54ede"
RESOURCE_ID = "1a79a313-8fc3-421c-af3d-34730fa046d1"
BASE = "https://resolver.test/1.0/identifiers"
NAME = "trust-config"
KIND = "TrustConfigManifest"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_utf8(data: bytes) -> str:
    return data.decode("utf-8")


PRIMITIVES = ManifestPrimitives(sha256_hex=_sha256_hex, decode_utf8=_decode_utf8)


def world(content, **opts) -> dict:
    body_bytes = json.dumps(content).encode("utf-8")
    checksum = opts.get("checksum", _sha256_hex(body_bytes))
    linked = {
        "resourceId": RESOURCE_ID,
        "resourceName": NAME,
        "resourceType": KIND,
        "resourceCollectionId": COLLECTION,
        "resourceVersion": "2026-11-01T00:00:00Z",
        "checksum": checksum,
        "nextVersionId": None,
        **opts.get("linked", {}),
    }
    retrieved_at = opts.get("retrievedAt", NOW)
    meta = {
        "dereferencingMetadata": {
            "retrieved": datetime.fromtimestamp(retrieved_at / 1000, tz=timezone.utc).isoformat()
        },
        "contentMetadata": {"linkedResourceMetadata": opts.get("linkedList", [linked])},
    }
    return {"meta": meta, "bytes": body_bytes}


def fetch_for(w: dict):
    calls = {"count": 0}

    async def fn(url: str) -> ManifestResolverResponse:
        calls["count"] += 1
        if "resourceMetadata=true" in url:
            return ManifestResolverResponse(status=200, body=json.dumps(w["meta"]).encode("utf-8"))
        if "/resources/" in url:
            return ManifestResolverResponse(status=200, body=w["bytes"])
        return ManifestResolverResponse(status=404, body=b"")

    fn.calls = calls
    return fn


async def test_resolves_a_well_formed_manifest_and_checks_the_checksum():
    w = world({"acceptedIssuers": ["did:cheqd:testnet:abc"]})
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(resolvers=[BASE], fetch=fetch_for(w), primitives=PRIMITIVES, now=lambda: NOW),
    )
    assert result.ok is True
    assert result.content == {"acceptedIssuers": ["did:cheqd:testnet:abc"]}
    assert result.resource_id == RESOURCE_ID


async def test_a_checksum_that_does_not_match_the_bytes_is_rejected():
    w = world({"a": 1}, checksum="0" * 64)
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(resolvers=[BASE], fetch=fetch_for(w), primitives=PRIMITIVES, now=lambda: NOW),
    )
    assert result.ok is False
    assert "checksum_mismatch" in result.reasons


async def test_a_resource_bound_to_a_different_did_collection_is_rejected_even_with_matching_kind_name():
    # Regression: resolve_manifest used to check only (resourceType, resourceName), never that the
    # returned resource's resourceCollectionId actually belongs to the DID being resolved - so a
    # resolver answering with metadata from a DIFFERENT DID's collection (bug, misconfiguration, or
    # compromise) would be accepted as long as that other collection happened to have a resource of
    # the same kind and name. TS's equivalent check (`collection_mismatch`, PR #43) must be ported
    # here too.
    w = world({"a": 1}, linked={"resourceCollectionId": "99999999-9999-4999-8999-999999999999"})
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(resolvers=[BASE], fetch=fetch_for(w), primitives=PRIMITIVES, now=lambda: NOW),
    )
    assert result.ok is False
    assert "collection_mismatch" in result.reasons


async def test_a_malformed_did_is_rejected_without_any_fetch():
    # An untrusted DID string must be validated before any fetch is constructed or sent, not only
    # before trusting a resolver's answer - a malformed `did` (e.g. one containing a dot-segment a
    # URL implementation would normalise away) must not trigger an outbound request at all.
    w = world({"a": 1})
    fetch = fetch_for(w)
    result = await resolve_manifest(
        "did:cheqd:testnet:VICTIM0000000000/../did:cheqd:testnet:ATTACKER00000000",
        KIND,
        NAME,
        ResolveManifestOptions(resolvers=[BASE], fetch=fetch, primitives=PRIMITIVES, now=lambda: NOW),
    )
    assert result.ok is False
    assert "unsupported_did" in result.reasons
    assert fetch.calls["count"] == 0


async def test_the_wrong_manifest_kind_at_the_same_name_is_rejected():
    w = world({"a": 1}, linked={"resourceType": "CapabilityManifest"})
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(resolvers=[BASE], fetch=fetch_for(w), primitives=PRIMITIVES, now=lambda: NOW),
    )
    assert result.ok is False
    assert "resource_mismatch" in result.reasons


async def test_a_stale_resolver_reply_is_rejected():
    w = world({"a": 1}, retrievedAt=NOW - 10 * 60_000)
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(resolvers=[BASE], fetch=fetch_for(w), primitives=PRIMITIVES, now=lambda: NOW),
    )
    assert result.ok is False
    assert "resolver_stale" in result.reasons


async def test_a_non_latest_version_is_rejected():
    w = world({"a": 1}, linked={"nextVersionId": "something-newer-exists"})
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(resolvers=[BASE], fetch=fetch_for(w), primitives=PRIMITIVES, now=lambda: NOW),
    )
    assert result.ok is False
    assert "not_latest_version" in result.reasons


async def test_an_oversized_resource_is_rejected_without_being_parsed():
    w = world({"a": 1})
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(
            resolvers=[BASE], fetch=fetch_for(w), primitives=PRIMITIVES, now=lambda: NOW, max_bytes=1
        ),
    )
    assert result.ok is False
    assert "resource_too_large" in result.reasons


async def test_http_resolvers_are_refused_unless_explicitly_allowed():
    w = world({"a": 1})
    result = await resolve_manifest(
        DID,
        KIND,
        NAME,
        ResolveManifestOptions(
            resolvers=["http://resolver.test/1.0/identifiers"],
            fetch=fetch_for(w),
            primitives=PRIMITIVES,
            now=lambda: NOW,
        ),
    )
    assert result.ok is False
    assert "resolver_not_https" in result.reasons


# --- create_manifest_cache -----------------------------------------------------------------


async def test_the_cache_serves_a_fresh_entry_without_re_fetching():
    w = world({"a": 1})
    fetch = fetch_for(w)
    cache = create_manifest_cache(
        ManifestCacheOptions(
            resolvers=[BASE], fetch=fetch, primitives=PRIMITIVES, now=lambda: NOW, default_ttl_ms=60_000
        )
    )
    await cache.get(DID, KIND, NAME)
    await cache.get(DID, KIND, NAME)
    assert fetch.calls["count"] == 2  # metadata + resource, once - the second get() hit the cache


async def test_the_cache_re_fetches_once_the_per_kind_ttl_has_elapsed():
    w = world({"a": 1})
    fetch = fetch_for(w)
    clock = {"value": NOW}
    cache = create_manifest_cache(
        ManifestCacheOptions(
            resolvers=[BASE],
            fetch=fetch,
            primitives=PRIMITIVES,
            now=lambda: clock["value"],
            ttl_ms_by_kind={KIND: 1000},
        )
    )
    await cache.get(DID, KIND, NAME)
    clock["value"] += 2000
    await cache.get(DID, KIND, NAME)
    assert fetch.calls["count"] == 4  # two full resolutions (metadata + resource each)


async def test_a_failed_resolution_is_cached_too_so_a_down_resolver_is_not_hammered_within_the_ttl():
    calls = {"count": 0}

    async def fetch(_url):
        calls["count"] += 1
        return ManifestResolverResponse(status=503, body=b"")

    cache = create_manifest_cache(
        ManifestCacheOptions(
            resolvers=[BASE], fetch=fetch, primitives=PRIMITIVES, now=lambda: NOW, default_ttl_ms=60_000
        )
    )
    first = await cache.get(DID, KIND, NAME)
    second = await cache.get(DID, KIND, NAME)
    assert first.ok is False
    assert first == second
    assert calls["count"] == 1


async def test_clear_drops_cached_entries():
    w = world({"a": 1})
    fetch = fetch_for(w)
    cache = create_manifest_cache(
        ManifestCacheOptions(
            resolvers=[BASE], fetch=fetch, primitives=PRIMITIVES, now=lambda: NOW, default_ttl_ms=60_000
        )
    )
    await cache.get(DID, KIND, NAME)
    cache.clear()
    await cache.get(DID, KIND, NAME)
    assert fetch.calls["count"] == 4


async def test_the_cache_evicts_the_oldest_entry_once_max_entries_is_reached():
    # Regression: the cache was an unbounded dict - expired entries are only ever overwritten on
    # the same key, never evicted, so a caller presenting a fresh, distinct resource_name per call
    # (e.g. an a2a trustConfigRef, which is caller-controlled) grows it by one entry per call,
    # forever. With max_entries=3, a 4th distinct key must evict the oldest rather than grow to 4.
    w = world({"a": 1})
    cache = create_manifest_cache(
        ManifestCacheOptions(
            resolvers=[BASE],
            fetch=fetch_for(w),
            primitives=PRIMITIVES,
            now=lambda: NOW,
            default_ttl_ms=60_000,
            max_entries=3,
        )
    )
    for i in range(10):
        await cache.get(DID, KIND, f"resource-{i}")
        assert cache.size() <= 3
    assert cache.size() == 3
