# SPDX-License-Identifier: Apache-2.0
# Unit tests for verify_trust_extension/create_trust_extension_cache: fakes
# resolve_did_document, manifest_cache and check_status directly rather than exercising
# cheqd_agent_identity's own building blocks again (those are tested in packages/core).
from cheqd_agent_identity.dlr.resolve_manifest import ResolveManifestFailed, ResolveManifestOk
from cheqd_agent_identity.linkage.reciprocal_linkage import LinkageDidDocument

from cheqd_agent_identity_a2a.trust_extension import (
    TrustExtensionActivation,
    TrustExtensionDeps,
    create_trust_extension_cache,
    verify_trust_extension,
)

CANONICAL = "did:web:server.example"
ANCHORED = "did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede"


class FakeManifestCache:
    def __init__(self, result=None):
        self.result = result or ResolveManifestOk(
            content=None, resource_id="", checksum="", resource_version="", resolvers=()
        )
        self.calls = 0

    async def get(self, did, kind, resource_name):
        self.calls += 1
        return self.result

    def clear(self):
        pass


async def test_an_activation_with_nothing_declared_passes_trivially():
    async def resolve_did_document(_did):
        return None

    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=FakeManifestCache())
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(), deps)
    assert result.ok is True


async def test_reciprocal_linkage_is_checked_when_anchored_did_is_declared():
    docs = {
        CANONICAL: LinkageDidDocument(id=CANONICAL, also_known_as=[ANCHORED]),
        ANCHORED: LinkageDidDocument(id=ANCHORED, also_known_as=[CANONICAL]),
    }

    async def resolve_did_document(did):
        return docs.get(did)

    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=FakeManifestCache())
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(anchored_did=ANCHORED), deps)
    assert result.ok is True


async def test_a_one_directional_linkage_claim_fails_closed():
    docs = {
        CANONICAL: LinkageDidDocument(id=CANONICAL, also_known_as=[ANCHORED]),
        ANCHORED: LinkageDidDocument(id=ANCHORED, also_known_as=[]),
    }

    async def resolve_did_document(did):
        return docs.get(did)

    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=FakeManifestCache())
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(anchored_did=ANCHORED), deps)
    assert result.ok is False
    assert any(r.startswith("linkage_") for r in result.reasons)


async def test_a_manifest_resolution_failure_fails_closed():
    ref = f"{ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest"

    async def resolve_did_document(_did):
        return LinkageDidDocument(id=CANONICAL)

    deps = TrustExtensionDeps(
        resolve_did_document=resolve_did_document,
        manifest_cache=FakeManifestCache(ResolveManifestFailed(reasons=("resource_unavailable",))),
    )
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(trust_config_ref=ref), deps)
    assert result.ok is False
    assert result.reasons == ("manifest_resource_unavailable",)


async def test_a_malformed_trust_config_ref_fails_closed_without_calling_the_manifest_cache():
    async def resolve_did_document(_did):
        return None

    cache = FakeManifestCache()
    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=cache)
    result = await verify_trust_extension(
        CANONICAL, TrustExtensionActivation(trust_config_ref="not-a-ref"), deps
    )
    assert result.ok is False
    assert cache.calls == 0


async def test_status_check_required_fails_closed_when_no_checker_is_configured():
    async def resolve_did_document(_did):
        return None

    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=FakeManifestCache())
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(status_check="required"), deps)
    assert result.ok is False
    assert result.reasons == ("status_check_unavailable",)


async def test_status_check_required_fails_closed_on_a_revoked_or_stale_result():
    async def resolve_did_document(_did):
        return None

    async def check_status(_did):
        return (True, True)

    deps = TrustExtensionDeps(
        resolve_did_document=resolve_did_document,
        manifest_cache=FakeManifestCache(),
        check_status=check_status,
    )
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(status_check="required"), deps)
    assert result.ok is False
    assert result.reasons == ("status_revoked",)


async def test_status_check_required_passes_when_the_status_is_clear_and_fresh():
    async def resolve_did_document(_did):
        return None

    async def check_status(_did):
        return (False, True)

    deps = TrustExtensionDeps(
        resolve_did_document=resolve_did_document,
        manifest_cache=FakeManifestCache(),
        check_status=check_status,
    )
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(status_check="required"), deps)
    assert result.ok is True


async def test_create_trust_extension_cache_serves_a_fresh_entry_without_re_checking():
    async def resolve_did_document(_did):
        return None

    cache_backend = FakeManifestCache()
    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=cache_backend)
    ref = f"{ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest"
    cache = create_trust_extension_cache(deps, ttl_ms=60_000)
    await cache.get(CANONICAL, TrustExtensionActivation(trust_config_ref=ref))
    await cache.get(CANONICAL, TrustExtensionActivation(trust_config_ref=ref))
    assert cache_backend.calls == 1


async def test_create_trust_extension_cache_re_checks_once_the_ttl_has_elapsed():
    async def resolve_did_document(_did):
        return None

    cache_backend = FakeManifestCache()
    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=cache_backend)
    ref = f"{ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest"
    clock = {"value": 0.0}
    cache = create_trust_extension_cache(deps, ttl_ms=1000, now=lambda: clock["value"])
    await cache.get(CANONICAL, TrustExtensionActivation(trust_config_ref=ref))
    clock["value"] = 1001
    await cache.get(CANONICAL, TrustExtensionActivation(trust_config_ref=ref))
    assert cache_backend.calls == 2
