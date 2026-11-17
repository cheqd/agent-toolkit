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

    # did-aware and reciprocal, so the (now-enforced) linkage checks pass trivially and the
    # only failure surfacing is the manifest one this test is about.
    async def resolve_did_document(did):
        return LinkageDidDocument(id=did, also_known_as=[ANCHORED if did == CANONICAL else CANONICAL])

    deps = TrustExtensionDeps(
        resolve_did_document=resolve_did_document,
        manifest_cache=FakeManifestCache(ResolveManifestFailed(reasons=("resource_unavailable",))),
    )
    # anchored_did must be declared (and match the ref's did) now that trust_config_ref is bound to it.
    result = await verify_trust_extension(
        CANONICAL, TrustExtensionActivation(anchored_did=ANCHORED, trust_config_ref=ref), deps
    )
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
    # anchored_did must match the ref's did now that trust_config_ref is bound to it.
    activation = TrustExtensionActivation(anchored_did=ANCHORED, trust_config_ref=ref)
    await cache.get(CANONICAL, activation)
    await cache.get(CANONICAL, activation)
    assert cache_backend.calls == 1


async def test_create_trust_extension_cache_re_checks_once_the_ttl_has_elapsed():
    async def resolve_did_document(_did):
        return None

    cache_backend = FakeManifestCache()
    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=cache_backend)
    ref = f"{ANCHORED}?resourceName=TrustConfig&resourceType=TrustConfigManifest"
    clock = {"value": 0.0}
    cache = create_trust_extension_cache(deps, ttl_ms=1000, now=lambda: clock["value"])
    # anchored_did must match the ref's did now that trust_config_ref is bound to it.
    activation = TrustExtensionActivation(anchored_did=ANCHORED, trust_config_ref=ref)
    await cache.get(CANONICAL, activation)
    clock["value"] = 1001
    await cache.get(CANONICAL, activation)
    assert cache_backend.calls == 2


# Regression: verify_trust_extension used to trust resolve_did_document's result purely on the
# basis that SOMETHING resolved - verify_reciprocal_linkage only compares the two returned
# documents against each other, never against the DIDs actually requested. A lax/generic
# resolver (e.g. over did:web) could return a document whose `id` names the OTHER party's DID -
# e.g. an attacker's did:web document declaring `id: <victim's anchored DID>` - and inherit that
# victim's linkage. Each resolved document's own `id` must equal the DID this module actually
# asked for.
async def test_a_resolved_document_whose_id_does_not_match_the_requested_did_fails_closed():
    attacker_canonical = "did:web:attacker.example"
    docs = {
        # The attacker's resolver returns a document claiming the VICTIM's canonical DID as its
        # own id, with also_known_as pointing at ANCHORED - reciprocal with ANCHORED's own
        # document, so verify_reciprocal_linkage alone would accept this.
        attacker_canonical: LinkageDidDocument(id=CANONICAL, also_known_as=[ANCHORED]),
        ANCHORED: LinkageDidDocument(id=ANCHORED, also_known_as=[CANONICAL]),
    }

    async def resolve_did_document(did):
        return docs.get(did)

    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=FakeManifestCache())
    result = await verify_trust_extension(
        attacker_canonical, TrustExtensionActivation(anchored_did=ANCHORED), deps
    )
    assert result.ok is False
    assert "linkage_resolved_doc_id_mismatch" in result.reasons


async def test_a_resolved_anchored_document_whose_id_does_not_match_anchored_did_fails_closed():
    docs = {
        CANONICAL: LinkageDidDocument(id=CANONICAL, also_known_as=[ANCHORED]),
        # Resolver answers for ANCHORED's DID but hands back a document claiming to be some
        # other DID entirely.
        ANCHORED: LinkageDidDocument(
            id="did:cheqd:testnet:00000000-0000-0000-0000-000000000000", also_known_as=[CANONICAL]
        ),
    }

    async def resolve_did_document(did):
        return docs.get(did)

    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=FakeManifestCache())
    result = await verify_trust_extension(CANONICAL, TrustExtensionActivation(anchored_did=ANCHORED), deps)
    assert result.ok is False
    assert "linkage_resolved_doc_id_mismatch" in result.reasons


# Regression: the manifest check only verified that trust_config_ref's did:cheqd resolved with
# a matching checksum - never that it belonged to the right DID. An attacker who is not
# ANCHORED at all could declare a trust_config_ref pointing at a third-party DID's
# perfectly-valid manifest and have it accepted as if it were the caller's own trust config.
async def test_a_trust_config_ref_pointing_at_a_did_other_than_anchored_did_fails_closed():
    other_did = "did:cheqd:testnet:11111111-1111-1111-1111-111111111111"
    ref = f"{other_did}?resourceName=TrustConfig&resourceType=TrustConfigManifest"

    async def resolve_did_document(did):
        return LinkageDidDocument(id=did, also_known_as=[ANCHORED if did == CANONICAL else CANONICAL])

    cache = FakeManifestCache()
    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=cache)
    result = await verify_trust_extension(
        CANONICAL, TrustExtensionActivation(anchored_did=ANCHORED, trust_config_ref=ref), deps
    )
    assert result.ok is False
    assert "manifest_did_mismatch" in result.reasons
    assert cache.calls == 0


# Same binding, no anchored_did declared: the manifest must then belong to the canonical DID
# itself (there is no other DID this check is being run for).
async def test_a_trust_config_ref_pointing_at_a_did_other_than_canonical_did_fails_closed_without_anchored_did():
    other_did = "did:cheqd:testnet:22222222-2222-2222-2222-222222222222"
    ref = f"{other_did}?resourceName=TrustConfig&resourceType=TrustConfigManifest"

    async def resolve_did_document(_did):
        return None

    cache = FakeManifestCache()
    deps = TrustExtensionDeps(resolve_did_document=resolve_did_document, manifest_cache=cache)
    result = await verify_trust_extension(
        "did:cheqd:testnet:0000000000000000aaaaaaaaaaaaaaaa",
        TrustExtensionActivation(trust_config_ref=ref),
        deps,
    )
    assert result.ok is False
    assert "manifest_did_mismatch" in result.reasons
    assert cache.calls == 0


# Regression: the Python cache (#36 ported from TS) used to be an unbounded dict - every
# (canonical_did, activation) lookup cached its result forever, regardless of outcome. A caller
# presenting a fresh self-asserted DID per request (cheap: one keypair) and failing the trust
# check every time would grow the cache without bound - a memory-exhaustion DoS vector.
# max_entries caps the entry count, evicting the oldest entry to make room for a new key.
async def test_the_cache_is_bounded_distinct_canonical_dids_beyond_max_entries_evict_the_oldest():
    async def resolve_did_document(_did):
        return None

    async def check_status(_did):
        return (False, True)

    deps = TrustExtensionDeps(
        resolve_did_document=resolve_did_document,
        manifest_cache=FakeManifestCache(),
        check_status=check_status,
    )
    cache = create_trust_extension_cache(deps, max_entries=3)
    for i in range(10):
        await cache.get(f"did:example:caller-{i}", TrustExtensionActivation(status_check="required"))
        assert cache.size() <= 3, f"size {cache.size()} exceeded max_entries after caller-{i}"
    assert cache.size() == 3
