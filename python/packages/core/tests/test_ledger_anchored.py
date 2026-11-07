# SPDX-License-Identifier: Apache-2.0
# Tests for the ledger-anchored status check, against a fake resolver that mimics the public
# cheqd resolver's responses.
import gzip
import hashlib
import json
from base64 import urlsafe_b64encode
from datetime import datetime, timezone

from cheqd_agent_identity.status.ledger_anchored import (
    LedgerAnchoredStatusOptions,
    StatusEntry,
    StatusListPrimitives,
    StatusListResponse,
    verify_ledger_anchored_status,
)

NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1000
COLLECTION = "0c3581f0-011f-4263-b1ca-15ad70d54ede"
DID = f"did:cheqd:testnet:{COLLECTION}"
NAME = "agent-revocations"
RESOURCE_ID = "1a79a313-8fc3-421c-af3d-34730fa046d1"
BASE = "https://resolver.test/1.0/identifiers"
ENTRY = StatusEntry(
    status_list_credential=f"{BASE}/{DID}?resourceName={NAME}&resourceType=BitstringStatusListCredential#41260",
    status_list_index="41260",
    status_purpose="revocation",
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _gunzip(data: bytes, max_bytes: int) -> bytes:
    out = gzip.decompress(data)
    if len(out) > max_bytes:
        raise ValueError("output too large")
    return out


def _decode_utf8(data: bytes) -> str:
    return data.decode("utf-8")


PRIMITIVES = StatusListPrimitives(sha256_hex=_sha256_hex, gunzip=_gunzip, decode_utf8=_decode_utf8)


def _b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii")


def encode_list(entries: int, set_bits: list[int] | None = None) -> str:
    set_bits = set_bits or []
    bits = bytearray(entries // 8)
    for index in set_bits:
        bits[index // 8] |= 0x80 >> (index % 8)
    return _b64url(gzip.compress(bytes(bits)))


def world(**opts) -> dict:
    """Build the world a resolver would serve. Each option mutates one thing, to make one
    failure."""
    entries = opts.get("entries", 131072)
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": DID,
        "issuanceDate": "2026-10-01T00:00:00Z",
        "credentialSubject": {
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": opts.get("encodedList", encode_list(entries, opts.get("setBits", []))),
        },
        "proof": {"type": "JwtProof2020", "jwt": "header.payload.signature"},
        **opts.get("credential", {}),
    }
    credential["credentialSubject"].update(opts.get("subject", {}))
    record = {
        "bitstringStatusListCredential": credential,
        "metadata": {
            "encrypted": False,
            "encoding": "base64url",
            "length": entries,
            "statusSize": 1,
            **opts.get("metadata", {}),
        },
    }
    raw_bytes = opts.get("rawBytes")
    body_bytes = raw_bytes if raw_bytes is not None else json.dumps(record).encode("utf-8")
    checksum = opts.get("checksum", _sha256_hex(raw_bytes if raw_bytes is not None else body_bytes))
    linked = {
        "resourceURI": f"{DID}/resources/{RESOURCE_ID}",
        "resourceCollectionId": COLLECTION,
        "resourceId": RESOURCE_ID,
        "resourceName": NAME,
        "resourceType": "BitstringStatusListCredential",
        "mediaType": "application/json",
        "resourceVersion": "2026-10-01T00:00:00Z",
        "created": "2026-10-01T00:00:00Z",
        "checksum": checksum,
        "previousVersionId": None,
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


def fetch_for(worlds: dict, seen: list | None = None):
    """A fetch that serves one world per resolver base, recording every URL requested."""
    seen = seen if seen is not None else []

    async def fetch(url: str) -> StatusListResponse:
        seen.append(url)
        base = next((b for b in worlds if url.startswith(b)), None)
        w = worlds.get(base) if base is not None else None
        if w is None or w == "down":
            raise ConnectionError("network")
        if isinstance(w, dict) and "status" in w:
            return StatusListResponse(status=w["status"], body=b"")
        if "resourceMetadata=true" in url:
            return StatusListResponse(status=200, body=json.dumps(w["meta"]).encode("utf-8"))
        if "/resources/" in url:
            return StatusListResponse(status=200, body=w["bytes"])
        return StatusListResponse(status=404, body=b"")

    return fetch


async def check(w, overrides=None, entry=ENTRY, issuer=DID):
    overrides = overrides or {}
    base_options = {
        "resolvers": [BASE],
        "fetch": fetch_for({BASE: w}),
        "primitives": PRIMITIVES,
        "now": lambda: NOW,
    }
    base_options.update(overrides)
    options = LedgerAnchoredStatusOptions(**base_options)
    return await verify_ledger_anchored_status(entry, issuer, options)


def rejected(result, reason):
    assert result.ok is False, f"expected rejection, got {result}"
    assert reason in result.reasons, f"expected {reason}, got {result.reasons}"


async def test_a_clear_bit_reads_as_not_revoked():
    result = await check(world(setBits=[7]))
    assert result.ok is True
    assert result.revoked is False
    assert result.resource_id == RESOURCE_ID


async def test_a_set_bit_reads_as_revoked_bit_order_is_msb_first_within_a_byte():
    result = await check(world(setBits=[41260]))
    assert result.ok is True
    assert result.revoked is True


async def test_only_the_named_index_is_read():
    result = await check(world(setBits=[41259, 41261]))
    assert result.ok and result.revoked is False


async def test_the_checksum_must_match_the_bytes_returned():
    good = world(setBits=[1])
    tampered = world(setBits=[41260], checksum=_sha256_hex(good["bytes"]))
    rejected(await check(tampered), "checksum_mismatch")


async def test_a_resolver_serving_different_bytes_than_it_described_is_rejected():
    claimed = world(setBits=[])
    served = world(setBits=[41260])
    rejected(await check({"meta": claimed["meta"], "bytes": served["bytes"]}), "checksum_mismatch")


async def test_an_older_version_a_newer_one_exists_is_rejected():
    rejected(
        await check(world(linked={"nextVersionId": "ffffffff-ffff-ffff-ffff-ffffffffffff"})),
        "not_latest_version",
    )


async def test_a_stale_resolver_reply_is_rejected():
    rejected(await check(world(retrievedAt=NOW - 10 * 60_000)), "resolver_stale")


async def test_a_resource_from_another_collection_is_rejected():
    rejected(
        await check(world(linked={"resourceCollectionId": "99999999-9999-4999-8999-999999999999"})),
        "collection_mismatch",
    )


async def test_a_list_issued_by_a_different_did_is_rejected():
    rejected(
        await check(world(credential={"issuer": "did:cheqd:testnet:99999999-9999-4999-8999-999999999999"})),
        "issuer_mismatch",
    )


async def test_an_entry_whose_list_is_under_a_different_did_than_the_expected_issuer_is_rejected():
    rejected(
        await check(world(), None, ENTRY, "did:cheqd:testnet:99999999-9999-4999-8999-999999999999"),
        "issuer_mismatch",
    )


async def test_a_purpose_mismatch_is_rejected():
    entry = StatusEntry(ENTRY.status_list_credential, ENTRY.status_list_index, "suspension")
    rejected(await check(world(), None, entry), "purpose_mismatch")


async def test_an_out_of_range_index_is_rejected():
    entry = StatusEntry(ENTRY.status_list_credential, "131072", ENTRY.status_purpose)
    rejected(await check(world(), None, entry), "index_out_of_range")


async def test_non_canonical_indexes_are_rejected_never_read_as_another_bit():
    for index in ["0x2A", " 1", "+1", "1e1", "-1", "1.5", ""]:
        entry = StatusEntry(ENTRY.status_list_credential, index, ENTRY.status_purpose)
        rejected(await check(world(), None, entry), "invalid_status_list_index")


async def test_a_list_shorter_than_the_privacy_floor_is_rejected():
    rejected(await check(world(entries=1024)), "list_too_short")


async def test_an_oversized_inflated_list_is_rejected_not_inflated():
    rejected(
        await check(world(encodedList=_b64url(gzip.compress(bytes(40 * 1024 * 1024))))), "resolver_error"
    )


async def test_an_encrypted_list_is_rejected():
    rejected(await check(world(metadata={"encrypted": True})), "encrypted_list_unsupported")


async def test_cheqds_default_of_two_bits_per_entry_is_rejected():
    rejected(await check(world(metadata={"statusSize": 2})), "unsupported_status_size")
    entry = StatusEntry(
        ENTRY.status_list_credential, ENTRY.status_list_index, ENTRY.status_purpose, status_size=2
    )
    rejected(await check(world(), None, entry), "unsupported_status_size")


async def test_an_expired_list_is_rejected():
    rejected(await check(world(credential={"validUntil": "2026-10-01T00:00:00Z"})), "list_expired")


async def test_invalid_json_is_rejected():
    body_bytes = b"not json"
    w = world(checksum=_sha256_hex(body_bytes))
    rejected(await check({"meta": w["meta"], "bytes": body_bytes}), "invalid_json")


async def test_the_old_status_list_2021_data_record_is_not_supported():
    body_bytes = json.dumps(
        {
            "StatusList2021": {
                "statusPurpose": "revocation",
                "encodedList": "H4sIAAAAAAAAA-3BAQ0AAADCoPdPbQ8HFAAAAAAAAAAAAAAAAAAAAADwaDhDr_xcRAAA",
                "validFrom": "2023-09-22T09:47:02.025Z",
            },
            "metadata": {"type": "StatusList2021Revocation", "encrypted": False},
        }
    ).encode("utf-8")
    w = world(checksum=_sha256_hex(body_bytes))
    rejected(await check({"meta": w["meta"], "bytes": body_bytes}), "malformed_resource")


async def test_an_unavailable_resolver_is_rejected():
    rejected(await check({"status": 503}), "metadata_unavailable")
    rejected(await check("down"), "resolver_error")


async def test_a_missing_or_ambiguous_resource_is_rejected():
    rejected(await check(world(linkedList=[])), "ambiguous_or_missing_resource")
    two = world()
    linked = two["meta"]["contentMetadata"]["linkedResourceMetadata"][0]
    rejected(await check(world(linkedList=[linked, linked])), "ambiguous_or_missing_resource")


async def test_the_host_in_the_credentials_url_is_never_fetched():
    seen: list[str] = []
    entry = StatusEntry(
        f"https://attacker.example/1.0/identifiers/{DID}?resourceName={NAME}&resourceType=BitstringStatusListCredential",
        ENTRY.status_list_index,
        ENTRY.status_purpose,
    )
    await verify_ledger_anchored_status(
        entry,
        DID,
        LedgerAnchoredStatusOptions(
            resolvers=[BASE], fetch=fetch_for({BASE: world()}, seen), primitives=PRIMITIVES, now=lambda: NOW
        ),
    )
    assert len(seen) > 0 and all(url.startswith(BASE) for url in seen), f"fetched {seen}"


async def test_lists_by_resource_id_or_from_other_did_methods_are_rejected():
    entry_a = StatusEntry(f"{DID}/resources/{RESOURCE_ID}", ENTRY.status_list_index, ENTRY.status_purpose)
    rejected(await check(world(), None, entry_a), "unsupported_list_reference")
    entry_b = StatusEntry("https://example.com/status/1", ENTRY.status_list_index, ENTRY.status_purpose)
    rejected(await check(world(), None, entry_b), "not_a_cheqd_list")


async def test_http_resolvers_are_refused_unless_explicitly_allowed():
    insecure = "http://resolver.test/1.0/identifiers"
    options = {
        "resolvers": [insecure],
        "fetch": fetch_for({insecure: world()}),
        "primitives": PRIMITIVES,
        "now": lambda: NOW,
    }
    rejected(
        await verify_ledger_anchored_status(ENTRY, DID, LedgerAnchoredStatusOptions(**options)),
        "resolver_not_https",
    )
    allowed = await verify_ledger_anchored_status(
        ENTRY, DID, LedgerAnchoredStatusOptions(**options, allow_insecure_resolvers=True)
    )
    assert allowed.ok is True


async def test_two_resolvers_that_agree_are_accepted_and_both_reported():
    b2 = "https://resolver-two.test/1.0/identifiers"
    w = world(setBits=[41260])
    result = await verify_ledger_anchored_status(
        ENTRY,
        DID,
        LedgerAnchoredStatusOptions(
            resolvers=[BASE, b2],
            fetch=fetch_for({BASE: w, b2: w}),
            primitives=PRIMITIVES,
            now=lambda: NOW,
            min_agreement=2,
        ),
    )
    assert result.ok and result.revoked is True
    assert len(result.resolvers) == 2


async def test_two_resolvers_that_disagree_are_rejected_even_when_one_says_revoked():
    b2 = "https://resolver-two.test/1.0/identifiers"
    result = await verify_ledger_anchored_status(
        ENTRY,
        DID,
        LedgerAnchoredStatusOptions(
            resolvers=[BASE, b2],
            fetch=fetch_for({BASE: world(), b2: world(setBits=[41260])}),
            primitives=PRIMITIVES,
            now=lambda: NOW,
        ),
    )
    rejected(result, "resolver_disagreement")


async def test_too_few_agreeing_resolvers_is_rejected_when_agreement_is_required():
    b2 = "https://resolver-two.test/1.0/identifiers"
    options = {
        "resolvers": [BASE, b2],
        "fetch": fetch_for({BASE: world(), b2: "down"}),
        "primitives": PRIMITIVES,
        "now": lambda: NOW,
    }
    rejected(
        await verify_ledger_anchored_status(
            ENTRY, DID, LedgerAnchoredStatusOptions(**options, min_agreement=2)
        ),
        "resolver_error",
    )
    result = await verify_ledger_anchored_status(
        ENTRY, DID, LedgerAnchoredStatusOptions(**options, min_agreement=1)
    )
    assert result.ok is True


async def test_asking_for_more_agreement_than_there_are_resolvers_is_rejected():
    rejected(await check(world(), {"min_agreement": 2}), "not_enough_resolvers")
