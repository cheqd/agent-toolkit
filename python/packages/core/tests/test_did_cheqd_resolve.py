# SPDX-License-Identifier: Apache-2.0
import pytest

from cheqd_agent_identity.agent_card.retrieve_public_key import KeyResolutionError, create_retrieve_public_key
from cheqd_agent_identity.did_cheqd.resolve import create_did_cheqd_resolver

BASE = "https://resolver.test/1.0/identifiers"
DID = "did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede"
KID = f"{DID}#key-1"


def json_response(status, body):
    class Response:
        status_code = status

        def json(self):
            return body

    return Response()


async def test_resolves_a_universal_resolver_shaped_response_did_document():
    seen_url = {}

    async def fetch(url):
        seen_url["url"] = url
        return json_response(
            200,
            {
                "didDocument": {
                    "id": DID,
                    "verificationMethod": [
                        {"id": KID, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"}}
                    ],
                }
            },
        )

    resolve = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    doc = await resolve(DID)
    assert seen_url["url"] == f"{BASE}/{DID}"
    assert doc.id == DID
    assert doc.verification_method[0].id == KID


async def test_resolves_a_raw_did_document_no_wrapper():
    async def fetch(_url):
        return json_response(200, {"id": DID, "verificationMethod": []})

    resolve = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    doc = await resolve(DID)
    assert doc.id == DID


async def test_a_non_200_response_resolves_to_none_not_a_raise():
    async def fetch(_url):
        return json_response(404, {})

    resolve = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    assert await resolve(DID) is None


async def test_a_document_whose_id_does_not_match_the_requested_did_resolves_to_none():
    async def fetch(_url):
        return json_response(200, {"id": "did:cheqd:testnet:someone-else", "verificationMethod": []})

    resolve = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    assert await resolve(DID) is None


async def test_invalid_json_resolves_to_none_not_a_raise():
    class Response:
        status_code = 200

        def json(self):
            raise ValueError("bad json")

    async def fetch(_url):
        return Response()

    resolve = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    assert await resolve(DID) is None


async def test_a_non_did_cheqd_did_is_rejected_before_any_fetch():
    called = {"value": False}

    async def fetch(_url):
        called["value"] = True
        return json_response(200, {})

    resolve = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    assert await resolve("did:web:example.com") is None
    assert called["value"] is False


async def test_a_network_failure_resolves_to_none_not_a_raise():
    async def fetch(_url):
        raise ConnectionError("ECONNREFUSED")

    resolve = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    assert await resolve(DID) is None


# --- wired into create_retrieve_public_key's opt-in slot ---------------------------------------


async def test_wired_into_create_retrieve_public_key_a_did_cheqd_kid_resolves_end_to_end():
    async def fetch(_url):
        return json_response(
            200,
            {
                "id": DID,
                "verificationMethod": [
                    {"id": KID, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"}}
                ],
            },
        )

    resolve_did_cheqd = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    retrieve = create_retrieve_public_key(resolve_did_cheqd=resolve_did_cheqd)
    jwk = await retrieve(KID, None)
    assert jwk["x"] == "abc"


async def test_wired_into_create_retrieve_public_key_a_did_cheqd_resolver_failure_is_rejected():
    async def fetch(_url):
        return json_response(404, {})

    resolve_did_cheqd = create_did_cheqd_resolver(resolver_url=BASE, fetch=fetch)
    retrieve = create_retrieve_public_key(resolve_did_cheqd=resolve_did_cheqd)
    with pytest.raises(KeyResolutionError):
        await retrieve(KID, None)
