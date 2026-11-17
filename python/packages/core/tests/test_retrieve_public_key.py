# SPDX-License-Identifier: Apache-2.0
# Tests for the DID-backed create_retrieve_public_key callback. did:key is pure computation,
# checked against a real generated Ed25519 keypair encoded by hand (no external test vector
# trusted blindly). did:web uses an injected fetch, so no network call is made.
import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cheqd_agent_identity.agent_card.retrieve_public_key import (
    KeyResolutionError,
    MinimalDidDocument,
    MinimalVerificationMethod,
    create_retrieve_public_key,
)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    if len(data) == 0:
        return ""
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        out = BASE58_ALPHABET[remainder] + out
    leading_zeros = 0
    for byte in data:
        if byte != 0:
            break
        leading_zeros += 1
    return "1" * leading_zeros + out


def multibase_for(public_key_bytes: bytes) -> str:
    return "z" + base58_encode(b"\xed\x01" + public_key_bytes)


def did_key_for(public_key_bytes: bytes) -> str:
    return f"did:key:{multibase_for(public_key_bytes)}"


def raw_ed25519_public_key() -> tuple[bytes, str]:
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk_x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return raw, jwk_x


async def test_did_key_resolves_to_the_correct_jwk_computed_from_the_did_itself():
    raw, jwk_x = raw_ed25519_public_key()
    did = did_key_for(raw)
    retrieve = create_retrieve_public_key()
    jwk = await retrieve(f"{did}#{multibase_for(raw)}", None)
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["x"] == jwk_x


async def test_did_key_with_a_malformed_fragment_is_rejected():
    raw, _ = raw_ed25519_public_key()
    did = did_key_for(raw)
    retrieve = create_retrieve_public_key()
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#not-the-right-fragment", None)


async def test_an_attacker_supplied_jku_is_never_read():
    raw, jwk_x = raw_ed25519_public_key()
    did = did_key_for(raw)
    retrieve = create_retrieve_public_key()
    kid = f"{did}#{did[len('did:key:') :]}"
    jwk = await retrieve(kid, "https://attacker.example/jwks.json")
    assert jwk["x"] == jwk_x


async def test_a_kid_belonging_to_a_different_did_than_expected_did_is_rejected_before_any_resolution():
    raw, _ = raw_ed25519_public_key()
    did = did_key_for(raw)
    retrieve = create_retrieve_public_key(expected_did="did:key:someone-else")
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#{did[len('did:key:') :]}", None)


async def test_did_web_fetches_the_well_known_document_via_the_injected_fetch_never_the_network():
    _, jwk_x = raw_ed25519_public_key()
    did = "did:web:example.com"
    kid = f"{did}#key-1"
    fetched_url = {}

    class Response:
        status_code = 200

        def json(self):
            return {
                "id": did,
                "verificationMethod": [
                    {
                        "id": kid,
                        "controller": did,
                        "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": jwk_x},
                    }
                ],
            }

    async def fetch_did_web_document(url):
        fetched_url["url"] = url
        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    jwk = await retrieve(kid, None)
    assert fetched_url["url"] == "https://example.com/.well-known/did.json"
    assert jwk["x"] == jwk_x


async def test_did_web_with_a_path_component_builds_the_path_based_url():
    did = "did:web:example.com:users:alice"
    fetched_url = {}

    class Response:
        status_code = 200

        def json(self):
            return {"id": did, "verificationMethod": []}

    async def fetch_did_web_document(url):
        fetched_url["url"] = url
        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)  # no matching method, but the URL build is what's under test
    assert fetched_url["url"] == "https://example.com/users/alice/did.json"


async def test_a_did_web_document_whose_id_does_not_match_the_requested_did_is_rejected():
    did = "did:web:example.com"

    class Response:
        status_code = 200

        def json(self):
            return {"id": "did:web:attacker.example", "verificationMethod": []}

    async def fetch_did_web_document(_url):
        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)


async def test_did_web_host_with_a_percent_encoded_port_resolves_to_host_port():
    did = "did:web:example.com%3A3000"
    fetched_url = {}

    class Response:
        status_code = 200

        def json(self):
            return {"id": did, "verificationMethod": []}

    async def fetch_did_web_document(url):
        fetched_url["url"] = url
        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):  # no matching method; the URL build is what's under test
        await retrieve(f"{did}#key-1", None)
    assert fetched_url["url"] == "https://example.com:3000/.well-known/did.json"


async def test_a_did_web_host_that_decodes_to_an_authority_confusing_string_is_rejected_before_any_fetch():
    # Regression: the decoded host segment used to be inserted into the fetch URL with no
    # validation. %3A443%40 decodes to :443@, so this DID's "host" segment becomes
    # trusted.example:443@attacker.example - a real HTTP client sends the request to
    # attacker.example (everything before the unescaped @ is userinfo), while the raw DID
    # string still reads as if it names trusted.example. The attack is mechanically real: a
    # real client parses that authority as attacker.example, not trusted.example.
    confusing_url = httpx.URL("https://trusted.example:443@attacker.example/.well-known/did.json")
    assert confusing_url.host == "attacker.example"

    did = "did:web:trusted.example%3A443%40attacker.example"
    fetch_called = {"value": False}

    class Response:
        status_code = 200

        def json(self):
            return {}

    async def fetch_did_web_document(_url):
        fetch_called["value"] = True
        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert fetch_called["value"] is False, (
        "must reject before ever attempting to fetch the attacker-controlled host"
    )


async def test_a_did_web_host_that_decodes_to_a_path_like_string_is_rejected_before_any_fetch():
    did = "did:web:example.com%2Fattacker.example"
    fetch_called = {"value": False}

    class Response:
        status_code = 200

        def json(self):
            return {}

    async def fetch_did_web_document(_url):
        fetch_called["value"] = True
        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert fetch_called["value"] is False


def _oversized_but_otherwise_valid_did_web_document(did: str, kid: str, jwk_x: str) -> bytes:
    # Deliberately well-formed and resolvable if read in full (just padded past the 1 MiB cap) -
    # not malformed or truncated. Isolates the size cap as the only possible rejection reason;
    # a malformed oversized body would "pass" against pre-fix code for the wrong reason.
    return json.dumps(
        {
            "id": did,
            "verificationMethod": [
                {"id": kid, "controller": did, "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": jwk_x}}
            ],
            "padding": "x" * (2 * 1024 * 1024),
        }
    ).encode("utf-8")


async def test_the_default_did_web_fetch_rejects_an_oversized_response_even_with_an_accurate_content_length(
    monkeypatch,
):
    _, jwk_x = raw_ed25519_public_key()
    did = "did:web:example.com"
    kid = f"{did}#key-1"
    body = _oversized_but_otherwise_valid_did_web_document(did, kid, jwk_x)

    def handler(request):
        return httpx.Response(200, content=body)  # httpx sets an accurate Content-Length itself

    transport = httpx.MockTransport(handler)
    original_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **kw: original_async_client(*a, transport=transport, **kw)
    )

    retrieve = create_retrieve_public_key()
    with pytest.raises(KeyResolutionError):
        await retrieve(kid, None)


async def test_the_default_did_web_fetch_rejects_an_oversized_response_with_no_content_length_by_counting_bytes_read(
    monkeypatch,
):
    _, jwk_x = raw_ed25519_public_key()
    did = "did:web:example.com"
    kid = f"{did}#key-1"
    body = _oversized_but_otherwise_valid_did_web_document(did, kid, jwk_x)

    def handler(request):
        response = httpx.Response(200, content=body)
        del response.headers["content-length"]
        return response

    transport = httpx.MockTransport(handler)
    original_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **kw: original_async_client(*a, transport=transport, **kw)
    )

    retrieve = create_retrieve_public_key()
    with pytest.raises(KeyResolutionError):
        await retrieve(kid, None)


async def test_a_did_web_fetch_failure_non_200_is_rejected_not_treated_as_no_key():
    did = "did:web:example.com"

    class Response:
        status_code = 404

        def json(self):
            return {}

    async def fetch_did_web_document(_url):
        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)


async def test_did_cheqd_is_rejected_by_default_no_resolver_configured_fails_closed():
    retrieve = create_retrieve_public_key()
    with pytest.raises(KeyResolutionError):
        await retrieve("did:cheqd:testnet:abc#key-1", None)


async def test_did_cheqd_resolves_via_the_injected_resolver_when_configured():
    did = "did:cheqd:testnet:abc"
    kid = f"{did}#key-1"

    async def resolve_did_cheqd(requested):
        if requested != did:
            return None
        return MinimalDidDocument(
            id=did,
            verification_method=(
                MinimalVerificationMethod(
                    id=kid, public_key_jwk={"kty": "OKP", "crv": "Ed25519", "x": "abc"}
                ),
            ),
        )

    retrieve = create_retrieve_public_key(resolve_did_cheqd=resolve_did_cheqd)
    jwk = await retrieve(kid, None)
    assert jwk["x"] == "abc"


async def test_did_cheqd_resolves_a_legacy_ed25519verificationkey2018_public_key_base58_method():
    # The real public cheqd testnet resolver still serves this format on at least one live DID -
    # not a hypothetical shape.
    raw, jwk_x = raw_ed25519_public_key()
    did = "did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede"
    kid = f"{did}#key-1"

    async def resolve_did_cheqd(_requested):
        return MinimalDidDocument(
            id=did,
            verification_method=(
                MinimalVerificationMethod(id=kid, controller=did, public_key_base58=base58_encode(raw)),
            ),
        )

    retrieve = create_retrieve_public_key(resolve_did_cheqd=resolve_did_cheqd)
    jwk = await retrieve(kid, None)
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["x"] == jwk_x


async def test_did_cheqd_rejects_a_public_key_base58_that_does_not_decode_to_a_32_byte_ed25519_key():
    did = "did:cheqd:testnet:abc"
    kid = f"{did}#key-1"

    async def resolve_did_cheqd(_requested):
        return MinimalDidDocument(
            id=did,
            verification_method=(
                MinimalVerificationMethod(id=kid, public_key_base58=base58_encode(bytes(16))),
            ),
        )

    retrieve = create_retrieve_public_key(resolve_did_cheqd=resolve_did_cheqd)
    with pytest.raises(KeyResolutionError):
        await retrieve(kid, None)


async def test_an_unsupported_did_method_is_rejected():
    retrieve = create_retrieve_public_key()
    with pytest.raises(KeyResolutionError):
        await retrieve("did:example:123#key-1", None)


async def test_a_kid_with_no_fragment_is_rejected():
    retrieve = create_retrieve_public_key()
    with pytest.raises(KeyResolutionError):
        await retrieve("did:web:example.com", None)
