# SPDX-License-Identifier: Apache-2.0
# Tests for the DID-backed create_retrieve_public_key callback. did:key is pure computation,
# checked against a real generated Ed25519 keypair encoded by hand (no external test vector
# trusted blindly). did:web uses an injected fetch, so no network call is made.
import base64

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
