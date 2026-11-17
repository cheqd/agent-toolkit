# SPDX-License-Identifier: Apache-2.0
# Tests for the DID-backed create_retrieve_public_key callback. did:key is pure computation,
# checked against a real generated Ed25519 keypair encoded by hand (no external test vector
# trusted blindly). did:web uses an injected fetch, so no network call is made.
import asyncio
import base64
import time

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


# Regression: _did_web_to_url used to percent-decode each segment and concatenate it straight
# into a URL f-string with no re-validation. A decoded segment containing '@' is read by a real
# URL parser as an authority separator: `good.example.com@internal-host` becomes userinfo
# `good.example.com` (discarded) plus host `internal-host` - an SSRF primitive letting a
# did:web value that superficially names one host actually direct the fetch at a different one.
# Asserts the fetch is never even attempted, so this cannot pass for the unrelated reason that
# an otherwise-successful fetch returns no matching key.
async def test_a_did_web_segment_that_decodes_to_an_at_sign_is_rejected():
    did = "did:web:good.example.com%40internal-host"
    called = {"value": False}

    async def fetch_did_web_document(_url):
        called["value"] = True

        class Response:
            status_code = 200

            def json(self):
                return {"id": did, "verificationMethod": []}

        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert called["value"] is False, "must be rejected before any fetch is attempted"


# Regression: a decoded '#' is a fragment separator to a real URL parser - it silently
# truncates the path actually sent to the server, a corruption of the same root cause.
async def test_a_did_web_segment_that_decodes_to_a_hash_is_rejected():
    did = "did:web:example.com:a%23b"
    called = {"value": False}

    async def fetch_did_web_document(_url):
        called["value"] = True

        class Response:
            status_code = 200

            def json(self):
                return {"id": did, "verificationMethod": []}

        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert called["value"] is False, "must be rejected before any fetch is attempted"


# Regression: a decoded '/' blurs the host/path boundary the same way.
async def test_a_did_web_segment_that_decodes_to_a_slash_is_rejected():
    did = "did:web:example.com%2Fattacker-path"
    called = {"value": False}

    async def fetch_did_web_document(_url):
        called["value"] = True

        class Response:
            status_code = 200

            def json(self):
                return {"id": did, "verificationMethod": []}

        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert called["value"] is False, "must be rejected before any fetch is attempted"


# Regression (part of review finding #8 that belongs to this file: the did:web variant).
# _did_web_to_url did not reject '.' / '..' / empty segments, so a did:web value with a '..'
# segment is built into a URL a real URL parser (or an upstream server) normalizes away, letting
# `did:web:host:users:bob:..:alice` actually address alice's path while superficially naming
# bob's - a path-traversal/identity-confusion primitive on top of the #42 character denylist.
async def test_a_did_web_path_containing_a_dotdot_segment_is_rejected():
    did = "did:web:example.com:users:bob:..:alice"
    called = {"value": False}

    async def fetch_did_web_document(_url):
        called["value"] = True

        class Response:
            status_code = 200

            def json(self):
                return {"id": did, "verificationMethod": []}

        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert called["value"] is False, "must be rejected before any fetch is attempted"


async def test_a_did_web_path_containing_a_lone_dot_segment_is_rejected():
    did = "did:web:example.com:users:.:alice"
    called = {"value": False}

    async def fetch_did_web_document(_url):
        called["value"] = True

        class Response:
            status_code = 200

            def json(self):
                return {"id": did, "verificationMethod": []}

        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert called["value"] is False, "must be rejected before any fetch is attempted"


async def test_a_did_web_path_containing_an_empty_segment_is_rejected():
    did = "did:web:example.com:users::alice"
    called = {"value": False}

    async def fetch_did_web_document(_url):
        called["value"] = True

        class Response:
            status_code = 200

            def json(self):
                return {"id": did, "verificationMethod": []}

        return Response()

    retrieve = create_retrieve_public_key(fetch_did_web_document=fetch_did_web_document)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
    assert called["value"] is False, "must be rejected before any fetch is attempted"


async def test_a_did_web_fetch_that_never_resolves_is_rejected_once_the_timeout_elapses():
    did = "did:web:example.com"

    async def fetch_did_web_document(_url):
        await asyncio.sleep(3600)

    retrieve = create_retrieve_public_key(
        fetch_did_web_document=fetch_did_web_document, did_web_fetch_timeout_seconds=0.05
    )
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)


# Regression (review finding #3): _base58_decode did the big-int multiply-accumulate over the
# WHOLE input before any length check, and the kid is attacker-controlled (kid == did#multibase
# is trivially satisfied for did:key). Decode cost is quadratic in input length, so an oversized
# multibase value ties up the event loop. Asserts both the exact failure mode (eventually raises)
# and the exact symptom the review measured (wall-clock time), not merely that it raises - a
# slow-but-eventually-correct rejection would still be the vulnerability.
async def test_a_did_key_with_a_huge_base58_multibase_payload_is_rejected_quickly():
    # '1' is base58's lowest digit, but 'z' is the highest-value digit (57) - repeating it forces
    # the accumulator to grow on every character, the worst case for the quadratic decode cost.
    huge_encoded = "z" * 50_000
    multibase = f"z{huge_encoded}"
    did = f"did:key:{multibase}"
    retrieve = create_retrieve_public_key()
    started = time.monotonic()
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#{multibase}", None)
    elapsed_seconds = time.monotonic() - started
    assert elapsed_seconds < 0.2, f"expected rejection well under 200ms, took {elapsed_seconds * 1000:.1f}ms"


# Regression (review finding #5, Python side): the review states httpx.AsyncClient() already
# defaults to follow_redirects=False, so a 3xx fails the `status_code != 200` check rather than
# being silently followed - unlike the TS default fetch(). This test exercises the DEFAULT fetch
# implementation (no injected fetch_did_web_document) against two real local HTTP servers to
# verify that claim directly, rather than trusting the review's prose.
async def test_the_default_did_web_fetch_does_not_follow_a_redirect_to_a_different_host():
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    class _Server:
        def __init__(self, handler_factory):
            self.hit = False
            self._httpd = HTTPServer(("127.0.0.1", 0), handler_factory(self))
            self._thread = Thread(target=self._httpd.serve_forever, daemon=True)
            self._thread.start()

        @property
        def port(self) -> int:
            return self._httpd.server_address[1]

        def close(self):
            self._httpd.shutdown()
            self._httpd.server_close()

    def attacker_handler_factory(server):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                server.hit = True
                body = b'{"id": "did:web:attacker-controlled", "verificationMethod": []}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        return Handler

    attacker = _Server(attacker_handler_factory)

    def origin_handler_factory(_server):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{attacker.port}/evil.json")
                self.end_headers()

            def log_message(self, *args):
                pass

        return Handler

    origin = _Server(origin_handler_factory)

    try:
        # _did_web_to_url always builds an https:// URL (the #42 hardening); this did is resolved
        # directly against the plain-HTTP local server by monkeypatching nothing - instead we call
        # the module's own default-fetch-producing factory against an http:// URL directly, which
        # exercises the exact same httpx.AsyncClient() construction `_default_fetch_did_web` uses.
        from cheqd_agent_identity.agent_card.retrieve_public_key import _default_fetch_did_web

        fetch = _default_fetch_did_web(1_000_000)
        response = await fetch(f"http://127.0.0.1:{origin.port}/.well-known/did.json")
        assert response.status_code == 302, "a redirect response must be surfaced, not followed"
        assert attacker.hit is False, "the redirect must not be followed to a different host/port"
    finally:
        origin.close()
        attacker.close()


async def test_a_did_web_response_body_over_the_configured_byte_cap_is_rejected(monkeypatch):
    # Exercises the DEFAULT fetch implementation's own bound via a real streamed httpx response,
    # not the injected json() shortcut other tests use (an injected fetch_did_web_document is
    # responsible for its own bound - see the module doc comment).
    did = "did:web:example.com"
    huge_body = f'{{"id": "{did}", "verificationMethod": [], "padding": "{"x" * 1000}"}}'.encode("utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=huge_body)

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_async_client)

    retrieve = create_retrieve_public_key(did_web_max_response_bytes=10)
    with pytest.raises(KeyResolutionError):
        await retrieve(f"{did}#key-1", None)
