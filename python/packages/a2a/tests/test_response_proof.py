# SPDX-License-Identifier: Apache-2.0
# Tests for the legacy org.kya-os/response-proof engine (generate_response_proof +
# verify_response_proof). From-spec re-implementation, no TypeScript test file to port from -
# see docs/design-decisions.md D14.
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity_a2a.proof.response import (
    CanonicalRequest,
    CanonicalResponse,
    ResponseProofIdentity,
    ResponseProofSession,
    generate_response_proof,
    verify_response_proof,
)

SERVER_DID = "did:web:server.example"
SERVER_KID = f"{SERVER_DID}#key-1"
CLIENT_DID = "did:web:client.example"


def keypair() -> tuple[Ed25519PrivateKey, dict]:
    sk = Ed25519PrivateKey.generate()
    x = base64.urlsafe_b64encode(sk.public_key().public_bytes_raw()).rstrip(b"=").decode()
    return sk, {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": SERVER_KID}


async def consume_factory():
    store: set = set()

    async def consume(nonce, did, ttl):
        key = (did, nonce)
        if key in store:
            return False
        store.add(key)
        return True

    return consume


async def test_a_validly_signed_response_proof_verifies():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={"message": {}})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    result = await verify_response_proof(
        proof, public_jwk, (req, resp), expected_did=SERVER_DID, expected_audience=CLIENT_DID
    )
    assert result.valid is True


async def test_a_response_swapped_after_signing_fails_content_binding():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={"message": {}})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    swapped = CanonicalResponse(data={"status": "DIFFERENT"})
    result = await verify_response_proof(
        proof, public_jwk, (req, swapped), expected_did=SERVER_DID, expected_audience=CLIENT_DID
    )
    assert result.valid is False
    assert "Response hash mismatch" in result.reason


async def test_a_tampered_proof_field_fails_the_signature():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    tampered = {**proof, "meta": {**proof["meta"], "audience": "did:web:attacker.example"}}
    result = await verify_response_proof(
        tampered,
        public_jwk,
        (req, resp),
        expected_did=SERVER_DID,
        expected_audience="did:web:attacker.example",
    )
    assert result.valid is False
    assert result.reason == "Invalid JWS signature"


async def test_the_wrong_signer_did_is_rejected():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    result = await verify_response_proof(
        proof,
        public_jwk,
        (req, resp),
        expected_did="did:web:someone-else.example",
        expected_audience=CLIENT_DID,
    )
    assert result.valid is False
    assert "expected DID" in result.reason


async def test_the_wrong_audience_is_rejected():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    result = await verify_response_proof(
        proof,
        public_jwk,
        (req, resp),
        expected_did=SERVER_DID,
        expected_audience="did:web:someone-else.example",
    )
    assert result.valid is False
    assert "different audience" in result.reason


async def test_a_replayed_nonce_is_rejected_the_second_time():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    consume = await consume_factory()
    first = await verify_response_proof(
        proof,
        public_jwk,
        (req, resp),
        expected_did=SERVER_DID,
        expected_audience=CLIENT_DID,
        consume_nonce_if_fresh=consume,
    )
    second = await verify_response_proof(
        proof,
        public_jwk,
        (req, resp),
        expected_did=SERVER_DID,
        expected_audience=CLIENT_DID,
        consume_nonce_if_fresh=consume,
    )
    assert first.valid is True
    assert second.valid is False
    assert "replay" in second.reason.lower()


async def test_replay_is_not_checked_when_no_nonce_cache_is_supplied_documented_tradeoff():
    # Characterizes the documented tradeoff in verify_response_proof's docstring: unlike
    # verify_card_proof (verify.py), which FAILS CLOSED when its nonce seam is missing, this
    # function SKIPS replay checking entirely when consume_nonce_if_fresh is omitted - which is
    # the default, matching client.py's ClientOptions.consume_nonce_if_fresh default of None.
    # A captured, valid response proof can therefore be replayed without limit unless the
    # caller wires up the seam themselves. This test pins that behaviour down: if it ever
    # starts failing, the docstring (and this test) must change together with any deliberate
    # change to the default - it must never drift silently.
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    first = await verify_response_proof(
        proof, public_jwk, (req, resp), expected_did=SERVER_DID, expected_audience=CLIENT_DID
    )
    second = await verify_response_proof(
        proof, public_jwk, (req, resp), expected_did=SERVER_DID, expected_audience=CLIENT_DID
    )
    assert first.valid is True
    assert second.valid is True  # the exact same proof verifies again - no replay defense


async def test_nonce_cache_ttl_is_floored_to_default_retention_not_bare_skew():
    # Guards the gap a cross-language audit found: passing the bare skew_sec straight through
    # as the cache TTL left a replay window the +-skew check alone wouldn't catch once the
    # cache had already evicted the nonce - see _nonce_retention_seconds in proof/response.py.
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})
    resp = CanonicalResponse(data={"status": "completed"})

    proof = await generate_response_proof(req, resp, identity, session)
    seen_ttl = {}

    async def consume(nonce, did, ttl):
        seen_ttl["value"] = ttl
        return True

    skew_sec = 5
    await verify_response_proof(
        proof,
        public_jwk,
        (req, resp),
        expected_did=SERVER_DID,
        expected_audience=CLIENT_DID,
        consume_nonce_if_fresh=consume,
        skew_sec=skew_sec,
    )
    assert seen_ttl["value"] >= 300
    assert seen_ttl["value"] > skew_sec


async def test_a_response_proof_with_no_response_rejects_a_supplied_response():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})

    proof = await generate_response_proof(req, None, identity, session)
    resp = CanonicalResponse(data={"status": "completed"})
    result = await verify_response_proof(
        proof, public_jwk, (req, resp), expected_did=SERVER_DID, expected_audience=CLIENT_DID
    )
    assert result.valid is False
    assert "binds none" in result.reason


async def test_a_small_order_public_key_cannot_forge_a_universal_signature():
    # A small-order Ed25519 public key (order 1, 2, 4, or 8) lets an attacker build a signature
    # that `cryptography`'s raw Ed25519 verification accepts for EVERY message, without ever
    # touching a private key: R = the identity point's encoding, S = 0 (see
    # proof/small_order.py's module docstring, and verify.py's _ed25519_verify, which already
    # guards against exactly this for the org.kya-os/proof.v1 request-proof path). Confirmed
    # directly against `cryptography`: Ed25519PublicKey.from_public_bytes(bytes([1]+[0]*31))
    # .verify(bytes([1]+[0]*31) + bytes(32), <any message>) raises no InvalidSignature at all.
    # response.py's _verify_signature lacked the equivalent guard, so a verifier pinned (or
    # resolving) to such a key would accept an arbitrary, never-actually-signed response.
    identity_encoding = bytes([1] + [0] * 31)
    zero_scalar = bytes(32)
    identity_x = base64.urlsafe_b64encode(identity_encoding).rstrip(b"=").decode()
    small_order_public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": identity_x, "kid": SERVER_KID}

    forged_meta_wire = {
        "did": SERVER_DID,
        "kid": SERVER_KID,
        "ts": 1_700_000_000,
        "nonce": "forged-nonce",
        "audience": CLIENT_DID,
        "sessionId": "a2a-stateless",
        "requestHash": "sha256:" + "0" * 64,
    }
    protected_b64 = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "kid": SERVER_KID}, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    forged_signature = base64.urlsafe_b64encode(identity_encoding + zero_scalar).rstrip(b"=").decode()
    # _verify_signature recomputes the payload from `meta` itself (never trusts the JWS's own
    # payload segment), so the middle segment is irrelevant to what actually gets checked.
    forged_jws = f"{protected_b64}..{forged_signature}"
    forged_proof = {"jws": forged_jws, "meta": forged_meta_wire}

    result = await verify_response_proof(
        forged_proof,
        small_order_public_jwk,
        expected_did=SERVER_DID,
        expected_audience=CLIENT_DID,
        now=lambda: 1_700_000_000 * 1000.0,
    )
    assert result.valid is False


async def test_stale_timestamp_outside_skew_is_rejected():
    sk, public_jwk = keypair()
    identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=sk)
    session = ResponseProofSession(session_id="a2a-stateless", audience=CLIENT_DID)
    req = CanonicalRequest(method="SendMessage", params={})
    resp = CanonicalResponse(data={"status": "completed"})

    clock = {"value": 1_700_000_000 * 1000.0}
    proof = await generate_response_proof(req, resp, identity, session, now=lambda: clock["value"])
    clock["value"] = 1_710_000_000 * 1000.0
    result = await verify_response_proof(
        proof,
        public_jwk,
        (req, resp),
        expected_did=SERVER_DID,
        expected_audience=CLIENT_DID,
        now=lambda: clock["value"],
    )
    assert result.valid is False
    assert "skew" in result.reason
