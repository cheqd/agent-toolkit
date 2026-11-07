# SPDX-License-Identifier: Apache-2.0
# Tests for the legacy org.kya-os/response-proof engine (generate_response_proof +
# verify_response_proof). From-spec re-implementation, no TypeScript test file to port from -
# see docs/design-decisions.md D14.
import base64

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
    return sk, {"kty": "OKP", "crv": "Ed25519", "x": x}


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
