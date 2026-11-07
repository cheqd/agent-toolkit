# SPDX-License-Identifier: Apache-2.0
# End-to-end test against the REAL a2a-sdk protobuf types (a2a.types.SendMessageRequest/
# Task/Message), not a hand-rolled stand-in for them - the one thing docs/design-decisions.md
# D15 flagged as unverified: whether gate.py/client.py's dict-based correctness survives a
# real proto<->dict round trip, specifically for the security-sensitive request-hash binding.
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.protobuf.json_format import MessageToDict, ParseDict

from a2a.types import Message, SendMessageRequest, Task
from cheqd_agent_identity_a2a.client import ProofInterceptor, ProofInterceptorOptions
from cheqd_agent_identity_a2a.gate import AgentIdentityGate, GateEnforcementError, ResponseProofOptions
from cheqd_agent_identity_a2a.proof.response import ResponseProofIdentity
from cheqd_agent_identity_a2a.proof.signer import ed25519_signer_from_jwk
from cheqd_agent_identity_a2a.proof.verify import VerifyProofDeps
from cheqd_agent_identity_a2a.proto_bridge import (
    result_dict_to_proto,
    send_message_request_to_params,
    wrap_on_message_send,
)

CLIENT_DID = "did:web:client.example"
CLIENT_KID = f"{CLIENT_DID}#key-1"
SERVER_DID = "did:web:server.example"
SERVER_KID = f"{SERVER_DID}#key-1"


def _ed25519_jwks() -> tuple[dict, Ed25519PrivateKey, dict]:
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pub = sk.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub).rstrip(b"=").decode()
    d = base64.urlsafe_b64encode(seed).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}, sk, {"kty": "OKP", "crv": "Ed25519", "x": x}


def _simulate_wire_roundtrip(params: dict) -> SendMessageRequest:
    """What the real `a2a-sdk` JSON-RPC/REST dispatcher does to an incoming request body
    before `on_message_send` ever sees it (`jsonrpc_dispatcher.py`'s own
    `ParseDict(params, model_class(), ignore_unknown_fields=True)`, read directly) - parses
    the wire dict into a real protobuf message. This is the step that turns every `int`
    inside `message.metadata` (a `google.protobuf.Struct`) into a `double`.
    """
    return ParseDict(params, SendMessageRequest(), ignore_unknown_fields=True)


async def test_a_client_minted_proof_survives_a_real_proto_round_trip_and_verifies():
    client_private_jwk, _client_sk, client_public_jwk = _ed25519_jwks()
    _server_private_jwk, server_sk, server_public_jwk = _ed25519_jwks()
    server_public_jwk = {**server_public_jwk, "kid": SERVER_KID}

    client_signer = ed25519_signer_from_jwk(did=CLIENT_DID, kid=CLIENT_KID, private_jwk=client_private_jwk)
    interceptor = ProofInterceptor(
        ProofInterceptorOptions(
            signer=client_signer,
            server_did=SERVER_DID,
            client_did=CLIENT_DID,
            server_public_jwk=server_public_jwk,
            extension_uri="https://cheqd.io/a2a/ext/trust/v1",
        )
    )
    params, _headers = await interceptor.before("SendMessage", {"message": {"parts": [{"text": "hello"}]}})

    # The client's own proof is minted over plain-dict `params` with real ints for
    # created/expires. Simulate what actually happens on the wire: a real SendMessageRequest
    # proto round trip (Struct turns those ints into doubles) before the server-side gate
    # ever sees the params dict again.
    request_proto = _simulate_wire_roundtrip(params)
    assert isinstance(request_proto, SendMessageRequest)
    server_side_params = send_message_request_to_params(request_proto)
    created = server_side_params["message"]["metadata"]["org.kya-os/request-proof"]["created"]
    assert isinstance(created, float), "the proto round trip is expected to produce a float here"

    nonces: set = set()

    async def resolve_key(kid):
        assert kid == CLIENT_KID
        return client_public_jwk

    async def consume(nonce, did, min_ttl):
        key = (did, nonce)
        if key in nonces:
            return False
        nonces.add(key)
        return True

    verify_deps = VerifyProofDeps(
        resolve_key=resolve_key,
        expected_audience=SERVER_DID,
        consume_nonce_if_fresh=consume,
        trust_resolve_key_authority=True,
    )
    gate = AgentIdentityGate(
        verify_deps=verify_deps,
        response_proof=ResponseProofOptions(
            identity=ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=server_sk)
        ),
    )

    async def real_on_message_send(_request, _context):
        task = Task()
        task.id = "task-1"
        task.status.state = 3  # TASK_STATE_COMPLETED
        return task

    result_proto = await wrap_on_message_send(
        gate=gate, request=request_proto, context=None, real_on_message_send=real_on_message_send
    )
    assert isinstance(result_proto, Task)
    result_dict = MessageToDict(result_proto)
    assert "org.kya-os/response-proof" in result_dict["metadata"]

    # And the client's own verification survives the same real proto round trip on the way
    # back (the dispatcher's own MessageToDict(SendMessageResponse(task=...)) call).
    await interceptor.after("SendMessage", result_dict)
    assert interceptor.state.last_response_check.valid is True


async def test_a_tampered_request_is_still_rejected_after_a_real_proto_round_trip():
    client_private_jwk, _client_sk, client_public_jwk = _ed25519_jwks()
    _server_private_jwk, server_sk, _server_public_jwk = _ed25519_jwks()

    client_signer = ed25519_signer_from_jwk(did=CLIENT_DID, kid=CLIENT_KID, private_jwk=client_private_jwk)
    interceptor = ProofInterceptor(
        ProofInterceptorOptions(
            signer=client_signer,
            server_did=SERVER_DID,
            client_did=CLIENT_DID,
            server_public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "x", "kid": SERVER_KID},
            extension_uri="https://cheqd.io/a2a/ext/trust/v1",
        )
    )
    params, _headers = await interceptor.before("SendMessage", {"message": {"parts": [{"text": "hello"}]}})
    params["message"]["parts"][0]["text"] = "TAMPERED after the proof was minted"

    request_proto = _simulate_wire_roundtrip(params)

    async def resolve_key(kid):
        return client_public_jwk

    async def consume(nonce, did, min_ttl):
        return True

    verify_deps = VerifyProofDeps(
        resolve_key=resolve_key,
        expected_audience=SERVER_DID,
        consume_nonce_if_fresh=consume,
        trust_resolve_key_authority=True,
    )
    gate = AgentIdentityGate(
        verify_deps=verify_deps,
        response_proof=ResponseProofOptions(
            identity=ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=server_sk)
        ),
    )

    async def real_on_message_send(_request, _context):
        return Message()

    with pytest.raises(GateEnforcementError) as exc_info:
        await wrap_on_message_send(
            gate=gate, request=request_proto, context=None, real_on_message_send=real_on_message_send
        )
    assert exc_info.value.code == "proof_invalid"
    assert "request_hash_mismatch" in exc_info.value.reason


def test_result_dict_to_proto_dispatches_on_status_key():
    assert isinstance(result_dict_to_proto({"id": "t1", "status": {"state": "TASK_STATE_COMPLETED"}}), Task)
    assert isinstance(result_dict_to_proto({"role": "ROLE_AGENT", "messageId": "m1"}), Message)
