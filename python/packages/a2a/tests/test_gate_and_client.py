# SPDX-License-Identifier: Apache-2.0
# End-to-end test: a real ProofInterceptor (client) talking to a real AgentIdentityGate
# (server), both built in this package - proves the two halves work together. Does NOT prove
# interop with the real a2a-sdk's protobuf types or a TypeScript peer - see
# docs/design-decisions.md D15 for that boundary.
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity_a2a.client import ProofInterceptor, ProofInterceptorOptions
from cheqd_agent_identity_a2a.gate import (
    AgentIdentityGate,
    GateEnforcementError,
    ResponseProofOptions,
    TrustExtensionGate,
)
from cheqd_agent_identity_a2a.proof.response import ResponseProofIdentity
from cheqd_agent_identity_a2a.proof.signer import ed25519_signer_from_jwk
from cheqd_agent_identity_a2a.proof.verify import VerifyProofDeps

CLIENT_DID = "did:web:client.example"
CLIENT_KID = f"{CLIENT_DID}#key-1"
SERVER_DID = "did:web:server.example"
SERVER_KID = f"{SERVER_DID}#key-1"
EXTENSION_URI = "https://cheqd.io/a2a/ext/trust/v1"


def _ed25519_jwks() -> tuple[dict, Ed25519PrivateKey, dict]:
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pub = sk.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(pub).rstrip(b"=").decode()
    d = base64.urlsafe_b64encode(seed).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}, sk, {"kty": "OKP", "crv": "Ed25519", "x": x}


class World:
    def __init__(self) -> None:
        client_private_jwk, _client_sk, self.client_public_jwk = _ed25519_jwks()
        _server_private_jwk, server_sk, self.server_public_jwk = _ed25519_jwks()

        self.client_signer = ed25519_signer_from_jwk(
            did=CLIENT_DID, kid=CLIENT_KID, private_jwk=client_private_jwk
        )
        self.server_identity = ResponseProofIdentity(did=SERVER_DID, kid=SERVER_KID, private_key=server_sk)

        self._nonces: set = set()

        async def resolve_key(kid):
            assert kid == CLIENT_KID
            return self.client_public_jwk

        async def consume(nonce, did, min_ttl):
            key = (did, nonce)
            if key in self._nonces:
                return False
            self._nonces.add(key)
            return True

        self.verify_deps = VerifyProofDeps(
            resolve_key=resolve_key,
            expected_audience=SERVER_DID,
            consume_nonce_if_fresh=consume,
            trust_resolve_key_authority=True,
        )

    def gate(self, *, trust_extension=None) -> AgentIdentityGate:
        return AgentIdentityGate(
            verify_deps=self.verify_deps,
            response_proof=ResponseProofOptions(identity=self.server_identity),
            trust_extension=trust_extension,
        )

    def interceptor(self) -> ProofInterceptor:
        return ProofInterceptor(
            ProofInterceptorOptions(
                signer=self.client_signer,
                server_did=SERVER_DID,
                client_did=CLIENT_DID,
                server_public_jwk=self.server_public_jwk,
                extension_uri=EXTENSION_URI,
            )
        )


async def completed_task_handler():
    return {"id": "task-1", "status": "completed", "metadata": {}}


async def test_a_full_round_trip_verifies_on_both_ends():
    world = World()
    interceptor = world.interceptor()
    gate = world.gate()

    params, headers = await interceptor.before("SendMessage", {"message": {"content": "hello"}})
    assert headers == {"A2A-Extensions": EXTENSION_URI}

    result = await gate.handle_send_message("SendMessage", params, completed_task_handler)
    assert "org.kya-os/response-proof" in result["metadata"]

    await interceptor.after("SendMessage", result)
    assert interceptor.state.last_response_check.valid is True


async def test_a_response_tampered_with_after_signing_is_caught_by_the_client():
    world = World()
    interceptor = world.interceptor()
    gate = world.gate()

    params, _ = await interceptor.before("SendMessage", {"message": {"content": "hello"}})
    result = await gate.handle_send_message("SendMessage", params, completed_task_handler)

    tampered = {**result, "status": "failed"}
    await interceptor.after("SendMessage", tampered)
    assert interceptor.state.last_response_check.valid is False
    assert "Response hash mismatch" in interceptor.state.last_response_check.reason


async def test_a_call_with_no_proof_at_all_is_rejected_before_the_handler_runs():
    world = World()
    gate = world.gate()
    handler_called = {"value": False}

    async def handler():
        handler_called["value"] = True
        return {"id": "task-1", "status": "completed"}

    with pytest.raises(GateEnforcementError) as exc_info:
        await gate.handle_send_message("SendMessage", {"message": {}}, handler)
    assert exc_info.value.code == "proof_required"
    assert handler_called["value"] is False


async def test_a_call_with_an_invalid_proof_is_rejected_with_proof_invalid():
    world = World()
    gate = world.gate()
    params, _ = await world.interceptor().before("SendMessage", {"message": {"content": "hello"}})
    params["message"]["metadata"]["org.kya-os/request-proof"]["audience"] = "did:web:someone-else.example"

    with pytest.raises(GateEnforcementError) as exc_info:
        await gate.handle_send_message("SendMessage", params, completed_task_handler)
    assert exc_info.value.code == "proof_invalid"


async def test_a_replayed_request_proof_is_rejected_on_the_second_call():
    world = World()
    gate = world.gate()
    interceptor = world.interceptor()
    params, _ = await interceptor.before("SendMessage", {"message": {"content": "hello"}})

    first = await gate.handle_send_message("SendMessage", params, completed_task_handler)
    assert "org.kya-os/response-proof" in first["metadata"]

    with pytest.raises(GateEnforcementError) as exc_info:
        await gate.handle_send_message("SendMessage", params, completed_task_handler)
    assert exc_info.value.code == "proof_invalid"
    assert "nonce_replayed" in exc_info.value.reason


async def test_a_message_result_passes_through_unsigned_nothing_to_prove_yet():
    world = World()
    gate = world.gate()
    interceptor = world.interceptor()
    params, _ = await interceptor.before("SendMessage", {"message": {"content": "hello"}})

    async def message_handler():
        return {"role": "agent", "content": "just a message, not a task"}

    result = await gate.handle_send_message("SendMessage", params, message_handler)
    assert "metadata" not in result


async def test_trust_extension_failure_rejects_an_otherwise_verified_caller():
    world = World()
    interceptor = world.interceptor()
    params, _ = await interceptor.before("SendMessage", {"message": {"content": "hello"}})

    class FailingCache:
        async def get(self, did, activation):
            from cheqd_agent_identity_a2a.trust_extension import TrustExtensionFailed

            return TrustExtensionFailed(reasons=("status_revoked",))

        def clear(self):
            pass

    from cheqd_agent_identity_a2a.trust_extension import TrustExtensionActivation

    gate = world.gate(
        trust_extension=TrustExtensionGate(cache=FailingCache(), activation=TrustExtensionActivation())
    )
    with pytest.raises(GateEnforcementError) as exc_info:
        await gate.handle_send_message("SendMessage", params, completed_task_handler)
    assert exc_info.value.code == "trust_extension_failed"
