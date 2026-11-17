# SPDX-License-Identifier: Apache-2.0
# End-to-end test: a real ProofInterceptor (client) talking to a real AgentIdentityGate
# (server), both built in this package - proves the two halves work together. Does NOT prove
# interop with the real a2a-sdk's protobuf types or a TypeScript peer - see
# docs/design-decisions.md D15 for that boundary.
import asyncio
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity_a2a.client import (
    ProofInterceptor,
    ProofInterceptorOptions,
    ResponseProofVerificationError,
)
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
        # The response-proof verifier requires the supplied public JWK to self-declare the
        # kid it was resolved for (see docs/design-decisions.md D14's cross-language finding).
        self.server_public_jwk = {**self.server_public_jwk, "kid": SERVER_KID}

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

    call = await interceptor.before("SendMessage", {"message": {"content": "hello"}})
    assert call.headers == {"A2A-Extensions": EXTENSION_URI}

    result = await gate.handle_send_message("SendMessage", call.params, completed_task_handler)
    assert "org.kya-os/response-proof" in result["metadata"]

    await interceptor.after("SendMessage", result, call)
    assert interceptor.state.last_response_check.valid is True


async def test_a_response_tampered_with_after_signing_is_caught_by_the_client():
    """Locks in the FIX for the review finding that this test used to lock in the opposite
    (fail-open) behaviour for: `after()` must now raise on a failed verification, not just
    record `valid is False` on `state` and return normally.
    """
    world = World()
    interceptor = world.interceptor()
    gate = world.gate()

    call = await interceptor.before("SendMessage", {"message": {"content": "hello"}})
    result = await gate.handle_send_message("SendMessage", call.params, completed_task_handler)

    tampered = {**result, "status": "failed"}
    with pytest.raises(ResponseProofVerificationError) as exc_info:
        await interceptor.after("SendMessage", tampered, call)
    assert exc_info.value.code == "proof_invalid"
    assert "Response hash mismatch" in exc_info.value.reason
    assert interceptor.state.last_response_check.valid is False
    assert "Response hash mismatch" in interceptor.state.last_response_check.reason


async def test_after_raises_when_there_is_no_covered_request_to_verify_against():
    """The third fail-open case the review flagged: `_last_covered is None` (no matching
    `before()` call) used to make `after()` return silently. It must now raise instead.
    """
    world = World()
    interceptor = world.interceptor()

    with pytest.raises(ResponseProofVerificationError) as exc_info:
        await interceptor.after("SendMessage", {"id": "task-1", "status": "completed", "metadata": {}})
    assert exc_info.value.code == "no_covered_request"


async def test_after_raises_when_the_response_carries_no_proof_at_all():
    world = World()
    interceptor = world.interceptor()

    call = await interceptor.before("SendMessage", {"message": {"content": "hello"}})
    with pytest.raises(ResponseProofVerificationError) as exc_info:
        await interceptor.after("SendMessage", {"id": "task-1", "status": "completed"}, call)
    assert exc_info.value.code == "no_response_proof"
    assert interceptor.state.last_response_check.valid is False


async def test_after_rejects_a_response_verified_against_a_different_calls_covered_request():
    """Proves the per-call `covered_request` `before()` returns is actually load-bearing: if a
    caller ever threads in the WRONG call's context - exactly what the old shared-instance
    `_last_covered` bug effectively did under concurrency (see the next test for the real
    concurrent-call regression) - the content-binding check must still catch it.
    """
    world = World()
    interceptor = world.interceptor()
    gate = world.gate()

    call_a = await interceptor.before("SendMessage", {"message": {"content": "message-A"}})
    call_b = await interceptor.before("SendMessage", {"message": {"content": "message-B"}})
    result_a = await gate.handle_send_message("SendMessage", call_a.params, completed_task_handler)

    with pytest.raises(ResponseProofVerificationError) as exc_info:
        # Call A's response, verified against call B's covered request.
        await interceptor.after("SendMessage", result_a, call_b)
    assert exc_info.value.code == "proof_invalid"
    assert "Request hash mismatch" in exc_info.value.reason


async def test_concurrent_send_message_calls_through_one_interceptor_do_not_cross_contaminate():
    """Regression test for the review's shared-instance-state finding (`_last_covered` used to
    live on `self`, not scoped per call - exactly the bug PR #39
    (https://github.com/cheqd/agent-toolkit/pull/39) fixed in the TypeScript client). Two
    `SendMessage` calls genuinely in flight at once (via `asyncio.gather`) through the SAME
    `ProofInterceptor` instance: each must verify its own response against its own covered
    request, not get cross-contaminated by the other's `before()`/`after()` interleaving.
    """
    world = World()
    interceptor = world.interceptor()
    gate = world.gate()

    async def round_trip(message_text: str):
        call = await interceptor.before("SendMessage", {"message": {"content": message_text}})

        async def handler():
            return {"id": f"task-{message_text}", "status": "completed", "metadata": {}}

        result = await gate.handle_send_message("SendMessage", call.params, handler)
        await interceptor.after("SendMessage", result, call)
        check = interceptor.state.last_response_check
        assert check is not None
        return check

    check_a, check_b = await asyncio.gather(round_trip("message-A"), round_trip("message-B"))
    assert check_a.valid is True
    assert check_b.valid is True


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


async def test_a_message_result_also_gets_a_response_proof_closing_the_non_task_bypass():
    # Regression test for the MEDIUM finding: a Message result used to pass through
    # unsigned ("nothing to prove here yet"), which meant the client had nothing to check
    # for a Message result and would silently accept one substituted in place of a proven
    # Task. The gate must sign a response proof for a Message result exactly as it does for
    # a Task result, so the client (see the matching test below) can always verify.
    world = World()
    gate = world.gate()
    interceptor = world.interceptor()
    params, _ = await interceptor.before("SendMessage", {"message": {"content": "hello"}})

    async def message_handler():
        return {"role": "agent", "content": "just a message, not a task"}

    result = await gate.handle_send_message("SendMessage", params, message_handler)
    assert "org.kya-os/response-proof" in result["metadata"]

    await interceptor.after("SendMessage", result)
    assert interceptor.state.last_response_check.valid is True


async def test_a_substituted_unproven_message_result_is_flagged_invalid_not_silently_accepted():
    # Regression test for the MEDIUM finding, client side: before the fix, client.after()
    # returned early for any result with no "status" field (i.e. a Message, not a Task)
    # without checking anything at all - `state.last_response_check` was simply never set,
    # so a caller inspecting it could not tell the difference between "nothing to check"
    # and "verified". A party able to answer in the server's place (a compromised proxy,
    # TLS terminator, DNS hijack) could substitute an arbitrary Message - with no proof at
    # all - for what should have been a proven Task, and this client accepted it.
    world = World()
    gate = world.gate()
    interceptor = world.interceptor()
    params, _ = await interceptor.before("SendMessage", {"message": {"content": "hello"}})

    # The real handler would have returned a genuine, proven Task via `gate.handle_send_message`.
    # Simulate a man-in-the-middle substituting an unproven Message instead - no "status" key,
    # no response-proof metadata at all.
    substituted = {"role": "agent", "content": "ATTACKER SUBSTITUTED MESSAGE, NEVER PROVEN"}

    await interceptor.after("SendMessage", substituted)
    assert interceptor.state.last_response_check is not None
    assert interceptor.state.last_response_check.valid is False
    assert interceptor.state.last_response_check.reason == "no response proof"


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
