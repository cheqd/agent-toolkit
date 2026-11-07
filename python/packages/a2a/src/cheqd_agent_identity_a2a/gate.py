"""The server-side gate: request-proof verification, enforcement, and response-proof
signing - the Python collapse of TypeScript's `user-builder.ts` + `wrapper.ts` into one layer.

See docs/design-decisions.md D15 for why: Python's `a2a-sdk` builds its `ServerCallContext`
synchronously (`ServerCallContextBuilder.build(request) -> ServerCallContext`, called without
`await`), so it cannot run the async proof verification TypeScript's `userBuilder` does in that
seam. The equivalent async hook in Python is one level down - wrapping `RequestHandler.
on_message_send` itself, which the dispatcher *does* await - so this module folds
verification, enforcement and response-proof signing into one wrapping layer instead of two
separate files.

This module operates on plain JSON-safe dicts (`CoveredRequest`/results), not the real
`a2a-sdk`'s protobuf-typed `SendMessageRequest`/`Task` objects. Converting those proto types to
and from the dicts this module expects (e.g. via `google.protobuf.json_format.MessageToDict`,
the pattern `a2a.utils.signing` already uses for Agent Card canonicalization) is the
integrator's job - deliberately kept out of this module so its own correctness doesn't depend
on unverified proto-JSON round-trip fidelity. See D15 for what this means for cross-language
(TypeScript client <-> Python server) interop specifically.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from a2a.auth.user import User

from cheqd_agent_identity_a2a.covered_request import (
    PROOF_META_KEY,
    RESPONSE_PROOF_META_KEY,
    CoveredRequest,
    covered_request,
    covered_result,
)
from cheqd_agent_identity_a2a.proof.canonical import CoveredRequest as ProofCoveredRequest
from cheqd_agent_identity_a2a.proof.response import (
    RESPONSE_PROOF_PROFILE_ENVELOPE,
    CanonicalRequest,
    CanonicalResponse,
    ResponseProofIdentity,
    ResponseProofProfile,
    ResponseProofSession,
    generate_response_proof,
)
from cheqd_agent_identity_a2a.proof.verify import VerifyProofDeps, verify_card_proof
from cheqd_agent_identity_a2a.trust_extension import TrustExtensionActivation, TrustExtensionCache

WRITE_METHODS = frozenset({"SendMessage", "SendStreamingMessage"})


@dataclass(frozen=True)
class VerifiedCaller:
    did: str
    covered: CoveredRequest


class GateUser(User):
    """The user shape this gate attaches to the (real or test) `ServerCallContext`."""

    def __init__(
        self,
        *,
        is_authenticated: bool,
        user_name: str,
        verified: Optional[VerifiedCaller] = None,
        rejection: Optional[str] = None,
    ) -> None:
        self._is_authenticated = is_authenticated
        self._user_name = user_name
        self.verified = verified
        self.rejection = rejection

    @property
    def is_authenticated(self) -> bool:
        return self._is_authenticated

    @property
    def user_name(self) -> str:
        return self._user_name


async def verify_caller(method: str, params: Any, deps: VerifyProofDeps) -> GateUser:
    """Reads the WIRE body (never an already-deserialized SDK object elsewhere in the
    pipeline), verifies the request proof, and returns the verified DID as a `GateUser`, or an
    unauthenticated one carrying the rejection reason. Never raises: a raising check here would
    surface as an opaque error, which this design deliberately avoids - callers enforce via
    `enforce()`.
    """
    if method not in WRITE_METHODS:
        return GateUser(is_authenticated=False, user_name="")
    message = params.get("message") if isinstance(params, dict) else None
    metadata = message.get("metadata") if isinstance(message, dict) else None
    proof = metadata.get(PROOF_META_KEY) if isinstance(metadata, dict) else None
    if not proof:
        return GateUser(is_authenticated=False, user_name="", rejection="missing")
    covered = covered_request(method, params)
    try:
        result = await verify_card_proof(
            proof, ProofCoveredRequest(method=covered.method, params=covered.params), deps
        )
    except Exception:
        return GateUser(is_authenticated=False, user_name="", rejection="verification_error")
    if not result.ok:
        reason = result.reasons[0] if result.reasons else "invalid"
        return GateUser(is_authenticated=False, user_name="", rejection=reason)
    return GateUser(
        is_authenticated=True, user_name=result.did, verified=VerifiedCaller(did=result.did, covered=covered)
    )


class GateEnforcementError(Exception):
    """Raised by `enforce()`. `code` distinguishes "no proof at all" (`proof_required`) from
    "a proof was given but did not verify" (`proof_invalid`) and from a failed trust-extension
    check (`trust_extension_failed`) - map these to whatever HTTP/RPC error shape the real
    transport needs.
    """

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class TrustExtensionGate:
    cache: TrustExtensionCache
    activation: TrustExtensionActivation


async def enforce(
    user: Optional[GateUser], trust_extension: Optional[TrustExtensionGate] = None
) -> VerifiedCaller:
    """Rejects any write without a verified identity. Fails closed: a missing `GateUser`
    (no verifier installed at all) looks identical to a missing proof, by design, not
    convention.
    """
    if user is None or user.verified is None:
        reason = (user.rejection if user is not None else None) or "no_verifier_installed"
        if reason in ("missing", "no_verifier_installed"):
            raise GateEnforcementError("proof_required", reason)
        raise GateEnforcementError("proof_invalid", reason)
    if trust_extension is not None:
        result = await trust_extension.cache.get(user.verified.did, trust_extension.activation)
        if not result.ok:
            raise GateEnforcementError("trust_extension_failed", ",".join(result.reasons))
    return user.verified


@dataclass(frozen=True)
class ResponseProofOptions:
    identity: ResponseProofIdentity
    profile: ResponseProofProfile = RESPONSE_PROOF_PROFILE_ENVELOPE


class AgentIdentityGate:
    """Combines request-proof verification, enforcement, and response-proof signing over the
    final result. `call_through` is invoked only after enforcement succeeds - task-state
    mutation inside the real `on_message_send` never runs for a rejected caller, matching this
    programme's own gate-ordering requirement (see docs/design-decisions.md D1).
    """

    def __init__(
        self,
        *,
        verify_deps: VerifyProofDeps,
        response_proof: ResponseProofOptions,
        trust_extension: Optional[TrustExtensionGate] = None,
    ) -> None:
        self._verify_deps = verify_deps
        self._response_proof = response_proof
        self._trust_extension = trust_extension

    async def handle_send_message(
        self, method: str, params: Any, call_through: Callable[[], Awaitable[Any]]
    ) -> Any:
        """`params`/the return of `call_through` MUST already be JSON-safe dicts (the
        integrator's own proto<->dict conversion, not this gate's - see module docstring).
        """
        user = await verify_caller(method, params, self._verify_deps)
        caller = await enforce(user, self._trust_extension)
        result = await call_through()
        if not isinstance(result, dict) or "status" not in result:
            return result  # a Message, not a Task - nothing to prove here yet
        data = covered_result(result)
        session = ResponseProofSession(session_id="a2a-stateless", audience=caller.did)
        req = CanonicalRequest(method=caller.covered.method, params=caller.covered.params)
        resp = CanonicalResponse(data=data)
        proof = await generate_response_proof(
            req, resp, self._response_proof.identity, session, profile=self._response_proof.profile
        )
        metadata = {**(result.get("metadata") or {}), RESPONSE_PROOF_META_KEY: proof}
        return {**result, "metadata": metadata}
