"""Client-side counterpart to `gate.py`: mints the request proof before `SendMessage` leaves
the client, and verifies the response proof against the result as received - the client MUST
verify, never trust the server's claim.

Two correctness requirements this file must hold, both found by review and both already fixed
in the TypeScript client (`packages/a2a/src/client.ts`) by
https://github.com/cheqd/agent-toolkit/pull/39 - this file ports that same fix:

1. FAIL CLOSED: a failed or missing response-proof check must make `after()` itself raise, not
   merely record a result on `self.state.last_response_check` for a caller to remember to check
   afterwards. Recording state alone lets an unverified or invalidly-proved task flow back to
   the caller as if it had been checked - exactly the bug PR #39 fixed on the TypeScript side,
   where nothing enforced the module's own "the client MUST verify" contract either.

2. PER-CALL STATE: the covered request computed in `before()` must be associated with the ONE
   `SendMessage` call it was computed for, never stored in a single instance variable shared by
   every call through one `ProofInterceptor`. A client is typically reused across concurrent
   calls; with a shared variable, call B's `before()` can overwrite the value call A's
   `before()` just set, so call A's `after()` would verify A's response against B's covered
   request - at best a spurious failure, at worst a meaningless comparison. PR #39's TS fix
   moves the covered request onto the SDK's own per-call `ClientCallContext`
   (`options.context`), which `@a2a-js/sdk` threads from `before()` to the matching `after()`
   for the same call automatically. This package has no equivalent SDK-provided threading -
   `before()`/`after()` are called directly by the integrator, not by a real `a2a-sdk`
   interceptor chain (see the module docstring above) - so the Python equivalent is for
   `before()` to RETURN the per-call context and for the caller to pass that same object into
   the matching `after()` call. See `ProofInterceptorCall`.

Like `gate.py`, operates on plain JSON-safe dicts; converting the real `a2a-sdk` client's
typed request/response objects to and from these dicts is the integrator's job. See
docs/design-decisions.md D15.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from cheqd_agent_identity_a2a.covered_request import RESPONSE_PROOF_META_KEY, covered_request, covered_result
from cheqd_agent_identity_a2a.proof.build import BuildProofContext, build_card_proof
from cheqd_agent_identity_a2a.proof.canonical import CoveredRequest
from cheqd_agent_identity_a2a.proof.response import (
    CanonicalRequest,
    CanonicalResponse,
    ConsumeNonceIfFresh,
    verify_response_proof,
)
from cheqd_agent_identity_a2a.proof.signer import ProofSigner


def _random_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class ProofInterceptorOptions:
    signer: ProofSigner
    server_did: str
    client_did: str
    server_public_jwk: dict[str, Any]
    """The server's public JWK - resolved and pinned by the caller. The client MUST resolve
    and bind the server's key itself; this interceptor does not do a DID-membership check for
    the response-proof side."""
    extension_uri: str
    consume_nonce_if_fresh: Optional[ConsumeNonceIfFresh] = None


@dataclass
class ResponseProofCheck:
    valid: bool
    reason: Optional[str] = None


@dataclass
class ProofInterceptorState:
    """Last response-proof check result, surfaced for the caller to inspect/log/assert on.
    This is still per-INSTANCE (shared by every call through one `ProofInterceptor`), so it is
    informational only - it is never what `after()` relies on to decide whether a call
    succeeded. That decision is made by raising; see the module docstring's "FAIL CLOSED"
    requirement and `ResponseProofVerificationError`.
    """

    last_response_check: Optional[ResponseProofCheck] = None


@dataclass(frozen=True)
class ProofInterceptorCall:
    """The per-call context `before()` returns. Thread this SAME object into the matching
    `after()` call - never share it, or a value left over from another call, across concurrent
    `SendMessage` calls. See the module docstring's "PER-CALL STATE" requirement for why this
    exists instead of an instance attribute like the old `self._last_covered`.

    Supports unpacking as `(params, headers)` - e.g. `params, headers = await
    interceptor.before(...)` - for source compatibility with callers that only need the
    minted request and transport headers and do not call `after()` (or that thread this whole
    object through some other channel). Any caller that DOES call `after()` for this call must
    keep the whole object, not just the unpacked `params`/`headers`, since `covered_request`
    does not survive unpacking.
    """

    params: dict[str, Any]
    headers: dict[str, str]
    covered_request: Optional[CoveredRequest] = None

    def __iter__(self) -> Iterator[Any]:
        return iter((self.params, self.headers))


class ResponseProofVerificationError(Exception):
    """Raised by `ProofInterceptor.after()` - never merely recorded on `state` - when the
    server's response proof is missing, invalid, or there is no covered request to check it
    against. `code` is one of `no_covered_request`, `no_response_proof`, `proof_invalid`;
    shaped like `gate.py`'s `GateEnforcementError` (the equivalent fail-closed contract on the
    server side of this same proof scheme).
    """

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


class ProofInterceptor:
    def __init__(self, options: ProofInterceptorOptions) -> None:
        self._options = options
        self.state = ProofInterceptorState()

    async def before(self, method: str, params: dict[str, Any]) -> ProofInterceptorCall:
        """Mints the request proof and returns a `ProofInterceptorCall` carrying the modified
        params, the headers/service parameters the transport should attach
        (`A2A-Extensions`), and this call's covered request. Thread the WHOLE returned object
        into the matching `after()` call - see `ProofInterceptorCall`.
        """
        if method != "SendMessage":
            return ProofInterceptorCall(params=params, headers={})
        covered = covered_request(method, params)
        proof = await build_card_proof(
            CoveredRequest(method=covered.method, params=covered.params),
            self._options.signer,
            BuildProofContext(audience=self._options.server_did, nonce=_random_nonce()),
        )
        message = dict(params.get("message") or {})
        message["metadata"] = {**(message.get("metadata") or {}), **proof}
        new_params = {**params, "message": message}
        return ProofInterceptorCall(
            params=new_params,
            headers={"A2A-Extensions": self._options.extension_uri},
            covered_request=covered,
        )

    async def after(
        self, method: str, result: dict[str, Any], call: Optional[ProofInterceptorCall] = None
    ) -> None:
        """Verify the server's response proof against the result as actually received. Raises
        `ResponseProofVerificationError` - never silently returns, and never only records the
        outcome on `self.state` - when there is no covered request to verify against, the
        response carries no proof at all, or the proof fails verification. See the module
        docstring's "FAIL CLOSED" requirement.

        `call` MUST be the exact `ProofInterceptorCall` the matching `before()` call returned
        for THIS `SendMessage` call - never one shared with, or left over from, another
        concurrent call. See the module docstring's "PER-CALL STATE" requirement.
        """
        if method != "SendMessage":
            return
        covered = call.covered_request if call is not None else None
        if covered is None:
            check = ResponseProofCheck(
                valid=False,
                reason=(
                    "no covered request for this call (before() was not called for it, or its "
                    "result was not passed to after())"
                ),
            )
            self.state.last_response_check = check
            raise ResponseProofVerificationError("no_covered_request", check.reason)
        if not isinstance(result, dict) or "status" not in result:
            return
        proof = (result.get("metadata") or {}).get(RESPONSE_PROOF_META_KEY)
        if not proof:
            check = ResponseProofCheck(valid=False, reason="no response proof")
            self.state.last_response_check = check
            raise ResponseProofVerificationError("no_response_proof", check.reason)
        covered_response = covered_result(result)
        req = CanonicalRequest(method=covered.method, params=covered.params)
        resp = CanonicalResponse(data=covered_response)
        verify_result = await verify_response_proof(
            proof,
            self._options.server_public_jwk,
            (req, resp),
            expected_did=self._options.server_did,
            expected_audience=self._options.client_did,
            consume_nonce_if_fresh=self._options.consume_nonce_if_fresh,
        )
        check = ResponseProofCheck(valid=verify_result.valid, reason=getattr(verify_result, "reason", None))
        self.state.last_response_check = check
        if not check.valid:
            raise ResponseProofVerificationError("proof_invalid", check.reason or "invalid")
