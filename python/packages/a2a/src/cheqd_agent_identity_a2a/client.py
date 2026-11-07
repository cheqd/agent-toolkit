"""Client-side counterpart to `gate.py`: mints the request proof before `SendMessage` leaves
the client, and verifies the response proof against the result as received - the client MUST
verify, never trust the server's claim.

Like `gate.py`, operates on plain JSON-safe dicts; converting the real `a2a-sdk` client's
typed request/response objects to and from these dicts is the integrator's job. See
docs/design-decisions.md D15.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Any, Optional

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
    """Last response-proof check result, surfaced for the caller to inspect/log/assert on."""

    last_response_check: Optional[ResponseProofCheck] = None


class ProofInterceptor:
    def __init__(self, options: ProofInterceptorOptions) -> None:
        self._options = options
        self.state = ProofInterceptorState()
        self._last_covered: Optional[CoveredRequest] = None

    async def before(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        """Mints the request proof and returns the modified params plus the headers/service
        parameters the transport should attach (`A2A-Extensions`).
        """
        if method != "SendMessage":
            return params, {}
        covered = covered_request(method, params)
        proof = await build_card_proof(
            CoveredRequest(method=covered.method, params=covered.params),
            self._options.signer,
            BuildProofContext(audience=self._options.server_did, nonce=_random_nonce()),
        )
        message = dict(params.get("message") or {})
        message["metadata"] = {**(message.get("metadata") or {}), **proof}
        new_params = {**params, "message": message}
        self._last_covered = covered
        return new_params, {"A2A-Extensions": self._options.extension_uri}

    async def after(self, method: str, result: dict[str, Any]) -> None:
        """Verify the server's response proof against the result as actually received."""
        if method != "SendMessage" or self._last_covered is None:
            return
        if not isinstance(result, dict) or "status" not in result:
            return
        proof = (result.get("metadata") or {}).get(RESPONSE_PROOF_META_KEY)
        if not proof:
            self.state.last_response_check = ResponseProofCheck(valid=False, reason="no response proof")
            return
        covered = covered_result(result)
        req = CanonicalRequest(method=self._last_covered.method, params=self._last_covered.params)
        resp = CanonicalResponse(data=covered)
        verify_result = await verify_response_proof(
            proof,
            self._options.server_public_jwk,
            (req, resp),
            expected_did=self._options.server_did,
            expected_audience=self._options.client_did,
            consume_nonce_if_fresh=self._options.consume_nonce_if_fresh,
        )
        self.state.last_response_check = ResponseProofCheck(
            valid=verify_result.valid, reason=getattr(verify_result, "reason", None)
        )
