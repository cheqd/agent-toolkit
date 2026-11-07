"""cnf key-continuity (WS5 decision 1): `thumbprint(AP2 cnf.jwk) == thumbprint(resolve(kid))`.
The same RFC 7638 thumbprint already used throughout this programme for the A2A proof's own
`cnf.jkt` fusion (spec §4.6 step 8) - this module compares the Open Mandate's `cnf.jwk`
against whichever agent key the caller resolved, so AP2's key continuity and A2A's share one
notion of "the same key", without this package reaching into `cheqd_agent_identity_a2a`'s gate
internals to get it.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional, Union

from cheqd_agent_identity_ap2.payment_key_authorization import (
    AgentPaymentKeyCredential,
    PaymentKeyAuthorizationDeps,
    verify_agent_payment_key_credential,
)

# RFC 7638 §3: the required members per key type, in the order the thumbprint JSON must use.
_REQUIRED_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "RSA": ("e", "kty", "n"),
    "oct": ("k", "kty"),
}


def calculate_jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK Thumbprint, SHA-256, base64url (no padding)."""
    kty = jwk.get("kty")
    members = _REQUIRED_MEMBERS.get(kty)
    if members is None:
        raise ValueError(f"unsupported_kty: {kty}")
    ordered = {member: jwk[member] for member in members}
    canonical = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class CnfFusionOk:
    tier: str  # 'same-key' | 'authorised-secondary-key'
    ok: bool = True


@dataclass(frozen=True)
class CnfFusionFailed:
    reason: str
    ok: bool = False


CnfFusionResult = Union[CnfFusionOk, CnfFusionFailed]


async def verify_same_key_continuity(
    mandate_cnf_jwk: dict[str, Any], resolved_agent_key_jwk: dict[str, Any]
) -> CnfFusionResult:
    """Compare the Open Mandate's `cnf.jwk` thumbprint against the resolved agent key's
    thumbprint. `ok=True` means the SAME key signs both the A2A proof and the AP2 mandate -
    full continuity. A mismatch is not automatically a failure: see
    `payment_key_authorization.py` for the authorised-secondary-key tier, which accepts a
    DIFFERENT key when it is itself authorised by the agent's primary key via a verified,
    non-revoked Agent Payment Key Credential.
    """
    try:
        mandate_thumbprint = calculate_jwk_thumbprint(mandate_cnf_jwk)
        agent_thumbprint = calculate_jwk_thumbprint(resolved_agent_key_jwk)
    except Exception:
        return CnfFusionFailed(reason="cnf_jwk_malformed")
    if mandate_thumbprint != agent_thumbprint:
        return CnfFusionFailed(reason="cnf_jwk_thumbprint_mismatch")
    return CnfFusionOk(tier="same-key")


async def verify_cnf_continuity(
    mandate_cnf_jwk: dict[str, Any],
    resolved_agent_key_jwk: dict[str, Any],
    primary_agent_did: str,
    payment_key_credential: Optional[AgentPaymentKeyCredential],
    deps: PaymentKeyAuthorizationDeps,
) -> CnfFusionResult:
    """Full WS5 decision 1+2 composition: try same-key continuity first; if the mandate's
    `cnf.jwk` is a different key, accept it only when `payment_key_credential` is given AND
    verifies as an authorised secondary key (decision A) AND its `payment_key_jwk` is the one
    actually bound in the mandate's `cnf`. Fails closed if neither path succeeds.
    """
    same_key = await verify_same_key_continuity(mandate_cnf_jwk, resolved_agent_key_jwk)
    if same_key.ok:
        return same_key
    if payment_key_credential is None:
        return same_key

    authorized = await verify_agent_payment_key_credential(payment_key_credential, primary_agent_did, deps)
    if not authorized.ok:
        return CnfFusionFailed(reason=authorized.reason)

    bound_to_authorized_key = await verify_same_key_continuity(mandate_cnf_jwk, authorized.payment_key_jwk)
    if not bound_to_authorized_key.ok:
        return CnfFusionFailed(reason="cnf_jwk_not_the_authorised_payment_key")

    return CnfFusionOk(tier="authorised-secondary-key")
