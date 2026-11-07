"""The authorised-secondary-key path (WS5 decision 2 + decision A): an "Agent Payment Key
Credential", a short-lived VC issued and signed by the agent's PRIMARY key, naming a
DIFFERENT key as authorised for payments. This is deliberately NOT the DID-document
verification-method path - a VC reuses this programme's existing status-list/revocation
machinery directly (`cheqd_agent_identity`'s `verify_ledger_anchored_status`) instead of
needing an on-chain write to rotate.

Trust tier (decision A): spec §4.6 step 8's `L3`/`L3-minus` assumes the SAME key signs the A2A
proof and is `cnf`-bound. A properly-authorised secondary key is a DIFFERENT key by design, so
it is neither `L3` nor `L3-minus` - it is a distinct tier, `authorised-secondary-key`,
established by verifying the authorisation CHAIN (primary key -> signed VC -> secondary key)
rather than by key identity. A revoked or expired credential, or one whose proof does not
verify against the agent's own primary key, is never promoted to this tier.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Literal, Optional, Sequence, Union

from cheqd_agent_identity.agent_card.retrieve_public_key import MinimalDidDocument
from cheqd_agent_identity.proof.eddsa_jcs_2022 import verify_eddsa_jcs_2022

AGENT_PAYMENT_KEY_CREDENTIAL_TYPE = "AgentPaymentKeyCredential"


@dataclass(frozen=True)
class AgentPaymentKeyCredentialSubject:
    id: str
    payment_key_jwk: dict[str, Any]


@dataclass(frozen=True)
class AgentPaymentKeyCredentialStatus:
    type: str
    status_purpose: Literal["revocation", "suspension"]
    status_list_credential: str
    status_list_index: str


@dataclass(frozen=True)
class AgentPaymentKeyCredential:
    type: Sequence[str]
    issuer: str
    """The agent's own primary DID - this credential is self-issued, naming a different key
    as authorised."""
    credential_subject: AgentPaymentKeyCredentialSubject
    context: Union[Sequence[str], str, None] = None
    issuance_date: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    credential_status: Optional[AgentPaymentKeyCredentialStatus] = None
    proof: Optional[dict[str, Any]] = None
    raw: dict[str, Any] = field(default_factory=dict)
    """The original decoded document, passed through to `verify_eddsa_jcs_2022` unchanged."""


CheckRevoked = Callable[[AgentPaymentKeyCredential], Awaitable[tuple[bool, bool]]]
ResolveDidDocument = Callable[[str], Awaitable[Optional[MinimalDidDocument]]]


@dataclass(frozen=True)
class PaymentKeyAuthorizationDeps:
    resolve_did_document: ResolveDidDocument
    check_revoked: CheckRevoked
    """Fails closed: a credential with no `credential_status`, or whose status cannot be
    checked, is rejected."""
    now: Callable[[], float] = field(default=lambda: datetime.now().timestamp() * 1000)


@dataclass(frozen=True)
class PaymentKeyAuthorizationOk:
    payment_key_jwk: dict[str, Any]
    tier: Literal["authorised-secondary-key"] = "authorised-secondary-key"
    ok: bool = True


@dataclass(frozen=True)
class PaymentKeyAuthorizationFailed:
    reason: str
    ok: bool = False


PaymentKeyAuthorizationResult = Union[PaymentKeyAuthorizationOk, PaymentKeyAuthorizationFailed]


async def verify_agent_payment_key_credential(
    credential: AgentPaymentKeyCredential,
    primary_agent_did: str,
    deps: PaymentKeyAuthorizationDeps,
) -> PaymentKeyAuthorizationResult:
    """Verify an Agent Payment Key Credential: its proof verifies against the issuer's (the
    agent's primary) resolved key, it is self-issued (subject == issuer), it is within its
    validity window, and it is not revoked. Fails closed on every unverifiable case.
    """
    if AGENT_PAYMENT_KEY_CREDENTIAL_TYPE not in credential.type:
        return PaymentKeyAuthorizationFailed(reason="wrong_credential_type")
    if credential.issuer != primary_agent_did:
        return PaymentKeyAuthorizationFailed(reason="issuer_is_not_primary_agent")
    if credential.credential_subject.id != primary_agent_did:
        return PaymentKeyAuthorizationFailed(reason="not_self_issued")

    valid_until = credential.valid_until
    if valid_until is not None:
        try:
            expires_at = datetime.fromisoformat(valid_until.replace("Z", "+00:00")).timestamp() * 1000
        except ValueError:
            return PaymentKeyAuthorizationFailed(reason="credential_expired")
        if expires_at <= deps.now():
            return PaymentKeyAuthorizationFailed(reason="credential_expired")

    if not await verify_eddsa_jcs_2022(credential.raw, deps.resolve_did_document):
        return PaymentKeyAuthorizationFailed(reason="proof_invalid")

    if credential.credential_status is None:
        return PaymentKeyAuthorizationFailed(reason="missing_credential_status")
    try:
        revoked, fresh = await deps.check_revoked(credential)
    except Exception:
        return PaymentKeyAuthorizationFailed(reason="status_check_failed")
    if revoked or not fresh:
        return PaymentKeyAuthorizationFailed(
            reason="payment_key_revoked" if revoked else "payment_key_status_not_fresh"
        )

    return PaymentKeyAuthorizationOk(payment_key_jwk=credential.credential_subject.payment_key_jwk)
