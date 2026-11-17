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

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentPaymentKeyCredential":
        """Parse every field from `raw` itself, so the result can never diverge from the
        document whose proof gets verified. This is the only safe way to build this dataclass:
        constructing it by hand from separately-sourced values (rather than from the one signed
        document) risks exactly the mismatch `verify_agent_payment_key_credential` guards
        against internally - see its docstring.
        """
        credential_subject_raw = raw.get("credentialSubject") or {}
        credential_status_raw = raw.get("credentialStatus")
        return cls(
            type=tuple(raw.get("type") or ()),
            issuer=raw.get("issuer", ""),
            credential_subject=AgentPaymentKeyCredentialSubject(
                id=credential_subject_raw.get("id", ""),
                payment_key_jwk=credential_subject_raw.get("paymentKeyJwk", {}),
            ),
            context=raw.get("@context"),
            issuance_date=raw.get("issuanceDate"),
            valid_from=raw.get("validFrom"),
            valid_until=raw.get("validUntil"),
            credential_status=(
                AgentPaymentKeyCredentialStatus(
                    type=credential_status_raw.get("type", ""),
                    status_purpose=credential_status_raw.get("statusPurpose", "revocation"),
                    status_list_credential=credential_status_raw.get("statusListCredential", ""),
                    status_list_index=credential_status_raw.get("statusListIndex", ""),
                )
                if credential_status_raw is not None
                else None
            ),
            proof=raw.get("proof"),
            raw=raw,
        )


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


def _parse_iso8601_to_epoch_ms(value: str) -> float:
    """Raises ValueError for anything that doesn't parse - callers must fail closed on that,
    never treat an unparseable date as satisfying a validity check.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000


async def verify_agent_payment_key_credential(
    credential: AgentPaymentKeyCredential,
    primary_agent_did: str,
    deps: PaymentKeyAuthorizationDeps,
) -> PaymentKeyAuthorizationResult:
    """Verify an Agent Payment Key Credential: its proof verifies against the issuer's (the
    agent's primary) resolved key, it is self-issued (subject == issuer), it is within its
    validity window, and it is not revoked. Fails closed on every unverifiable case.

    Every decision, and the `payment_key_jwk` this returns on success, is derived from
    `credential.raw` alone (re-parsed via `AgentPaymentKeyCredential.from_dict`) - never from
    `credential`'s other, separately-populated fields. Those fields are NOT trusted: nothing
    stops a caller from constructing a `credential` whose `raw` is a real, correctly-signed
    document but whose other fields (`valid_until`, `credential_subject`, ...) were populated
    by hand and diverge from it. Proof verification alone would not catch that divergence,
    since it only checks `raw` - so deciding or returning anything from the separate fields
    would let a mismatched field silently override what was actually signed.
    """
    trusted = AgentPaymentKeyCredential.from_dict(credential.raw)

    if AGENT_PAYMENT_KEY_CREDENTIAL_TYPE not in trusted.type:
        return PaymentKeyAuthorizationFailed(reason="wrong_credential_type")
    if trusted.issuer != primary_agent_did:
        return PaymentKeyAuthorizationFailed(reason="issuer_is_not_primary_agent")
    if trusted.credential_subject.id != primary_agent_did:
        return PaymentKeyAuthorizationFailed(reason="not_self_issued")

    valid_from = trusted.valid_from
    if valid_from is not None:
        try:
            starts_at = _parse_iso8601_to_epoch_ms(valid_from)
        except ValueError:
            return PaymentKeyAuthorizationFailed(reason="credential_not_yet_valid")
        if starts_at > deps.now():
            return PaymentKeyAuthorizationFailed(reason="credential_not_yet_valid")

    valid_until = trusted.valid_until
    if valid_until is not None:
        try:
            expires_at = _parse_iso8601_to_epoch_ms(valid_until)
        except ValueError:
            return PaymentKeyAuthorizationFailed(reason="credential_expired")
        if expires_at <= deps.now():
            return PaymentKeyAuthorizationFailed(reason="credential_expired")

    if not await verify_eddsa_jcs_2022(credential.raw, deps.resolve_did_document):
        return PaymentKeyAuthorizationFailed(reason="proof_invalid")

    if trusted.credential_status is None:
        return PaymentKeyAuthorizationFailed(reason="missing_credential_status")
    try:
        revoked, fresh = await deps.check_revoked(trusted)
    except Exception:
        return PaymentKeyAuthorizationFailed(reason="status_check_failed")
    if revoked or not fresh:
        return PaymentKeyAuthorizationFailed(
            reason="payment_key_revoked" if revoked else "payment_key_status_not_fresh"
        )

    return PaymentKeyAuthorizationOk(payment_key_jwk=trusted.credential_subject.payment_key_jwk)
