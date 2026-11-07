"""SD-JWT-VC + Key Binding JWT verification for an AP2 open mandate presentation, using the
IETF reference `sd-jwt` package (RFC 9901's predecessor draft lineage - see the note on its
`exp`/`iat` gap below) for the SD-JWT/KB-JWT crypto layer. Deliberately does NOT port AP2's own
`~~`-joined multi-hop delegation-chain protocol (`mandate.py`/`chain.py`/`kb_sd_jwt.py` - an
unratified Google draft, not RFC 9901 itself); see the TypeScript package's README for why.

Instead this covers the single-delegation-hop case documented directly in AP2's own
`models/mandate.py` (`PaymentMandate.user_authorization` docstring): the holder presents the
open mandate with a Key Binding JWT whose `transaction_data` claim carries secure hashes of
the specific closed mandate content being authorised.

Two real gaps in the `sd-jwt` package (version 0.10.4) this module works around, both verified
directly against its source, not assumed:
- `SDJWTVerifier._verify_sd_jwt`/`_verify_key_binding_jwt` never check `exp`/`iat` at all (a
  literal `# TODO: Check exp/nbf/iat` in its own source) - this module checks both, with the
  same `skew_seconds`/`current_date` override shape the TypeScript package's `@sd-jwt/core`
  call exposes.
- `SDJWTVerifier.__init__` calls `_verify_key_binding_jwt` without forwarding an explicit
  `sign_alg`, so it silently defaults to `ES256` regardless of what algorithm the token
  actually used - this module subclasses `SDJWTVerifier` to pass the holder key's own
  algorithm through, rather than forcing every KB-JWT in this programme onto ES256.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Generic, Optional, TypeVar

from jwcrypto.jwk import JWK
from sd_jwt.verifier import SDJWTVerifier

from cheqd_agent_identity_ap2.types import OpenCheckoutMandate, OpenPaymentMandate


def _alg_for_jwk(jwk: dict[str, Any]) -> str:
    """The two algorithms KYA-OS's own proof profile allows (spec §4.1's `alg` allow-list), so
    AP2 verification stays consistent with the rest of this programme.
    """
    kty = jwk.get("kty")
    if kty == "OKP":
        return "EdDSA"
    if kty == "EC":
        return "ES256"
    raise ValueError(f"unsupported_kty: {kty}")


class _AlgPinnedVerifier(SDJWTVerifier):
    """Pins both the SD-JWT's and the KB-JWT's signature algorithm to what each signer's own
    JWK type allows, instead of `sd-jwt`'s defaults (autodetect-from-header for the SD-JWT,
    hardcoded ES256 for the KB-JWT).
    """

    def __init__(self, *args: Any, issuer_alg: str, **kwargs: Any) -> None:
        self._issuer_alg = issuer_alg
        super().__init__(*args, **kwargs)

    def _verify_sd_jwt(self, cb_get_issuer_key: Any, sign_alg: Optional[str] = None) -> None:
        super()._verify_sd_jwt(cb_get_issuer_key, sign_alg=self._issuer_alg)

    def _verify_key_binding_jwt(
        self,
        expected_aud: Optional[str] = None,
        expected_nonce: Optional[str] = None,
        sign_alg: Optional[str] = None,
    ) -> None:
        holder_jwk = (self._holder_public_key_payload or {}).get("jwk")
        if not holder_jwk:
            raise ValueError("missing_cnf_jwk")
        super()._verify_key_binding_jwt(expected_aud, expected_nonce, sign_alg=_alg_for_jwk(holder_jwk))


@dataclass(frozen=True)
class KeyBinding:
    aud: str
    nonce: str
    iat: int
    transaction_data: tuple[str, ...] = ()


Payload = TypeVar("Payload")


@dataclass(frozen=True)
class VerifiedOpenMandatePresentation(Generic[Payload]):
    payload: Payload
    key_binding: KeyBinding
    cnf_jwk: dict[str, Any]
    """The `cnf.jwk` the KB-JWT was bound to - feed this to `cnf_fusion.py`."""


def _decode_kb_jwt_payload(presentation: str) -> dict[str, Any]:
    """The KB-JWT is the final `~`-separated segment of a compact SD-JWT presentation. By the
    time this is called, `SDJWTVerifier` has already cryptographically verified it; this just
    reads the claims back out, since the library does not expose them itself.
    """
    kb_jwt = presentation.rsplit("~", 1)[-1]
    payload_segment = kb_jwt.split(".")[1]
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


async def _verify_open_mandate(
    *,
    token: str,
    issuer_public_jwk: dict[str, Any],
    expected_audience: str,
    expected_nonce: str,
    skew_seconds: int = 60,
    current_date: Optional[int] = None,
) -> VerifiedOpenMandatePresentation[Any]:
    issuer_key = JWK.from_json(json.dumps(issuer_public_jwk))

    def cb_get_issuer_key(_iss: Any, _header: Any) -> JWK:
        return issuer_key

    verifier = _AlgPinnedVerifier(
        token,
        cb_get_issuer_key,
        expected_aud=expected_audience,
        expected_nonce=expected_nonce,
        issuer_alg=_alg_for_jwk(issuer_public_jwk),
    )
    payload = verifier.get_verified_payload()

    now = current_date if current_date is not None else int(time.time())
    exp = payload.get("exp")
    if exp is not None and now > exp + skew_seconds:
        raise ValueError("mandate_expired")
    iat = payload.get("iat")
    if iat is not None and iat > now + skew_seconds:
        raise ValueError("mandate_not_yet_valid")

    kb_payload = _decode_kb_jwt_payload(token)
    if kb_payload.get("aud") != expected_audience:
        raise ValueError("key_binding_audience_mismatch")
    kb_iat = kb_payload.get("iat")
    if kb_iat is not None and abs(now - kb_iat) > skew_seconds:
        raise ValueError("key_binding_stale")

    transaction_data = kb_payload.get("transaction_data")
    cnf = payload.get("cnf") or {}
    return VerifiedOpenMandatePresentation(
        payload=payload,
        key_binding=KeyBinding(
            aud=kb_payload["aud"],
            nonce=kb_payload["nonce"],
            iat=kb_payload.get("iat"),
            transaction_data=tuple(transaction_data) if isinstance(transaction_data, list) else (),
        ),
        cnf_jwk=cnf["jwk"],
    )


async def verify_open_payment_mandate_presentation(
    *,
    token: str,
    issuer_public_jwk: dict[str, Any],
    expected_audience: str,
    expected_nonce: str,
    skew_seconds: int = 60,
    current_date: Optional[int] = None,
) -> VerifiedOpenMandatePresentation[OpenPaymentMandate]:
    """Verify a presented `OpenPaymentMandate` (SD-JWT-VC + KB-JWT)."""
    return await _verify_open_mandate(
        token=token,
        issuer_public_jwk=issuer_public_jwk,
        expected_audience=expected_audience,
        expected_nonce=expected_nonce,
        skew_seconds=skew_seconds,
        current_date=current_date,
    )


async def verify_open_checkout_mandate_presentation(
    *,
    token: str,
    issuer_public_jwk: dict[str, Any],
    expected_audience: str,
    expected_nonce: str,
    skew_seconds: int = 60,
    current_date: Optional[int] = None,
) -> VerifiedOpenMandatePresentation[OpenCheckoutMandate]:
    """Verify a presented `OpenCheckoutMandate` (SD-JWT-VC + KB-JWT)."""
    return await _verify_open_mandate(
        token=token,
        issuer_public_jwk=issuer_public_jwk,
        expected_audience=expected_audience,
        expected_nonce=expected_nonce,
        skew_seconds=skew_seconds,
        current_date=current_date,
    )


def transaction_data_hash(closed_mandate_content: Any) -> str:
    """Secure hash of closed-mandate content for `transaction_data` binding:
    base64url(SHA-256(JSON)).
    """
    encoded = json.dumps(closed_mandate_content).encode("utf-8")
    digest = hashlib.sha256(encoded).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_transaction_data_binding(key_binding: KeyBinding, closed_mandate_content: Any) -> bool:
    """Checks that `transaction_data_hash(content)` is one of the KB-JWT's declared
    `transaction_data` hashes - the binding between the open mandate presentation and a
    specific closed mandate. Fails closed (`False`) rather than raising on content that cannot
    be hashed at all.
    """
    try:
        digest = transaction_data_hash(closed_mandate_content)
    except Exception:
        return False
    return digest in key_binding.transaction_data
