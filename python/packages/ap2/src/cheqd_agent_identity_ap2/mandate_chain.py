"""Payment and checkout mandate-chain processing - a faithful port of AP2's
`payment_mandate_chain.py` and `checkout_mandate_chain.py`. Operates on already-decoded,
already-verified payloads (parsed from an SD-JWT presentation elsewhere - see
`sd_jwt_presentation.py`); this module owns only the business-constraint and hash-chain
linking logic, matching upstream's own separation between SD-JWT crypto and mandate semantics.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import json

from cheqd_agent_identity_ap2.constraints import check_checkout_constraints, check_payment_constraints
from cheqd_agent_identity_ap2.types import (
    Checkout,
    CheckoutMandate,
    MandateContext,
    OpenCheckoutMandate,
    OpenPaymentMandate,
    PaymentMandate,
)


def _base64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def sha256_base64url(jwt_compact: str) -> str:
    """base64url(SHA-256(utf8Bytes(jwt_compact))) - the hash both `checkout_hash` and
    `transaction_id` use.
    """
    digest = hashlib.sha256(jwt_compact.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class PaymentMandateChain:
    def __init__(self, open_mandate: OpenPaymentMandate, closed_mandate: PaymentMandate) -> None:
        self.open_mandate = open_mandate
        self.closed_mandate = closed_mandate

    @classmethod
    def parse(cls, payloads: tuple[OpenPaymentMandate, PaymentMandate]) -> PaymentMandateChain:
        return cls(payloads[0], payloads[1])

    def verify(
        self,
        *,
        expected_transaction_id: str | None = None,
        expected_open_checkout_hash: str | None = None,
        mandate_context: MandateContext | None = None,
    ) -> list[str]:
        """Verify the chain's constraints. `expected_transaction_id` checks the closed
        mandate's `transaction_id`; `expected_open_checkout_hash` is forwarded to any
        `payment.reference` constraint. Returns violation messages, or an empty list if none.
        """
        violations = check_payment_constraints(
            self.open_mandate, self.closed_mandate, expected_open_checkout_hash, mandate_context
        )
        if (
            expected_transaction_id is not None
            and expected_transaction_id != self.closed_mandate["transaction_id"]
        ):
            got = self.closed_mandate["transaction_id"]
            violations.append(
                f"Payment transaction_id mismatch: expected {expected_transaction_id}, got {got}"
            )
        return violations


class CheckoutMandateChain:
    def __init__(self, open_mandate: OpenCheckoutMandate, closed_mandate: CheckoutMandate) -> None:
        self.open_mandate = open_mandate
        self.closed_mandate = closed_mandate

    @classmethod
    def parse(cls, payloads: tuple[OpenCheckoutMandate, CheckoutMandate]) -> CheckoutMandateChain:
        return cls(payloads[0], payloads[1])

    def verify(self, checkout_jwt: str, *, expected_checkout_hash: str | None = None) -> list[str]:
        """Verify the chain's constraints against the decoded `checkout_jwt` payload.
        `expected_checkout_hash` checks the closed mandate's `checkout_hash`.
        """
        try:
            checkout = _extract_parsed_checkout_object(checkout_jwt)
        except Exception as error:
            return [str(error)]

        violations = check_checkout_constraints(self.open_mandate, checkout)
        if (
            expected_checkout_hash is not None
            and expected_checkout_hash != self.closed_mandate["checkout_hash"]
        ):
            got = self.closed_mandate["checkout_hash"]
            violations.append(
                f"Checkout checkout_hash mismatch: expected {expected_checkout_hash}, got {got}"
            )
        return violations


def _extract_parsed_checkout_object(checkout_jwt: str) -> Checkout:
    """Extracts the Checkout object from the checkout_jwt's payload segment. Does NOT verify
    the JWT's signature - matching upstream, which treats that as the merchant-trust layer's
    job, separate from mandate-chain constraint checking.
    """
    parts = checkout_jwt.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed checkout_jwt: expected header.payload.signature")
    try:
        decoded = json.loads(_base64url_decode(parts[1]).decode("utf-8"))
    except Exception as error:
        raise ValueError(f"Invalid JSON in checkout_jwt payload: {error}") from error
    if not isinstance(decoded, dict):
        raise ValueError("checkout_jwt payload failed schema validation: not an object")
    if (
        not isinstance(decoded.get("id"), str)
        or not isinstance(decoded.get("line_items"), list)
        or not isinstance(decoded.get("status"), str)
        or not isinstance(decoded.get("currency"), str)
    ):
        raise ValueError("checkout_jwt payload failed schema validation: missing required Checkout fields")
    return decoded  # type: ignore[return-value]
