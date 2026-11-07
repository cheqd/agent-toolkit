"""AP2 (Agent Payments Protocol) mandate types - a faithful port of the "open mandate" (human-
not-present) schema from `google-agentic-commerce/AP2` (`code/sdk/schemas/ap2/*.json`, read
directly, not a reimplementation from memory of the spec prose). Field names, optionality and
the Budget-in-major-units / AmountRange-in-minor-units inconsistency are preserved exactly as
upstream has them, including the inconsistency - this package verifies what AP2 actually
signs, not a cleaned-up version of it.

Two parallel open/closed mandate pairs:
- `OpenPaymentMandate` (long-lived, `cnf`-bound, carries payment constraints) /
  `PaymentMandate` (one per transaction, checked against the open mandate's constraints).
- `OpenCheckoutMandate` (long-lived, `cnf`-bound, carries checkout constraints) /
  `CheckoutMandate` (wraps a merchant-signed `checkout_jwt`).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict, Union


class Merchant(TypedDict):
    id: NotRequired[str]
    name: str
    website: NotRequired[str]


class Amount(TypedDict):
    """`amount` is minor units per ISO 4217 (e.g. 27999 = $279.99)."""

    amount: float
    currency: str


class PaymentInstrument(TypedDict):
    id: str
    type: str
    description: NotRequired[str]


class Pisp(TypedDict):
    legal_name: str
    brand_name: str
    domain_name: str


# --- Open Payment Mandate constraints (payment.*) ----------------------------------------------


class AllowedPayees(TypedDict):
    type: Literal["payment.allowed_payees"]
    allowed: list[Merchant]


class AmountRange(TypedDict):
    """`max`/`min` are minor units."""

    type: Literal["payment.amount_range"]
    currency: str
    max: float
    min: NotRequired[float]


class PaymentReference(TypedDict):
    type: Literal["payment.reference"]
    conditional_transaction_id: str
    """Digest of the associated Open Checkout Mandate."""


Frequency = Literal["ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"]


class AgentRecurrence(TypedDict):
    type: Literal["payment.agent_recurrence"]
    frequency: Frequency
    max_occurrences: NotRequired[int]


class Budget(TypedDict):
    """`max` is MAJOR units (NOT minor units - this is how upstream defines it; see
    constraints.py).
    """

    type: Literal["payment.budget"]
    max: float
    currency: str


class ExecutionDateConstraint(TypedDict):
    type: Literal["payment.execution_date"]
    not_before: NotRequired[str]
    not_after: NotRequired[str]


class AllowedPaymentInstruments(TypedDict):
    type: Literal["payment.allowed_payment_instruments"]
    allowed: list[PaymentInstrument]


class AllowedPisps(TypedDict):
    type: Literal["payment.allowed_pisps"]
    allowed: list[Pisp]


PaymentConstraint = Union[
    AgentRecurrence,
    AllowedPayees,
    AllowedPaymentInstruments,
    AllowedPisps,
    AmountRange,
    Budget,
    ExecutionDateConstraint,
    PaymentReference,
]


class Cnf(TypedDict):
    jwk: dict[str, Any]


class OpenPaymentMandate(TypedDict):
    """`vct: mandate.payment.open.1`. Long-lived, `cnf`-bound."""

    vct: Literal["mandate.payment.open.1"]
    constraints: list[PaymentConstraint]
    cnf: Cnf
    payee: NotRequired[Merchant]
    payment_amount: NotRequired[Amount]
    payment_instrument: NotRequired[PaymentInstrument]
    pisp: NotRequired[Pisp]
    execution_date: NotRequired[str]
    risk_data: NotRequired[dict[str, Any]]
    iat: NotRequired[int]
    exp: NotRequired[int]


class PaymentMandate(TypedDict):
    """`vct: mandate.payment.1`. One per transaction."""

    vct: Literal["mandate.payment.1"]
    transaction_id: str
    """base64url hash of the associated checkout_jwt (same hash alg as the sd-jwt's sd_hash,
    else sha-256)."""
    payee: Merchant
    pisp: NotRequired[Pisp]
    payment_amount: Amount
    payment_instrument: PaymentInstrument
    execution_date: NotRequired[str]
    risk_data: NotRequired[dict[str, Any]]
    iat: NotRequired[int]
    exp: NotRequired[int]


# --- Open Checkout Mandate constraints (checkout.*) --------------------------------------------


class AllowedMerchants(TypedDict):
    type: Literal["checkout.allowed_merchants"]
    allowed: list[Merchant]


class Item(TypedDict):
    id: str
    title: str


class LineItemRequirements(TypedDict):
    id: str
    acceptable_items: list[Item]
    quantity: float


class LineItems(TypedDict):
    type: Literal["checkout.line_items"]
    items: list[LineItemRequirements]


CheckoutConstraint = Union[AllowedMerchants, LineItems]


class OpenCheckoutMandate(TypedDict):
    """`vct: mandate.checkout.open.1`. Long-lived, `cnf`-bound."""

    vct: Literal["mandate.checkout.open.1"]
    constraints: list[CheckoutConstraint]
    cnf: Cnf
    iat: NotRequired[int]
    exp: NotRequired[int]


class CheckoutMandate(TypedDict):
    """`vct: mandate.checkout.1`. The merchant-signed checkout."""

    vct: Literal["mandate.checkout.1"]
    checkout_jwt: str
    """base64url-encoded merchant-signed JWT of the Checkout payload."""
    checkout_hash: str
    """base64url hash of checkout_jwt."""
    iat: NotRequired[int]
    exp: NotRequired[int]


# --- The Checkout object the merchant-signed checkout_jwt decodes to ---------------------------


class LineItemTotal(TypedDict):
    type: str
    amount: float


class LineItem(TypedDict):
    id: str
    item: Item
    quantity: float
    totals: list[LineItemTotal]
    parent_id: NotRequired[str]


CheckoutStatus = Literal[
    "incomplete", "requires_escalation", "ready_for_complete", "complete_in_progress", "completed", "canceled"
]


class Checkout(TypedDict):
    """UCP Checkout object (dev.ucp.shopping.checkout); `merchant` is AP2's own extension for
    mandate binding.
    """

    id: str
    merchant: NotRequired[Merchant]
    line_items: list[LineItem]
    status: CheckoutStatus
    currency: str
    totals: list[LineItemTotal]


class MandateContext(TypedDict):
    """Aggregated usage context for a recurring/budget-constrained mandate - the state
    `MandateConsumptionStore` (mandate_consumption_store.py) persists per mandate id.
    """

    total_amount: float
    total_uses: int
    last_used_date: NotRequired[int]
