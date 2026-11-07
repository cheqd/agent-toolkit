"""Payment and checkout constraint evaluation - a faithful port of AP2's `constraints.py`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import math

from cheqd_agent_identity_ap2.max_flow import evaluate_line_items_max_flow
from cheqd_agent_identity_ap2.types import (
    AgentRecurrence,
    AllowedMerchants,
    AllowedPayees,
    AllowedPaymentInstruments,
    AllowedPisps,
    AmountRange,
    Budget,
    Checkout,
    CheckoutConstraint,
    ExecutionDateConstraint,
    LineItems,
    MandateContext,
    Merchant,
    OpenCheckoutMandate,
    OpenPaymentMandate,
    PaymentConstraint,
    PaymentInstrument,
    PaymentMandate,
    PaymentReference,
)


def merchant_matches(candidate: Merchant, target: Merchant) -> bool:
    """Match merchants by `id` (preferred), or by `name` + `website` (both present and
    equal).
    """
    if candidate.get("id") and target.get("id"):
        return candidate["id"] == target["id"]
    return (
        bool(candidate.get("name"))
        and candidate.get("name") == target.get("name")
        and bool(candidate.get("website"))
        and candidate.get("website") == target.get("website")
    )


def _evaluate_amount_range(constraint: AmountRange, closed: PaymentMandate) -> list[str]:
    violations: list[str] = []
    amount = closed["payment_amount"]
    if constraint.get("currency") and amount["currency"] != constraint["currency"]:
        violations.append(f"Currency mismatch: expected {constraint['currency']}, got {amount['currency']}")
    if constraint.get("min") is not None and amount["amount"] < constraint["min"]:
        violations.append(f"Amount {amount['amount']} below minimum {constraint['min']}")
    if amount["amount"] > constraint["max"]:
        violations.append(f"Amount {amount['amount']} exceeds maximum {constraint['max']}")
    return violations


def _evaluate_allowed_payees(constraint: AllowedPayees, closed: PaymentMandate) -> list[str]:
    payee = closed["payee"]
    if any(merchant_matches(allowed, payee) for allowed in constraint["allowed"]):
        return []
    return [f"Payee {payee['name']} not in allowed list"]


def _evaluate_payment_reference(constraint: PaymentReference, open_checkout_hash: str | None) -> list[str]:
    """Binds the payment to a specific open checkout mandate via the `checkout_reference`
    digest: the closed payment's `transaction_id` must equal `conditional_transaction_id`.
    """
    if not open_checkout_hash:
        return ["open_checkout_hash is required to evaluate PaymentReference constraints"]
    if open_checkout_hash != constraint["conditional_transaction_id"]:
        expected = constraint["conditional_transaction_id"]
        return [
            f"PaymentReference mismatch: expected open checkout hash {expected}, got {open_checkout_hash}"
        ]
    return []


def _evaluate_agent_recurrence(constraint: AgentRecurrence, context: MandateContext | None) -> list[str]:
    """Upstream's own `AgentRecurrenceEvaluator.evaluate` only checks `max_occurrences` against
    `mandate_context.total_uses` - `frequency` is a required, validated field but is not
    actually enforced anywhere in `constraints.py` (no period-window check exists there
    either). Ported faithfully: `frequency` is validated by the type system (`types.py`'s
    `Frequency`) but not otherwise used here.
    """
    limit = constraint.get("max_occurrences")
    if limit is None:
        return []
    if context is None:
        return ["Missing mandate context required to evaluate recurrence"]
    if context["total_uses"] >= limit:
        return [f"Maximum occurrences exceeded: {context['total_uses']} >= {limit}"]
    return []


def _evaluate_allowed_payment_instruments(
    constraint: AllowedPaymentInstruments, closed: PaymentMandate
) -> list[str]:
    instrument = closed.get("payment_instrument")
    if not instrument:
        return ["Missing payment instrument in closed mandate"]
    if any(allowed["id"] == instrument["id"] for allowed in constraint["allowed"]):
        return []
    return [f"Payment instrument {instrument['id']} not in allowed list"]


def _evaluate_allowed_pisps(constraint: AllowedPisps, closed: PaymentMandate) -> list[str]:
    pisp = closed.get("pisp")
    if not pisp:
        return ["Missing PISP in closed mandate"]
    if any(
        allowed["domain_name"] == pisp["domain_name"]
        and allowed["legal_name"] == pisp["legal_name"]
        and allowed["brand_name"] == pisp["brand_name"]
        for allowed in constraint["allowed"]
    ):
        return []
    return [f"PISP {json.dumps(pisp)} not in allowed list"]


def _evaluate_budget(constraint: Budget, closed: PaymentMandate, context: MandateContext | None) -> list[str]:
    """Upstream's `Budget.max` is in MAJOR units (dollars) while `AmountRange`'s min/max are
    MINOR units (cents) - a real inconsistency in the AP2 schema itself, preserved here rather
    than "fixed", since this package verifies what AP2 actually signs. The `* 100` below also
    assumes a 2-decimal currency (matching upstream's own hardcoded assumption) - not correct
    for zero-decimal currencies (e.g. JPY), but that is upstream's bug to fix, not ours to
    paper over.
    """
    if closed["payment_amount"]["currency"] != constraint["currency"]:
        got = closed["payment_amount"]["currency"]
        return [f"Budget currency mismatch: expected {constraint['currency']}, got {got}"]
    if context is None:
        return ["Missing mandate context required to evaluate budget"]
    past_spend = context["total_amount"]
    total_spend = past_spend + closed["payment_amount"]["amount"]
    budget_max_cents = math.trunc(constraint["max"] * 100)
    if total_spend > budget_max_cents:
        return [
            f"Cumulative spend {total_spend} exceeds budget limit {budget_max_cents} "
            f"(past spend: {past_spend})"
        ]
    return []


def _evaluate_execution_date(constraint: ExecutionDateConstraint, closed: PaymentMandate) -> list[str]:
    exec_date = closed.get("execution_date")
    if not exec_date:
        return []
    violations: list[str] = []
    not_before = constraint.get("not_before")
    not_after = constraint.get("not_after")
    if not_before and exec_date < not_before:
        violations.append(f"Execution date {exec_date} is before allowed window {not_before}")
    if not_after and exec_date > not_after:
        violations.append(f"Execution date {exec_date} is after allowed window {not_after}")
    return violations


def _evaluate_payment_constraint(
    constraint: PaymentConstraint,
    closed: PaymentMandate,
    open_checkout_hash: str | None,
    context: MandateContext | None,
) -> list[str]:
    constraint_type = constraint["type"]
    if constraint_type == "payment.amount_range":
        return _evaluate_amount_range(constraint, closed)
    if constraint_type == "payment.allowed_payees":
        return _evaluate_allowed_payees(constraint, closed)
    if constraint_type == "payment.reference":
        return _evaluate_payment_reference(constraint, open_checkout_hash)
    if constraint_type == "payment.agent_recurrence":
        return _evaluate_agent_recurrence(constraint, context)
    if constraint_type == "payment.allowed_payment_instruments":
        return _evaluate_allowed_payment_instruments(constraint, closed)
    if constraint_type == "payment.allowed_pisps":
        return _evaluate_allowed_pisps(constraint, closed)
    if constraint_type == "payment.budget":
        return _evaluate_budget(constraint, closed, context)
    if constraint_type == "payment.execution_date":
        return _evaluate_execution_date(constraint, closed)
    return []


def _amount_equals(a: dict, b: dict) -> bool:
    return a["amount"] == b["amount"] and a["currency"] == b["currency"]


def _instrument_equals(a: PaymentInstrument, b: PaymentInstrument) -> bool:
    return a["id"] == b["id"] and a["type"] == b["type"]


def check_preset_payment_claims(open_mandate: OpenPaymentMandate, closed: PaymentMandate) -> list[str]:
    """Pre-set claims the open mandate fixed at issuance must appear unchanged in the closed
    mandate.
    """
    violations: list[str] = []
    preset_payee = open_mandate.get("payee")
    if preset_payee is not None and not merchant_matches(preset_payee, closed["payee"]):
        violations.append(
            f"Pre-set payee mismatch: expected {preset_payee['name']}, got {closed['payee']['name']}"
        )
    preset_amount = open_mandate.get("payment_amount")
    if preset_amount is not None and not _amount_equals(preset_amount, closed["payment_amount"]):
        expected_amount = json.dumps(preset_amount)
        got_amount = json.dumps(closed["payment_amount"])
        violations.append(f"Pre-set amount mismatch: expected {expected_amount}, got {got_amount}")
    preset_instrument = open_mandate.get("payment_instrument")
    if preset_instrument is not None and not _instrument_equals(
        preset_instrument, closed["payment_instrument"]
    ):
        violations.append("Pre-set payment_instrument mismatch")
    preset_execution_date = open_mandate.get("execution_date")
    if preset_execution_date is not None and preset_execution_date != closed.get("execution_date"):
        got = closed.get("execution_date")
        violations.append(f"Pre-set execution_date mismatch: expected {preset_execution_date}, got {got}")
    return violations


def check_payment_constraints(
    open_mandate: OpenPaymentMandate,
    closed_payment: PaymentMandate,
    open_checkout_hash: str | None = None,
    context: MandateContext | None = None,
) -> list[str]:
    """Verify the closed payment satisfies the open mandate's constraints, including that any
    pre-set claims are present and unchanged. `open_checkout_hash` is required only if a
    `payment.reference` constraint is present; `context` is required only if
    `agent_recurrence` or `budget` constraints are present.
    """
    violations: list[str] = check_preset_payment_claims(open_mandate, closed_payment)

    has_recurrence = any(c["type"] == "payment.agent_recurrence" for c in open_mandate["constraints"])
    if has_recurrence:
        has_amount = any(c["type"] == "payment.amount_range" for c in open_mandate["constraints"])
        has_budget = any(c["type"] == "payment.budget" for c in open_mandate["constraints"])
        if not has_amount:
            violations.append("payment.agent_recurrence requires payment.amount_range constraint")
        if not has_budget:
            violations.append("payment.agent_recurrence requires payment.budget constraint")

    for constraint in open_mandate["constraints"]:
        violations.extend(
            _evaluate_payment_constraint(constraint, closed_payment, open_checkout_hash, context)
        )
    return violations


def _evaluate_allowed_merchants(constraint: AllowedMerchants, checkout: Checkout) -> list[str]:
    merchant = checkout.get("merchant")
    if not merchant:
        return ["Missing merchant in checkout"]
    if any(merchant_matches(allowed, merchant) for allowed in constraint["allowed"]):
        return []
    return [f"Merchant {merchant.get('name', '')} not in allowed list"]


def _evaluate_line_items(constraint: LineItems, checkout: Checkout) -> list[str]:
    items = checkout.get("line_items") or []
    if len(items) == 0:
        return ["Empty cart does not satisfy line_items constraint"]
    return evaluate_line_items_max_flow(items, constraint["items"])


def _evaluate_checkout_constraint(constraint: CheckoutConstraint, checkout: Checkout) -> list[str]:
    constraint_type = constraint["type"]
    if constraint_type == "checkout.allowed_merchants":
        return _evaluate_allowed_merchants(constraint, checkout)
    if constraint_type == "checkout.line_items":
        return _evaluate_line_items(constraint, checkout)
    return []


def check_checkout_constraints(open_mandate: OpenCheckoutMandate, checkout: Checkout) -> list[str]:
    """Verify a decoded Checkout satisfies the open checkout mandate's constraints."""
    violations: list[str] = []
    for constraint in open_mandate["constraints"]:
        violations.extend(_evaluate_checkout_constraint(constraint, checkout))
    return violations
