# SPDX-License-Identifier: Apache-2.0
# Unit tests for the constraint evaluators ported from AP2's constraints.py.
from cheqd_agent_identity_ap2.constraints import (
    check_checkout_constraints,
    check_payment_constraints,
    merchant_matches,
)

MERCHANT = {"id": "m1", "name": "Acme", "website": "https://acme.example"}
OTHER_MERCHANT = {"id": "m2", "name": "Other", "website": "https://other.example"}
INSTRUMENT = {"id": "card-1", "type": "card"}
BASE_PAYMENT = {
    "vct": "mandate.payment.1",
    "transaction_id": "t1",
    "payee": MERCHANT,
    "payment_amount": {"amount": 1000, "currency": "USD"},
    "payment_instrument": INSTRUMENT,
}


def open_mandate(constraints, **extra):
    return {"vct": "mandate.payment.open.1", "constraints": constraints, "cnf": {"jwk": {}}, **extra}


def test_merchant_matches_by_id_takes_precedence():
    assert merchant_matches({"id": "a", "name": "X"}, {"id": "a", "name": "Y"}) is True
    assert merchant_matches({"id": "a", "name": "X"}, {"id": "b", "name": "X"}) is False


def test_amount_range_within_range_passes():
    open_ = open_mandate([{"type": "payment.amount_range", "currency": "USD", "max": 2000, "min": 500}])
    assert check_payment_constraints(open_, BASE_PAYMENT) == []


def test_amount_range_over_max_fails():
    open_ = open_mandate([{"type": "payment.amount_range", "currency": "USD", "max": 500}])
    violations = check_payment_constraints(open_, BASE_PAYMENT)
    assert any("exceeds maximum" in v for v in violations)


def test_amount_range_currency_mismatch_fails():
    open_ = open_mandate([{"type": "payment.amount_range", "currency": "EUR", "max": 2000}])
    violations = check_payment_constraints(open_, BASE_PAYMENT)
    assert any("Currency mismatch" in v for v in violations)


def test_allowed_payees_payee_in_list_passes():
    open_ = open_mandate([{"type": "payment.allowed_payees", "allowed": [MERCHANT]}])
    assert check_payment_constraints(open_, BASE_PAYMENT) == []


def test_allowed_payees_payee_not_in_list_fails():
    open_ = open_mandate([{"type": "payment.allowed_payees", "allowed": [OTHER_MERCHANT]}])
    violations = check_payment_constraints(open_, BASE_PAYMENT)
    assert any("not in allowed list" in v for v in violations)


def test_payment_reference_requires_an_open_checkout_hash():
    open_ = open_mandate([{"type": "payment.reference", "conditional_transaction_id": "abc"}])
    violations = check_payment_constraints(open_, BASE_PAYMENT)
    assert any("required to evaluate" in v for v in violations)


def test_payment_reference_matches_the_supplied_hash():
    open_ = open_mandate([{"type": "payment.reference", "conditional_transaction_id": "abc"}])
    assert check_payment_constraints(open_, BASE_PAYMENT, "abc") == []


def test_agent_recurrence_requires_amount_range_and_budget_constraints():
    open_ = open_mandate([{"type": "payment.agent_recurrence", "frequency": "DAILY"}])
    violations = check_payment_constraints(open_, BASE_PAYMENT)
    assert "payment.agent_recurrence requires payment.amount_range constraint" in violations
    assert "payment.agent_recurrence requires payment.budget constraint" in violations


def test_agent_recurrence_max_occurrences_exceeded_fails():
    open_ = open_mandate(
        [
            {"type": "payment.agent_recurrence", "frequency": "DAILY", "max_occurrences": 2},
            {"type": "payment.amount_range", "currency": "USD", "max": 2000},
            {"type": "payment.budget", "currency": "USD", "max": 100},
        ]
    )
    violations = check_payment_constraints(open_, BASE_PAYMENT, None, {"total_amount": 0, "total_uses": 2})
    assert any("Maximum occurrences exceeded" in v for v in violations)


def test_budget_cumulative_spend_within_budget_passes():
    open_ = open_mandate(
        [
            {"type": "payment.budget", "currency": "USD", "max": 50},
            {"type": "payment.amount_range", "currency": "USD", "max": 2000},
            {"type": "payment.agent_recurrence", "frequency": "DAILY"},
        ]
    )
    # past spend 2000 cents + this 1000 cents = 3000 cents = $30, under the $50 budget.
    assert check_payment_constraints(open_, BASE_PAYMENT, None, {"total_amount": 2000, "total_uses": 1}) == []


def test_budget_cumulative_spend_over_budget_fails():
    # max $5 (500 cents); BASE_PAYMENT spends 1000 cents, which exceeds it.
    open_ = open_mandate(
        [
            {"type": "payment.budget", "currency": "USD", "max": 5},
            {"type": "payment.amount_range", "currency": "USD", "max": 2000},
            {"type": "payment.agent_recurrence", "frequency": "DAILY"},
        ]
    )
    violations = check_payment_constraints(open_, BASE_PAYMENT, None, {"total_amount": 0, "total_uses": 0})
    assert any("exceeds budget limit" in v for v in violations)


def test_allowed_payment_instruments_instrument_not_allowed_fails():
    open_ = open_mandate(
        [{"type": "payment.allowed_payment_instruments", "allowed": [{"id": "other-card", "type": "card"}]}]
    )
    violations = check_payment_constraints(open_, BASE_PAYMENT)
    assert any("not in allowed list" in v for v in violations)


def test_execution_date_outside_window_fails():
    open_ = open_mandate(
        [{"type": "payment.execution_date", "not_before": "2027-01-01", "not_after": "2027-12-31"}]
    )
    payment = {**BASE_PAYMENT, "execution_date": "2026-01-01"}
    violations = check_payment_constraints(open_, payment)
    assert any("before allowed window" in v for v in violations)


def test_preset_payee_in_the_open_mandate_must_match_the_closed_mandate():
    open_ = open_mandate(
        [{"type": "payment.amount_range", "currency": "USD", "max": 2000}], payee=OTHER_MERCHANT
    )
    violations = check_payment_constraints(open_, BASE_PAYMENT)
    assert any("Pre-set payee mismatch" in v for v in violations)


def test_checkout_allowed_merchants_merchant_not_allowed_fails():
    open_ = {
        "vct": "mandate.checkout.open.1",
        "constraints": [{"type": "checkout.allowed_merchants", "allowed": [OTHER_MERCHANT]}],
        "cnf": {"jwk": {}},
    }
    checkout = {
        "id": "c1",
        "merchant": MERCHANT,
        "line_items": [],
        "status": "incomplete",
        "currency": "USD",
        "totals": [],
    }
    violations = check_checkout_constraints(open_, checkout)
    assert any("not in allowed list" in v for v in violations)


def test_checkout_line_items_wildcard_requirement_satisfied_by_any_item():
    open_ = {
        "vct": "mandate.checkout.open.1",
        "constraints": [
            {"type": "checkout.line_items", "items": [{"id": "req1", "acceptable_items": [], "quantity": 1}]}
        ],
        "cnf": {"jwk": {}},
    }
    checkout = {
        "id": "c1",
        "line_items": [{"id": "li1", "item": {"id": "sku-1", "title": "Shoe"}, "quantity": 1, "totals": []}],
        "status": "incomplete",
        "currency": "USD",
        "totals": [],
    }
    assert check_checkout_constraints(open_, checkout) == []


def test_checkout_line_items_unsatisfiable_requirement_fails():
    open_ = {
        "vct": "mandate.checkout.open.1",
        "constraints": [
            {
                "type": "checkout.line_items",
                "items": [{"id": "req1", "acceptable_items": [{"id": "sku-X", "title": "X"}], "quantity": 1}],
            }
        ],
        "cnf": {"jwk": {}},
    }
    checkout = {
        "id": "c1",
        "line_items": [{"id": "li1", "item": {"id": "sku-1", "title": "Shoe"}, "quantity": 1, "totals": []}],
        "status": "incomplete",
        "currency": "USD",
        "totals": [],
    }
    violations = check_checkout_constraints(open_, checkout)
    assert len(violations) > 0
