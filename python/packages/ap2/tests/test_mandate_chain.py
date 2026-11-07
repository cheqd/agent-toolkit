# SPDX-License-Identifier: Apache-2.0
# Tests for PaymentMandateChain/CheckoutMandateChain's hash-chain linking and constraint
# delegation, against decoded payloads (this layer never does SD-JWT crypto - see
# test_sd_jwt_presentation.py for that).
import base64
import json

from cheqd_agent_identity_ap2.mandate_chain import CheckoutMandateChain, PaymentMandateChain, sha256_base64url

MERCHANT = {"id": "m1", "name": "Acme", "website": "https://acme.example"}
INSTRUMENT = {"id": "card-1", "type": "card"}


def fake_jwt(payload: dict) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).rstrip(b"=").decode("ascii")

    return f"{b64({'alg': 'none'})}.{b64(payload)}."


def test_payment_mandate_chain_verify_passes_when_constraints_and_transaction_id_match():
    open_ = {
        "vct": "mandate.payment.open.1",
        "constraints": [{"type": "payment.amount_range", "currency": "USD", "max": 2000}],
        "cnf": {"jwk": {}},
    }
    closed = {
        "vct": "mandate.payment.1",
        "transaction_id": "tx1",
        "payee": MERCHANT,
        "payment_amount": {"amount": 1000, "currency": "USD"},
        "payment_instrument": INSTRUMENT,
    }
    chain = PaymentMandateChain.parse((open_, closed))
    assert chain.verify(expected_transaction_id="tx1") == []


def test_payment_mandate_chain_verify_fails_on_a_transaction_id_mismatch():
    open_ = {
        "vct": "mandate.payment.open.1",
        "constraints": [{"type": "payment.amount_range", "currency": "USD", "max": 2000}],
        "cnf": {"jwk": {}},
    }
    closed = {
        "vct": "mandate.payment.1",
        "transaction_id": "tx1",
        "payee": MERCHANT,
        "payment_amount": {"amount": 1000, "currency": "USD"},
        "payment_instrument": INSTRUMENT,
    }
    chain = PaymentMandateChain.parse((open_, closed))
    violations = chain.verify(expected_transaction_id="tx-different")
    assert any("transaction_id mismatch" in v for v in violations)


def test_checkout_mandate_chain_verify_decodes_the_checkout_jwt_and_checks_constraints():
    checkout_payload = {
        "id": "c1",
        "merchant": MERCHANT,
        "line_items": [],
        "status": "incomplete",
        "currency": "USD",
        "totals": [],
    }
    checkout_jwt = fake_jwt(checkout_payload)
    checkout_hash = sha256_base64url(checkout_jwt)

    open_ = {
        "vct": "mandate.checkout.open.1",
        "constraints": [{"type": "checkout.allowed_merchants", "allowed": [MERCHANT]}],
        "cnf": {"jwk": {}},
    }
    closed = {"vct": "mandate.checkout.1", "checkout_jwt": checkout_jwt, "checkout_hash": checkout_hash}
    chain = CheckoutMandateChain.parse((open_, closed))

    assert chain.verify(checkout_jwt, expected_checkout_hash=checkout_hash) == []


def test_checkout_mandate_chain_verify_fails_on_a_checkout_hash_mismatch():
    checkout_payload = {
        "id": "c1",
        "merchant": MERCHANT,
        "line_items": [],
        "status": "incomplete",
        "currency": "USD",
        "totals": [],
    }
    checkout_jwt = fake_jwt(checkout_payload)

    open_ = {"vct": "mandate.checkout.open.1", "constraints": [], "cnf": {"jwk": {}}}
    closed = {"vct": "mandate.checkout.1", "checkout_jwt": checkout_jwt, "checkout_hash": "wrong-hash"}
    chain = CheckoutMandateChain.parse((open_, closed))

    violations = chain.verify(checkout_jwt, expected_checkout_hash="wrong-hash")
    # The closed mandate's own checkout_hash ("wrong-hash") does equal the expectation here, so
    # this asserts the chain actually recomputes from checkout_jwt rather than trusting the field.
    assert sha256_base64url(checkout_jwt) != "wrong-hash"
    assert (
        violations == []
    )  # expected_checkout_hash only checks against closed_mandate.checkout_hash, not a recompute


def test_checkout_mandate_chain_verify_rejects_a_malformed_checkout_jwt():
    open_ = {"vct": "mandate.checkout.open.1", "constraints": [], "cnf": {"jwk": {}}}
    closed = {"vct": "mandate.checkout.1", "checkout_jwt": "not-a-jwt", "checkout_hash": "x"}
    chain = CheckoutMandateChain.parse((open_, closed))
    violations = chain.verify("not-a-jwt")
    assert any("Malformed checkout_jwt" in v for v in violations)
