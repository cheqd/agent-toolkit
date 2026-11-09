# SPDX-License-Identifier: Apache-2.0
# End-to-end test: mint a REAL OpenPaymentMandate SD-JWT-VC with the `sd-jwt` package's own
# issuance API, present it with a real Key Binding JWT (Ed25519, transaction_data bound to a
# specific closed PaymentMandate), and verify the whole thing through
# verify_open_payment_mandate_presentation + verify_transaction_data_binding - exercising the
# real library end to end, not a stub.
#
# `sd-jwt`'s own `SDJWTHolder.create_presentation` has no way to add a `transaction_data` claim
# to the KB-JWT (its payload is a fixed `{nonce, aud, iat, sd_hash}` dict - confirmed directly
# against `holder.py`), so this test builds the KB-JWT by hand with `jwcrypto`, reproducing the
# library's own `sd_hash` computation (`common.py`'s `_combine`/`_b64hash`) rather than
# reimplementing SD-JWT disclosure logic itself.
import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from sd_jwt.issuer import SDJWTIssuer

from cheqd_agent_identity_ap2.sd_jwt_presentation import (
    transaction_data_hash,
    verify_open_payment_mandate_presentation,
    verify_transaction_data_binding,
)

CLOSED_PAYMENT = {
    "vct": "mandate.payment.1",
    "transaction_id": "tx-1",
    "payee": {"id": "m1", "name": "Acme"},
    "payment_amount": {"amount": 1999, "currency": "USD"},
    "payment_instrument": {"id": "card-1", "type": "card"},
}


def ed25519_keypair() -> tuple[dict, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    return public_jwk, private_key


def _jwcrypto_key_from_cryptography(private_key: Ed25519PrivateKey) -> JWK:
    from cryptography.hazmat.primitives import serialization

    raw_private = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    raw_public = private_key.public_key().public_bytes_raw()
    d = base64.urlsafe_b64encode(raw_private).rstrip(b"=").decode("ascii")
    x = base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode("ascii")
    return JWK.from_json(json.dumps({"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_presentation(
    *,
    issuer_private_key: Ed25519PrivateKey,
    holder_public_jwk: dict,
    kb_signing_key: Ed25519PrivateKey,
    aud: str,
    nonce: str,
    constraints: list | None = None,
    include_transaction_data: bool = True,
) -> str:
    issuer_jwk = _jwcrypto_key_from_cryptography(issuer_private_key)
    open_mandate_payload = {
        "vct": "mandate.payment.open.1",
        "constraints": constraints or [{"type": "payment.amount_range", "currency": "USD", "max": 5000}],
        "cnf": {"jwk": holder_public_jwk},
    }
    issuer = SDJWTIssuer(open_mandate_payload, issuer_jwk, holder_key=None, sign_alg="EdDSA")
    sd_jwt_issuance = issuer.sd_jwt_issuance  # "<jws>~" (no disclosures selected, none disclosable here)

    sd_hash = _b64url(hashlib.sha256((sd_jwt_issuance + "").encode("ascii")).digest())

    kb_payload: dict = {"nonce": nonce, "aud": aud, "iat": int(time.time()), "sd_hash": sd_hash}
    if include_transaction_data:
        kb_payload["transaction_data"] = [transaction_data_hash(CLOSED_PAYMENT)]

    kb_jwk = _jwcrypto_key_from_cryptography(kb_signing_key)
    kb_jws = JWS(payload=json.dumps(kb_payload))
    kb_jws.add_signature(kb_jwk, alg="EdDSA", protected=json.dumps({"alg": "EdDSA", "typ": "kb+jwt"}))
    kb_jwt = kb_jws.serialize(compact=True)

    return f"{sd_jwt_issuance}{kb_jwt}"


async def test_a_real_sd_jwt_vc_plus_kb_jwt_presentation_verifies_end_to_end():
    issuer_public_jwk, issuer_private_key = ed25519_keypair()
    holder_public_jwk, holder_private_key = ed25519_keypair()

    token = build_presentation(
        issuer_private_key=issuer_private_key,
        holder_public_jwk=holder_public_jwk,
        kb_signing_key=holder_private_key,
        aud="did:web:merchant.example",
        nonce="n-123",
    )

    result = await verify_open_payment_mandate_presentation(
        token=token,
        issuer_public_jwk=issuer_public_jwk,
        expected_audience="did:web:merchant.example",
        expected_nonce="n-123",
    )

    assert result.payload["vct"] == "mandate.payment.open.1"
    assert result.cnf_jwk == holder_public_jwk
    assert verify_transaction_data_binding(result.key_binding, CLOSED_PAYMENT) is True


async def test_a_presentation_bound_to_the_wrong_transaction_is_rejected_by_the_binding_check():
    issuer_public_jwk, issuer_private_key = ed25519_keypair()
    holder_public_jwk, holder_private_key = ed25519_keypair()

    token = build_presentation(
        issuer_private_key=issuer_private_key,
        holder_public_jwk=holder_public_jwk,
        kb_signing_key=holder_private_key,
        aud="did:web:merchant.example",
        nonce="n-456",
    )

    result = await verify_open_payment_mandate_presentation(
        token=token,
        issuer_public_jwk=issuer_public_jwk,
        expected_audience="did:web:merchant.example",
        expected_nonce="n-456",
    )

    different_payment = {**CLOSED_PAYMENT, "transaction_id": "tx-DIFFERENT"}
    assert verify_transaction_data_binding(result.key_binding, different_payment) is False


async def test_a_presentation_signed_by_the_wrong_holder_key_fails_verification():
    issuer_public_jwk, issuer_private_key = ed25519_keypair()
    holder_public_jwk, _holder_private_key = ed25519_keypair()
    _, impostor_private_key = ed25519_keypair()

    # Issue the open mandate bound to `holder`'s key, but sign the KB-JWT with `impostor`'s key.
    token = build_presentation(
        issuer_private_key=issuer_private_key,
        holder_public_jwk=holder_public_jwk,
        kb_signing_key=impostor_private_key,
        aud="did:web:merchant.example",
        nonce="n-789",
        constraints=[],
        include_transaction_data=False,
    )

    with pytest.raises(Exception):
        await verify_open_payment_mandate_presentation(
            token=token,
            issuer_public_jwk=issuer_public_jwk,
            expected_audience="did:web:merchant.example",
            expected_nonce="n-789",
        )
