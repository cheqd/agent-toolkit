# SPDX-License-Identifier: Apache-2.0
"""Real cross-language wire conformance for the AP2 open-mandate SD-JWT-VC + Key Binding JWT
presentation - the same kind of gap D18 closed for A2A (a real cross-language round trip, not
just each side's own round trip), but for AP2: has anyone ever proven that `@sd-jwt/core` (TS)
and the `sd-jwt` PyPI package (Python, decision D11's stand-in for `@sd-jwt/core`) actually
produce and accept the same compact SD-JWT-VC + KB-JWT wire format? Until this script, no.

Two modes, each a half of one of the two cross-language directions. The counterpart TS script is
conformance/cross-language-ap2-sd-jwt.mjs at the repository root - same two modes, same shapes,
the same fixed CLOSED_PAYMENT content so both sides compute the same transaction_data hash.

  mint   - acts as a real Python issuer+holder: issues an OpenPaymentMandate SD-JWT-VC with the
           `sd-jwt` package's own SDJWTIssuer, then builds a real Ed25519 Key Binding JWT by hand
           with jwcrypto (the same construction tests/test_sd_jwt_presentation.py uses, since
           SDJWTHolder.create_presentation has no way to add a transaction_data claim - confirmed
           directly against holder.py) bound to transaction_data_hash(CLOSED_PAYMENT). Prints
           {token, issuerPublicJwk, holderPublicJwk, aud, nonce} to stdout.
  verify - acts as a real Python verifier: reads that JSON from stdin (either this script's own
           mint output, or the TS script's), calls the real
           verify_open_payment_mandate_presentation + verify_transaction_data_binding against
           CLOSED_PAYMENT. Prints {"ok": true, "cnfJwk": ...} and exits 0 on success; prints
           {"ok": false, "error": ...} to stderr and exits 1 otherwise.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from sd_jwt.issuer import SDJWTIssuer

from cheqd_agent_identity_ap2.sd_jwt_presentation import (
    transaction_data_hash,
    verify_open_payment_mandate_presentation,
    verify_transaction_data_binding,
)

AUD = "did:web:merchant.example"
NONCE = "cross-language-conformance-nonce"

# Shared with conformance/cross-language-ap2-sd-jwt.mjs's CLOSED_PAYMENT, byte for byte (both
# sides json.dumps/JSON.stringify this exact object to compute the same transaction_data hash) -
# a real divergence in key order or number formatting between the two languages would show up
# here as a hash mismatch, which is exactly the kind of thing worth proving doesn't happen.
CLOSED_PAYMENT = {
    "vct": "mandate.payment.1",
    "transaction_id": "tx-1",
    "payee": {"id": "m1", "name": "Acme"},
    "payment_amount": {"amount": 1999, "currency": "USD"},
    "payment_instrument": {"id": "card-1", "type": "card"},
}


def _ed25519_keypair() -> tuple[dict[str, Any], Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {"kty": "OKP", "crv": "Ed25519", "x": x}, private_key


def _jwcrypto_key_from_cryptography(private_key: Ed25519PrivateKey) -> JWK:
    raw_private = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    raw_public = private_key.public_key().public_bytes_raw()
    d = base64.urlsafe_b64encode(raw_private).rstrip(b"=").decode("ascii")
    x = base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode("ascii")
    return JWK.from_json(json.dumps({"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint() -> None:
    issuer_public_jwk, issuer_private_key = _ed25519_keypair()
    holder_public_jwk, holder_private_key = _ed25519_keypair()

    issuer_jwk = _jwcrypto_key_from_cryptography(issuer_private_key)
    open_mandate_payload = {
        "vct": "mandate.payment.open.1",
        "constraints": [{"type": "payment.amount_range", "currency": "USD", "max": 5000}],
        "cnf": {"jwk": holder_public_jwk},
    }
    issuer = SDJWTIssuer(open_mandate_payload, issuer_jwk, holder_key=None, sign_alg="EdDSA")
    sd_jwt_issuance = issuer.sd_jwt_issuance  # "<jws>~" (no disclosures selected, none disclosable here)

    sd_hash = _b64url(hashlib.sha256((sd_jwt_issuance + "").encode("ascii")).digest())
    kb_payload = {
        "nonce": NONCE,
        "aud": AUD,
        "iat": int(time.time()),
        "sd_hash": sd_hash,
        "transaction_data": [transaction_data_hash(CLOSED_PAYMENT)],
    }

    kb_jwk = _jwcrypto_key_from_cryptography(holder_private_key)
    kb_jws = JWS(payload=json.dumps(kb_payload))
    kb_jws.add_signature(kb_jwk, alg="EdDSA", protected=json.dumps({"alg": "EdDSA", "typ": "kb+jwt"}))
    kb_jwt = kb_jws.serialize(compact=True)

    token = sd_jwt_issuance + kb_jwt
    json.dump(
        {
            "token": token,
            "issuerPublicJwk": issuer_public_jwk,
            "holderPublicJwk": holder_public_jwk,
            "aud": AUD,
            "nonce": NONCE,
        },
        sys.stdout,
    )


async def verify() -> None:
    payload = json.load(sys.stdin)
    try:
        result = await verify_open_payment_mandate_presentation(
            token=payload["token"],
            issuer_public_jwk=payload["issuerPublicJwk"],
            expected_audience=payload["aud"],
            expected_nonce=payload["nonce"],
        )
        if result.cnf_jwk != payload["holderPublicJwk"]:
            raise ValueError(
                "cnf_jwk_mismatch: verified cnf.jwk does not match the minting script's holder key"
            )
        if not verify_transaction_data_binding(result.key_binding, CLOSED_PAYMENT):
            raise ValueError("transaction_data_binding_failed")
        json.dump({"ok": True, "cnfJwk": result.cnf_jwk}, sys.stdout)
    except Exception as error:  # noqa: BLE001 - reported to the caller, not swallowed
        json.dump({"ok": False, "error": str(error)}, sys.stderr)
        sys.exit(1)


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else None
    if mode == "mint":
        mint()
    elif mode == "verify":
        asyncio.run(verify())
    else:
        sys.stderr.write("usage: python conformance_cross_language.py <mint|verify>\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
