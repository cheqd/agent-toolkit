"""KYA-OS Entity Card proof — canonicalization + hashing (the single source of truth).

Both the minter (`build_card_proof`) and the verifier (`verify_card_proof`) derive their
signing input from HERE, so the two can never drift. Ported from `@kya-os/mcp/card`'s
`card/proof/canonical.ts`. `request_hash` is emitted in the RFC 9421 Content-Digest
structured-field form (`sha-256=:<base64>:`), matching the TypeScript original - even
though this A2A package does not use the RFC 9421 HTTP Message Signature sibling (see
docs/design-decisions.md D13), the covered-claims `requestHash` field must still be in this
exact format for a proof to interoperate with any implementation of the real
`org.kya-os/proof.v1` profile.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Optional

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from cheqd_agent_identity_a2a.covered_request import CoveredRequest
from cheqd_agent_identity_a2a.proof.small_order import is_small_order_ed25519_key
from cheqd_agent_identity_a2a.proof.types import CardProofMeta


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def ed25519_sign_raw(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """A RAW EdDSA signature (NOT JWS-framed) over `data` - what a stock RFC 9421 verifier
    expects over the signature base, distinct from the detached JWS (whose signature also
    covers the protected header).
    """
    return private_key.sign(data)


def ed25519_verify_raw(public_jwk: dict[str, Any], signature: bytes, data: bytes) -> bool:
    """Verify a RAW EdDSA signature over `data`. Fail-closed on error or a small-order key
    (where one signature would fit every message).
    """
    try:
        x_bytes = _b64url_decode(public_jwk["x"])
        if is_small_order_ed25519_key(x_bytes):
            return False
        public_key = Ed25519PublicKey.from_public_bytes(x_bytes)
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def es256_sign_raw(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """A RAW ES256 signature (ECDSA P-256 over SHA-256, `r||s` - NOT DER, NOT JWS-framed) over
    `data` - the RFC 9421 `ecdsa-p256-sha256` form a stock 9421 verifier reconstructs.
    """
    der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def es256_verify_raw(public_jwk: dict[str, Any], signature: bytes, data: bytes) -> bool:
    """Verify a RAW ES256 signature over `data` against a P-256 public JWK. Fail-closed on
    error.
    """
    try:
        if len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der_signature = encode_dss_signature(r, s)
        x_bytes = _b64url_decode(public_jwk["x"])
        y_bytes = _b64url_decode(public_jwk["y"])
        public_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"), ec.SECP256R1()
        )
        public_key = public_numbers.public_key()
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def _strip_params_meta(params: Any) -> Any:
    """The §8.3 pre-signing transformation: remove the top-level `_meta` member of `params`
    before canonicalizing - it carries the proof itself, so it can never be part of the
    signed material.
    """
    if not isinstance(params, dict):
        return params
    if "_meta" not in params:
        return params
    rest = dict(params)
    del rest["_meta"]
    return rest


def compute_request_hash(req: CoveredRequest) -> str:
    """Bind a request to its `request_hash`: SHA-256 over `JCS({method, params})`, emitted
    as the RFC 9421 Content-Digest structured field `sha-256=:<base64>:`.
    """
    params = _strip_params_meta(req.params)
    canonical_request: dict[str, Any] = {"method": req.method}
    if params is not None:
        canonical_request["params"] = params
    digest = sha256(rfc8785.dumps(canonical_request))
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def _digest_hex(value: str) -> Optional[str]:
    rfc9421 = re.match(r"^sha-256=:([A-Za-z0-9+/=]+):$", value.strip())
    if rfc9421:
        return base64.b64decode(rfc9421.group(1)).hex()
    legacy = re.match(r"^sha256:([0-9a-fA-F]+)$", value.strip())
    return legacy.group(1).lower() if legacy else None


def digests_equal(a: str, b: str) -> bool:
    """True iff two request-hash strings carry the same SHA-256 digest, accepting either the
    card's RFC 9421 `sha-256=:<base64>:` form or the legacy `sha256:<hex>` form.
    """
    ha, hb = _digest_hex(a), _digest_hex(b)
    return ha is not None and ha == hb


def covered_claims(meta: CardProofMeta) -> dict[str, Any]:
    """The COVERED claims (every proof field except `jws`) - the object the JWS actually
    signs.
    """
    claims: dict[str, Any] = {
        "prf": meta.prf,
        "alg": meta.alg,
        "did": meta.did,
        "kid": meta.kid,
        "audience": meta.audience,
        "nonce": meta.nonce,
        "created": meta.created,
        "expires": meta.expires,
        "requestHash": meta.request_hash,
    }
    if meta.cnf is not None:
        claims["cnf"] = {"jkt": meta.cnf.jkt}
    return claims


def canonical_payload_bytes(meta: CardProofMeta) -> bytes:
    """The JCS canonical bytes of the covered claims - the exact detached-JWS signing
    payload.
    """
    return rfc8785.dumps(covered_claims(meta))
