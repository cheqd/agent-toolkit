"""KYA-OS Entity Card proof — the default minting seams.

Ported from `@kya-os/mcp/card`'s `card/proof/signer.ts`: `ed25519_signer_from_jwk` and
`es256_signer_from_jwk`. Each produces a DETACHED JWS (`protectedHeader..signature`) over the
JCS-canonical covered claims, AND exposes a `sign_raw` seam producing the RFC 9421
`http_sig.py` sibling's raw signature (`ed25519SignRaw`/`es256SignRaw` in the TypeScript
original) - `build_card_proof` attaches `httpSig` to the proof whenever the signer exposes
`sign_raw`, exactly like the TypeScript original's dual-carrier logic.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from cheqd_agent_identity_a2a.proof.canonical import ed25519_sign_raw, es256_sign_raw


def _rfc7638_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK Thumbprint, SHA-256, base64url (no padding). Duplicated from (not imported
    from) the AP2 package's own `cnf_fusion.calculate_jwk_thumbprint`: this package depends
    only on `cheqd_agent_identity` (core), matching the TypeScript repo's own rule that
    neither binding depends on the other. Covers both Ed25519 (`{crv,kty,x}`) and EC
    (`{crv,kty,x,y}`) JWKs - the ordering follows RFC 7638 §3.2/§3.3 (lexicographic member
    names), which `kty`/`crv`/`x`/`y` already satisfy once sorted.
    """
    required = ("crv", "kty", "x", "y") if jwk.get("kty") == "EC" else ("crv", "kty", "x")
    ordered = {k: jwk[k] for k in required}
    canonical = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class ProofSigner(Protocol):
    did: str
    kid: str
    jkt: Optional[str]
    alg: str
    sign_raw: Optional[Callable[[bytes], Any]]

    async def sign(self, payload: bytes) -> str: ...


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class _Ed25519Signer:
    did: str
    kid: str
    jkt: str
    _private_key: Ed25519PrivateKey
    alg: str = "EdDSA"

    async def sign(self, payload: bytes) -> str:
        protected = _b64url(
            json.dumps({"alg": "EdDSA", "kid": self.kid}, separators=(",", ":")).encode("utf-8")
        )
        payload_b64 = _b64url(payload)
        signing_input = f"{protected}.{payload_b64}".encode("ascii")
        signature = self._private_key.sign(signing_input)
        return f"{protected}..{_b64url(signature)}"

    async def sign_raw(self, payload: bytes) -> bytes:
        return ed25519_sign_raw(self._private_key, payload)


@dataclass
class _ES256Signer:
    did: str
    kid: str
    jkt: str
    _private_key: ec.EllipticCurvePrivateKey
    alg: str = "ES256"

    async def sign(self, payload: bytes) -> str:
        protected = _b64url(
            json.dumps({"alg": "ES256", "kid": self.kid}, separators=(",", ":")).encode("utf-8")
        )
        payload_b64 = _b64url(payload)
        signing_input = f"{protected}.{payload_b64}".encode("ascii")
        der_signature = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{protected}..{_b64url(raw_signature)}"

    async def sign_raw(self, payload: bytes) -> bytes:
        return es256_sign_raw(self._private_key, payload)


def ed25519_signer_from_jwk(*, did: str, kid: str, private_jwk: dict[str, Any]) -> ProofSigner:
    """Build a `ProofSigner` from an Ed25519 private JWK (`{kty: 'OKP', crv: 'Ed25519', x, d}`).
    `jkt` is the RFC 7638 thumbprint of the public half, which is what `cnf.jkt` and the
    sender-constraint fusion compare against.
    """
    d = private_jwk["d"]
    padded = d + "=" * (-len(d) % 4)
    seed = base64.urlsafe_b64decode(padded)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": private_jwk["x"]}
    jkt = _rfc7638_thumbprint(public_jwk)
    return _Ed25519Signer(did=did, kid=kid, jkt=jkt, _private_key=private_key)


def es256_signer_from_jwk(*, did: str, kid: str, private_jwk: dict[str, Any]) -> ProofSigner:
    """Build a `ProofSigner` from a P-256 private JWK (`{kty: 'EC', crv: 'P-256', x, y, d}`) -
    the ES256 (ECDSA, FIPS-eligible) sibling to `ed25519_signer_from_jwk`. Same shape: RFC
    7638 `jkt` over the public half `{kty,crv,x,y}`, a detached ES256 JWS (raw `r||s`, RFC
    7518 §3.4), and the raw `ecdsa-p256-sha256` RFC 9421 sibling via `sign_raw`.
    """
    d = private_jwk["d"]
    x = private_jwk["x"]
    y = private_jwk["y"]
    d_bytes = base64.urlsafe_b64decode(d + "=" * (-len(d) % 4))
    private_key = ec.derive_private_key(int.from_bytes(d_bytes, "big"), ec.SECP256R1())
    public_jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    jkt = _rfc7638_thumbprint(public_jwk)
    return _ES256Signer(did=did, kid=kid, jkt=jkt, _private_key=private_key)
