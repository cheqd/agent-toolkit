"""KYA-OS Entity Card proof — the default minting seam.

Ported from `@kya-os/mcp/card`'s `card/proof/signer.ts`. Produces a DETACHED JWS
(`protectedHeader..signature`) over the JCS-canonical covered claims. Signing support here is
Ed25519 (EdDSA) only - this programme's consistent Ed25519 posture (see
`sd_jwt_presentation.py`'s `_alg_for_jwk`); `verify_card_proof` still verifies BOTH EdDSA and
ES256 proofs, since a verifier must interoperate with any `org.kya-os/proof.v1` signer, not
just ones built by this package. An ES256 signer can be added the same way if a caller needs
to mint one - see docs/design-decisions.md D13.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _rfc7638_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK Thumbprint, SHA-256, base64url (no padding). Duplicated from (not imported
    from) the AP2 package's own `cnf_fusion.calculate_jwk_thumbprint`: this package depends
    only on `cheqd_agent_identity` (core), matching the TypeScript repo's own rule that
    neither binding depends on the other.
    """
    ordered = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    canonical = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class ProofSigner(Protocol):
    did: str
    kid: str
    jkt: Optional[str]
    alg: str

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
