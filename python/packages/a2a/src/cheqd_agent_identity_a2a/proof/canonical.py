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

from cheqd_agent_identity_a2a.covered_request import CoveredRequest
from cheqd_agent_identity_a2a.proof.types import CardProofMeta


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


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
