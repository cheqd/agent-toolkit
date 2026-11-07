"""KYA-OS Entity Card proof — MINT (`build_card_proof`).

Ported from `@kya-os/mcp/card`'s `card/proof/build.ts`. Mint a stateless, sender-constrained
`org.kya-os/proof.v1` for one request and return it under the card proof's own `_meta` key
(`KYA_OS_CARD_PROOF_META_KEY`). The RFC 9421 HTTP Message Signature sibling (`httpSig`) is not
ported - this package's gate never uses it (JSON-RPC/REST metadata, not real HTTP headers);
see docs/design-decisions.md D13.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from cheqd_agent_identity_a2a.proof.canonical import (
    CoveredRequest,
    canonical_payload_bytes,
    compute_request_hash,
)
from cheqd_agent_identity_a2a.proof.signer import ProofSigner
from cheqd_agent_identity_a2a.proof.types import (
    DEFAULT_TTL_SEC,
    KYA_OS_CARD_PROOF_META_KEY,
    MAX_TTL_SEC,
    PROOF_PROFILE_V1,
    CardProofCnf,
    CardProofMeta,
)


def _now_ms() -> float:
    return time.time() * 1000


@dataclass(frozen=True)
class BuildProofContext:
    audience: str
    nonce: str
    ttl_sec: int = DEFAULT_TTL_SEC
    cnf_jkt: Optional[str] = None
    now: Callable[[], float] = _now_ms
    """Epoch MILLISECONDS, matching this repo's own convention elsewhere (e.g.
    `cheqd_agent_identity.status.ledger_anchored`) and the TypeScript original's `Date.now()`."""


async def build_card_proof(
    req: CoveredRequest, signer: ProofSigner, ctx: BuildProofContext
) -> dict[str, Any]:
    """Mint an `org.kya-os/proof.v1` for `req`, signed by `signer`, bound to `ctx`. Returns the
    proof keyed by `KYA_OS_CARD_PROOF_META_KEY` so it can be spread straight into an A2A
    message's `metadata`. `cnf.jkt` is `ctx.cnf_jkt` when given, else the signer's own key
    thumbprint, else omitted (an L3-minus proof).
    """
    created = int(ctx.now() / 1000)
    ttl_sec = ctx.ttl_sec
    # Fail FAST at mint: a proof longer than the profile cap is guaranteed to be rejected by
    # the verifier (ttl_too_long), so surface the caller's error here rather than emit a
    # doomed proof.
    if ttl_sec > MAX_TTL_SEC:
        raise ValueError(f"build_card_proof: ttl_sec {ttl_sec} exceeds the profile cap of {MAX_TTL_SEC}s")

    expires = created + ttl_sec
    request_hash = compute_request_hash(req)
    jkt = ctx.cnf_jkt if ctx.cnf_jkt is not None else signer.jkt

    unsigned = CardProofMeta(
        prf=PROOF_PROFILE_V1,
        alg=signer.alg or "EdDSA",
        did=signer.did,
        kid=signer.kid,
        audience=ctx.audience,
        nonce=ctx.nonce,
        created=created,
        expires=expires,
        request_hash=request_hash,
        jws="",
        cnf=CardProofCnf(jkt=jkt) if jkt is not None else None,
    )
    jws = await signer.sign(canonical_payload_bytes(unsigned))
    signed = CardProofMeta(
        prf=unsigned.prf,
        alg=unsigned.alg,
        did=unsigned.did,
        kid=unsigned.kid,
        audience=unsigned.audience,
        nonce=unsigned.nonce,
        created=unsigned.created,
        expires=unsigned.expires,
        request_hash=unsigned.request_hash,
        jws=jws,
        cnf=unsigned.cnf,
    )
    return {KYA_OS_CARD_PROOF_META_KEY: _to_wire(signed)}


def _to_wire(meta: CardProofMeta) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "prf": meta.prf,
        "alg": meta.alg,
        "did": meta.did,
        "kid": meta.kid,
        "audience": meta.audience,
        "nonce": meta.nonce,
        "created": meta.created,
        "expires": meta.expires,
        "requestHash": meta.request_hash,
        "jws": meta.jws,
    }
    if meta.cnf is not None:
        wire["cnf"] = {"jkt": meta.cnf.jkt}
    return wire
