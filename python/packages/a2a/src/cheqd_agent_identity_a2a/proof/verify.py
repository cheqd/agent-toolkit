"""KYA-OS Entity Card proof — VERIFY (`verify_card_proof`), fail-closed.

Ported from `@kya-os/mcp/card`'s `card/proof/verify.ts`. Recompute EVERY binding a stateless
`org.kya-os/proof.v1` asserts and reject on the first thing that does not hold. The signature
only proves the proof is AUTHENTIC (signed by the holder of `kid`); accountability requires
binding that key to the accountable principal `did`:

  1. `kid`'s DID part MUST equal `proof.did` - closes the forgeable-principal gap where a
     proof claims a victim `did` while `kid` points elsewhere;
  2. the resolved signing key MUST be a verificationMethod of `proof.did`, via the injected
     `resolve_did_keys` seam (RFC 7638 thumbprint membership) - closes a key that merely
     shares the DID's `kid` prefix but is not actually published by that DID.

Plus: `audience` -> the verifier, `requestHash` -> THIS body, `nonce` -> unseen,
`created`/`expires` -> NOW (+-skew), the detached JWS -> the covered claims, and the `cnf.jkt`
fusion. Any failure appends a reason; `ok` is true iff there are none.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Sequence, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from cheqd_agent_identity_a2a.proof.canonical import (
    CoveredRequest,
    canonical_payload_bytes,
    compute_request_hash,
)
from cheqd_agent_identity_a2a.proof.small_order import ED25519_KEY_SIZE, is_small_order_ed25519_key
from cheqd_agent_identity_a2a.proof.types import (
    DEFAULT_SKEW_SEC,
    MAX_TTL_SEC,
    CardProofMeta,
    parse_card_proof_meta,
)

ResolveKey = Callable[[str], Awaitable[dict[str, Any]]]
ResolveDidKeys = Callable[[str], Awaitable[Sequence[dict[str, Any]]]]
ConsumeNonceIfFresh = Callable[[str, str, int], Awaitable[bool]]


def _now_ms() -> float:
    return time.time() * 1000


@dataclass(frozen=True)
class VerifyProofDeps:
    resolve_key: ResolveKey
    expected_audience: str
    resolve_did_keys: Optional[ResolveDidKeys] = None
    trust_resolve_key_authority: bool = False
    token_cnf_jkt: Optional[str] = None
    consume_nonce_if_fresh: Optional[ConsumeNonceIfFresh] = None
    now: Callable[[], float] = _now_ms
    skew_sec: int = DEFAULT_SKEW_SEC


@dataclass(frozen=True)
class ProofVerifyOk:
    level: str  # 'L3' | 'L3-minus'
    did: str
    reasons: Sequence[str] = field(default_factory=tuple)
    warnings: Sequence[str] = field(default_factory=tuple)
    ok: bool = True


@dataclass(frozen=True)
class ProofVerifyFailed:
    reasons: Sequence[str]
    warnings: Sequence[str] = field(default_factory=tuple)
    ok: bool = False


ProofVerifyResult = Union[ProofVerifyOk, ProofVerifyFailed]


async def verify_card_proof(proof: Any, req: CoveredRequest, deps: VerifyProofDeps) -> ProofVerifyResult:
    """Verify an `org.kya-os/proof.v1` against the request it should bind and the injected
    seams. Fail-closed: returns `ok=False` with reasons on any broken binding; on success
    returns the derived assurance (`L3` on full cnf fusion, `L3-minus` without an AS `cnf`)
    and the principal.
    """
    reasons: list[str] = []
    parsed = parse_card_proof_meta(proof)
    if not parsed.ok:
        return ProofVerifyFailed(reasons=("malformed_proof",))
    meta = parsed.meta

    if meta.kid.split("#")[0] != meta.did:
        reasons.append("kid_did_mismatch")

    # `resolve_key` (DID-key resolution, possibly a network fetch) and `compute_request_hash`
    # (local JCS + SHA-256) are INDEPENDENT - run them concurrently.
    key, computed_hash = await asyncio.gather(_resolve_key(meta.kid, deps, reasons), _compute_hash(req))
    if key is not None:
        await _assert_did_membership(key, meta.did, deps, reasons)

    # Bind the declared alg to the resolved key type: an ES256 claim MUST carry a P-256 key,
    # an EdDSA claim an Ed25519 key. `alg` is a signed covered claim, but the KEY type is
    # authoritative here - this closes alg/key confusion.
    alg_ok = key is not None and _key_matches_alg(key, meta.alg)
    if key is not None and not alg_ok:
        reasons.append("alg_key_mismatch")

    if meta.audience != deps.expected_audience:
        reasons.append("audience_mismatch")
    if meta.request_hash != computed_hash:
        reasons.append("request_hash_mismatch")

    _check_window(meta, deps, reasons)

    if key is not None and alg_ok and not _verify_detached_jws(meta, key):
        reasons.append("invalid_signature")

    warnings: list[str] = []
    level = "L3-minus"
    if key is not None:
        level = await _check_cnf_fusion(meta, key, deps, reasons, warnings)

    # Authenticate every binding before claiming state. The shared cache must atomically
    # decide which validated request, if any, first admits this nonce.
    if len(reasons) == 0:
        await _consume_nonce(meta, deps, reasons)

    ok = len(reasons) == 0
    if ok:
        return ProofVerifyOk(level=level, did=meta.did, warnings=tuple(warnings))
    return ProofVerifyFailed(reasons=tuple(reasons), warnings=tuple(warnings))


async def _compute_hash(req: CoveredRequest) -> str:
    return compute_request_hash(req)


async def _resolve_key(kid: str, deps: VerifyProofDeps, reasons: list[str]) -> Optional[dict[str, Any]]:
    """Resolve the signing key for `kid`; fail-closed (records `key_unresolvable`) on raise."""
    try:
        return await deps.resolve_key(kid)
    except Exception:
        reasons.append("key_unresolvable")
        return None


async def _assert_did_membership(
    key: dict[str, Any], did: str, deps: VerifyProofDeps, reasons: list[str]
) -> None:
    """Cryptographically bind the signing key to `did`: it MUST be one of the DID document's
    verification keys (RFC 7638 thumbprint membership), via the injected `resolve_did_keys`
    seam. SECURE BY DEFAULT: without that seam there is NO independent proof, so this FAILS
    CLOSED (`did_membership_unverifiable`) unless the caller explicitly attests its
    `resolve_key` is authoritative via `trust_resolve_key_authority`.
    """
    if deps.resolve_did_keys is None:
        if not deps.trust_resolve_key_authority:
            reasons.append("did_membership_unverifiable")
        return
    try:
        did_keys = await deps.resolve_did_keys(did)
    except Exception:
        reasons.append("did_keys_unresolvable")
        return
    try:
        key_jkt = _thumbprint(key)
        published = [_thumbprint(k) for k in did_keys]
    except Exception:
        reasons.append("thumbprint_computation_failed")
        return
    if key_jkt not in published:
        reasons.append("kid_not_in_did_document")


async def _consume_nonce(meta: CardProofMeta, deps: VerifyProofDeps, reasons: list[str]) -> None:
    """Atomically CONSUME the nonce via the injected `consume_nonce_if_fresh` replay seam
    (test-and-set). `False` is a replay (`nonce_replayed`). When the seam is not supplied
    there is no replay defense to run, so this FAILS CLOSED (`nonce_seam_missing`).
    """
    consume = deps.consume_nonce_if_fresh
    if consume is None:
        reasons.append("nonce_seam_missing")
        return
    try:
        min_ttl_sec = _nonce_retention_seconds(1, meta.expires + deps.skew_sec, deps.now())
        if (await consume(meta.nonce, meta.did, min_ttl_sec)) is not True:
            reasons.append("nonce_replayed")
    except Exception:
        reasons.append("nonce_cache_unavailable")


def _nonce_retention_seconds(configured_ttl_seconds: float, valid_until_seconds: float, now_ms: float) -> int:
    return max(1, int(configured_ttl_seconds), math.ceil(valid_until_seconds + 1 - now_ms / 1000))


def _check_window(meta: CardProofMeta, deps: VerifyProofDeps, reasons: list[str]) -> None:
    """Enforce the created/expires window: sane bounds, capped TTL, and +-skew freshness."""
    skew = deps.skew_sec
    now = int(deps.now() / 1000)
    if meta.expires <= meta.created:
        reasons.append("invalid_window")
    if meta.expires - meta.created > MAX_TTL_SEC:
        reasons.append("ttl_too_long")
    if meta.created > now + skew:
        reasons.append("created_in_future")
    if meta.expires < now - skew:
        reasons.append("expired")


def _decode_header(b64: str) -> Optional[dict[str, Any]]:
    if not b64:
        return None
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _verify_detached_jws(meta: CardProofMeta, key: dict[str, Any]) -> bool:
    """Verify the DETACHED JWS over the reconstructed covered claims. The header is NOT
    trusted: its `alg` MUST equal the signed `meta.alg`, and its `kid` MUST equal `meta.kid`.
    The payload is recomputed from the meta (JCS), so any tampered covered field yields a
    different signing input.
    """
    parts = meta.jws.split(".")
    if len(parts) != 3 or parts[1] != "":
        return False
    protected_b64, _, signature_b64 = parts
    header = _decode_header(protected_b64)
    if header is None or header.get("alg") != meta.alg or header.get("kid") != meta.kid:
        return False
    try:
        payload_b64 = base64.urlsafe_b64encode(canonical_payload_bytes(meta)).rstrip(b"=").decode("ascii")
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
        if meta.alg == "EdDSA":
            return _ed25519_verify(key, signature, signing_input)
        return _es256_jws_verify(key, signature, signing_input)
    except Exception:
        return False


def _ed25519_verify(key: dict[str, Any], signature: bytes, data: bytes) -> bool:
    x = key["x"]
    public_bytes = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    if len(public_bytes) != ED25519_KEY_SIZE or is_small_order_ed25519_key(public_bytes):
        return False
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def _es256_jws_verify(key: dict[str, Any], signature: bytes, data: bytes) -> bool:
    """JWS ES256 signatures are the raw `r || s` concatenation (RFC 7518 §3.4), not ASN.1
    DER - `cryptography`'s ECDSA primitives expect DER, so this converts.
    """
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_signature = encode_dss_signature(r, s)
    x = key["x"]
    y = key["y"]
    x_bytes = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    y_bytes = base64.urlsafe_b64decode(y + "=" * (-len(y) % 4))
    public_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x_bytes, "big"), int.from_bytes(y_bytes, "big"), ec.SECP256R1()
    )
    public_key = public_numbers.public_key()
    try:
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _key_matches_alg(key: dict[str, Any], alg: str) -> bool:
    """True iff the resolved key's type is the one the declared `alg` requires (anti-
    confusion).
    """
    if alg == "ES256":
        return key.get("kty") == "EC" and key.get("crv") == "P-256"
    return key.get("kty") == "OKP" and key.get("crv") == "Ed25519"


async def _check_cnf_fusion(
    meta: CardProofMeta, key: dict[str, Any], deps: VerifyProofDeps, reasons: list[str], warnings: list[str]
) -> str:
    """The `cnf.jkt` fusion (SPEC §8): a present `cnf.jkt` MUST equal the signing key's
    thumbprint, and when the AS supplies a token `cnf.jkt` the three MUST fuse for L3. No
    token `cnf` degrades to L3-minus; a token `cnf` with no proof `cnf` is a downgrade attack
    and fails closed.
    """
    try:
        key_jkt = _thumbprint(key)
    except Exception:
        reasons.append("thumbprint_computation_failed")
        return "L3-minus"

    if meta.cnf is not None and meta.cnf.jkt != key_jkt:
        reasons.append("cnf_key_mismatch")

    if deps.token_cnf_jkt is None:
        # No token cnf.jkt was supplied, so there is nothing to fuse against and assurance
        # is L3-minus. If the client nonetheless presented a sender-constraint, the proof
        # was CAPABLE of L3 - it degraded only because token_cnf_jkt was not wired. A
        # warning, not a failure.
        if meta.cnf is not None:
            warnings.append("cnf_present_but_token_unfused")
        return "L3-minus"

    if meta.cnf is None:
        reasons.append("cnf_required_by_token")
        return "L3-minus"

    if meta.cnf.jkt != deps.token_cnf_jkt:
        reasons.append("cnf_token_mismatch")
        return "L3-minus"

    return "L3" if meta.cnf.jkt == key_jkt else "L3-minus"


def _thumbprint(key: dict[str, Any]) -> str:
    """The RFC 7638 thumbprint of a public JWK, projected to its canonical members only."""
    jwk = _to_jwk(key)
    ordered = {k: jwk[k] for k in sorted(jwk.keys())}
    canonical = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode("ascii")


def _to_jwk(key: dict[str, Any]) -> dict[str, Any]:
    """Project a proof public JWK to its canonical members (drop `kid`/`use`; EC carries
    `x`+`y`).
    """
    if key.get("kty") == "EC":
        return {"kty": "EC", "crv": "P-256", "x": key["x"], "y": key["y"]}
    return {"kty": "OKP", "crv": "Ed25519", "x": key["x"]}
