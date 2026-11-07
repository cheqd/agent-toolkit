"""The legacy MCP-style RESPONSE proof (`org.kya-os/response-proof`) - a from-spec
re-implementation of `@kya-os/mcp`'s `src/proof/generator.ts` and `src/proof/verifier.ts` (read
directly from `node_modules/@kya-os/mcp/dist`, MIT-licensed), scoped to exactly what
`wrapper.py` (sign) and the client interceptor (verify) use - see docs/design-decisions.md D14.

Distinct from `org.kya-os/proof.v1` (the `canonical.py`/`build.py`/`verify.py` modules in this
same package): this is a full (non-detached) compact Ed25519 JWS, used by the SERVER to prove
its RESPONSE is genuine, the opposite direction from proof.v1's client-request binding. Not
ported: the `verifyProofArtifact`/`verifyProofDetached` (deprecated) paths, DID-based key
resolution (`fetchPublicKeyFromDID` - this package's caller always pins the server's key
itself, matching client.ts's own `serverPublicJwk` option), and the MCP `_meta`-key-tolerance
helpers (`extractProofFromMeta`/`validateMetaStructure` - A2A reads `RESPONSE_PROOF_META_KEY`
directly, never through MCP's `_meta` namespace).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal, Optional, Union

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RESPONSE_PROOF_PROFILE_BODY = "org.kya-os/response-proof.body"
RESPONSE_PROOF_PROFILE_ENVELOPE = "org.kya-os/response-proof.envelope"
ResponseProofProfile = Literal["org.kya-os/response-proof.body", "org.kya-os/response-proof.envelope"]


@dataclass(frozen=True)
class CanonicalRequest:
    method: str
    params: Any = None


@dataclass(frozen=True)
class CanonicalResponse:
    data: Any


def _canonicalize(value: Any) -> bytes:
    return rfc8785.dumps(value)


def _sha256_hex(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_response_body(data: Any, profile: ResponseProofProfile) -> Any:
    """The profile-selected response material that `response_hash` covers. The body profile
    hashes `data` verbatim; the envelope profile removes the top-level `_meta` member from an
    object envelope only.
    """
    if profile != RESPONSE_PROOF_PROFILE_ENVELOPE or not isinstance(data, dict):
        return data
    return {k: v for k, v in data.items() if k != "_meta"}


def compute_canonical_hashes(
    request: CanonicalRequest,
    response: Optional[CanonicalResponse] = None,
    profile: ResponseProofProfile = RESPONSE_PROOF_PROFILE_BODY,
) -> tuple[str, Optional[str]]:
    """`request_hash` = SHA-256 over RFC 8785 `canonicalize({method, params})`. `response_hash`
    (omitted when there is no response body) depends on the response-proof profile - see
    `_canonical_response_body`.
    """
    canonical_request: dict[str, Any] = {"method": request.method}
    if request.params is not None:
        canonical_request["params"] = request.params
    request_hash = _sha256_hex(_canonicalize(canonical_request))
    if response is None:
        return request_hash, None
    response_hash = _sha256_hex(_canonicalize(_canonical_response_body(response.data, profile)))
    return request_hash, response_hash


@dataclass(frozen=True)
class ResponseProofMeta:
    did: str
    kid: str
    ts: int
    nonce: str
    audience: str
    session_id: str
    request_hash: str
    response_hash: Optional[str] = None
    scope_id: Optional[str] = None
    delegation_ref: Optional[str] = None
    client_did: Optional[str] = None
    outcome: Optional[str] = None
    reason: Optional[str] = None
    prf: Optional[str] = None


def build_proof_jws_payload(meta: ResponseProofMeta) -> dict[str, Any]:
    """Build the exact JWS payload object a proof signs over, from its meta. SINGLE source of
    truth for the payload SHAPE, shared by the signer and verifier.
    """
    payload: dict[str, Any] = {
        "aud": meta.audience,
        "sub": meta.did,
        "iss": meta.did,
        "requestHash": meta.request_hash,
    }
    if meta.response_hash is not None:
        payload["responseHash"] = meta.response_hash
    payload.update({"ts": meta.ts, "nonce": meta.nonce, "sessionId": meta.session_id})
    if meta.scope_id is not None:
        payload["scopeId"] = meta.scope_id
    if meta.delegation_ref is not None:
        payload["delegationRef"] = meta.delegation_ref
    if meta.client_did is not None:
        payload["clientDid"] = meta.client_did
    if meta.outcome is not None:
        payload["outcome"] = meta.outcome
    if meta.reason is not None:
        payload["reason"] = meta.reason
    if meta.prf is not None:
        payload["prf"] = meta.prf
    return payload


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass(frozen=True)
class ResponseProofIdentity:
    did: str
    kid: str
    private_key: Ed25519PrivateKey


@dataclass(frozen=True)
class ResponseProofSession:
    session_id: str
    audience: str


def _random_nonce() -> str:
    return _b64url(secrets.token_bytes(16))


def _now_ms() -> float:
    return time.time() * 1000


async def generate_response_proof(
    request: CanonicalRequest,
    response: Optional[CanonicalResponse],
    identity: ResponseProofIdentity,
    session: ResponseProofSession,
    *,
    profile: ResponseProofProfile = RESPONSE_PROOF_PROFILE_BODY,
    now: Callable[[], float] = _now_ms,
) -> dict[str, Any]:
    """Generate a detached (well, embedded - see module docstring) proof for an A2A response.
    Binds `request_hash` -> `request`, `response_hash` -> `response` (profile-dependent), and
    signs with `identity`'s key. `now` returns epoch MILLISECONDS, matching this package's
    convention elsewhere.
    """
    request_hash, response_hash = compute_canonical_hashes(request, response, profile)
    meta = ResponseProofMeta(
        did=identity.did,
        kid=identity.kid,
        ts=int(now() / 1000),
        nonce=_random_nonce(),
        audience=session.audience,
        session_id=session.session_id,
        request_hash=request_hash,
        response_hash=response_hash,
        prf=RESPONSE_PROOF_PROFILE_ENVELOPE if profile == RESPONSE_PROOF_PROFILE_ENVELOPE else None,
    )
    jws = _sign(meta, identity.private_key)
    return {"jws": jws, "meta": _meta_to_wire(meta)}


def _sign(meta: ResponseProofMeta, private_key: Ed25519PrivateKey) -> str:
    payload = build_proof_jws_payload(meta)
    protected = _b64url(json.dumps({"alg": "EdDSA", "kid": meta.kid}, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(_canonicalize(payload))
    signing_input = f"{protected}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input)
    return f"{protected}.{payload_b64}.{_b64url(signature)}"


def _meta_to_wire(meta: ResponseProofMeta) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "did": meta.did,
        "kid": meta.kid,
        "ts": meta.ts,
        "nonce": meta.nonce,
        "audience": meta.audience,
        "sessionId": meta.session_id,
        "requestHash": meta.request_hash,
    }
    if meta.response_hash is not None:
        wire["responseHash"] = meta.response_hash
    if meta.prf is not None:
        wire["prf"] = meta.prf
    return wire


def _wire_to_meta(wire: dict[str, Any]) -> Optional[ResponseProofMeta]:
    """Validate a `DetachedProof.meta`-shaped dict, matching `validateDetachedProof`'s checks
    in the TypeScript original. Returns `None` on anything malformed.
    """
    for field_name in ("did", "kid", "nonce", "audience", "sessionId"):
        if not isinstance(wire.get(field_name), str) or len(wire[field_name]) == 0:
            return None
    ts = wire.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0:
        return None
    request_hash = wire.get("requestHash")
    if not isinstance(request_hash, str) or not re.match(r"^sha256:[a-f0-9]{64}$", request_hash):
        return None
    response_hash = wire.get("responseHash")
    if response_hash is not None and (
        not isinstance(response_hash, str) or not re.match(r"^sha256:[a-f0-9]{64}$", response_hash)
    ):
        return None
    prf = wire.get("prf")
    if prf is not None and prf != RESPONSE_PROOF_PROFILE_ENVELOPE:
        return None
    return ResponseProofMeta(
        did=wire["did"],
        kid=wire["kid"],
        ts=ts,
        nonce=wire["nonce"],
        audience=wire["audience"],
        session_id=wire["sessionId"],
        request_hash=request_hash,
        response_hash=response_hash,
        prf=prf,
    )


@dataclass(frozen=True)
class ResponseProofVerifyOk:
    valid: bool = True


@dataclass(frozen=True)
class ResponseProofVerifyFailed:
    reason: str
    valid: bool = False


ResponseProofVerifyResult = Union[ResponseProofVerifyOk, ResponseProofVerifyFailed]

ConsumeNonceIfFresh = Callable[[str, str, int], Awaitable[bool]]


def _did_of_kid(kid: str) -> Optional[str]:
    return kid.split("#")[0] if kid.startswith("did:") else None


async def verify_response_proof(
    proof: Any,
    public_key_jwk: dict[str, Any],
    expected: Optional[tuple[CanonicalRequest, Optional[CanonicalResponse]]] = None,
    *,
    expected_did: Optional[str] = None,
    expected_audience: Optional[str] = None,
    consume_nonce_if_fresh: Optional[ConsumeNonceIfFresh] = None,
    now: Callable[[], float] = _now_ms,
    skew_sec: int = 120,
) -> ResponseProofVerifyResult:
    """Verify a response proof: authenticity (the detached-style JWS over the covered claims),
    signer binding (kid/did/audience), timestamp freshness, optional content binding against
    `expected` (the request/response actually seen - detects substitution), and replay.
    """
    if not isinstance(proof, dict):
        return ResponseProofVerifyFailed(reason="Invalid proof structure")
    jws = proof.get("jws")
    if not isinstance(jws, str) or len(jws) == 0:
        return ResponseProofVerifyFailed(reason="Invalid proof structure")
    meta = _wire_to_meta(proof.get("meta"))
    if meta is None:
        return ResponseProofVerifyFailed(reason="Invalid proof structure")

    kid_owner = _did_of_kid(meta.kid)
    if kid_owner is not None and kid_owner != meta.did:
        return ResponseProofVerifyFailed(reason="Proof kid names a key of a different DID than meta.did")
    if expected_did is not None and meta.did != expected_did:
        return ResponseProofVerifyFailed(reason="Proof was not issued by the expected DID")
    if expected_audience is not None and meta.audience != expected_audience:
        return ResponseProofVerifyFailed(reason="Proof is addressed to a different audience")

    now_ms = now()
    ts_ms = meta.ts * 1000
    if abs(now_ms - ts_ms) > skew_sec * 1000:
        return ResponseProofVerifyFailed(reason=f"Timestamp out of skew window (skew: {skew_sec}s)")

    if not _verify_signature(jws, meta, public_key_jwk):
        return ResponseProofVerifyFailed(reason="Invalid JWS signature")

    if expected is not None:
        mismatch = _content_binding_mismatch(meta, expected)
        if mismatch is not None:
            return ResponseProofVerifyFailed(reason=mismatch)

    if consume_nonce_if_fresh is not None:
        ok = await consume_nonce_if_fresh(meta.nonce, meta.did, skew_sec)
        if ok is not True:
            return ResponseProofVerifyFailed(reason="Nonce already used (replay attack detected)")

    return ResponseProofVerifyOk()


def _verify_signature(jws: str, meta: ResponseProofMeta, public_key_jwk: dict[str, Any]) -> bool:
    if public_key_jwk.get("kty") != "OKP" or public_key_jwk.get("crv") != "Ed25519":
        return False
    x = public_key_jwk.get("x")
    if not isinstance(x, str) or len(x) == 0:
        return False
    # The supplied JWK must itself declare the kid it was resolved for, matching the proof's
    # own kid - an extra integrity check against a misconfigured/stale key resolver/cache,
    # matching `CryptoService.verifyJWS`'s `expectedKid` check in the TypeScript original
    # (confirmed via a real cross-language conformance run, not assumed - see
    # docs/design-decisions.md D14).
    if public_key_jwk.get("kid") != meta.kid:
        return False
    parts = jws.split(".")
    if len(parts) != 3:
        return False
    protected_b64 = parts[0]
    try:
        header = json.loads(_b64url_decode(protected_b64))
    except Exception:
        return False
    if header.get("alg") != "EdDSA" or header.get("kid") != meta.kid:
        return False
    # Recompute the payload from meta (never trust the JWS's own embedded payload) - the
    # same rule `CryptoService.verifyJWS`'s `detachedPayload` option enforces.
    payload_b64 = _b64url(_canonicalize(build_proof_jws_payload(meta)))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    try:
        signature = _b64url_decode(parts[2])
        public_bytes = _b64url_decode(x)
        if len(public_bytes) != 32:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, signing_input)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _content_binding_mismatch(
    meta: ResponseProofMeta, expected: tuple[CanonicalRequest, Optional[CanonicalResponse]]
) -> Optional[str]:
    """Recompute the canonical hashes of the request/response actually received and compare
    to the proof's bound hashes - the check that detects content substitution (e.g. a
    MITM-swapped response).
    """
    expected_request, expected_response = expected
    profile: ResponseProofProfile = (
        RESPONSE_PROOF_PROFILE_ENVELOPE
        if meta.prf == RESPONSE_PROOF_PROFILE_ENVELOPE
        else RESPONSE_PROOF_PROFILE_BODY
    )
    request_hash, response_hash = compute_canonical_hashes(expected_request, expected_response, profile)
    if meta.request_hash != request_hash:
        return "Request hash mismatch: the proof does not bind the request you supplied"
    binds_response = meta.response_hash is not None
    if binds_response != (expected_response is not None):
        if binds_response:
            return "Proof binds a response but no response was supplied to verify against"
        return "A response was supplied but the proof binds none - content/proof mismatch"
    if binds_response and meta.response_hash != response_hash:
        return "Response hash mismatch: received content differs from what the server signed"
    return None
