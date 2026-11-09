"""A DID-backed retrieve_public_key callback, for whatever A2A SDK hook needs one.

A2A §8.4.3, as currently published, says to retrieve the key "using the `kid` and `jku`",
which lets a signer nominate its own trust root (CWE-863: a verifier that fetches `jku`
verifies against whatever key the ATTACKER serves there, not the key the caller actually
trusts). This implementation never reads `jku` - it is accepted only so the callback shape
matches the SDK's, and resolves strictly by `kid`, against DID documents it chooses to trust.

Supports `did:web` (a real HTTPS fetch, injected) and `did:key` (Ed25519 only, pure
computation, no fetch). `did:cheqd` is opt-in only, via an injected resolver - this module has
no network dependency of its own for it.

Fails closed - raises `KeyResolutionError`, never anything else - on: an unsupported DID
method, a malformed DID, `kid` not matching `expected_did` (when given), a `kid` the resolved
document does not publish, transport failure, invalid JSON, or a malformed DID document.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Optional, Protocol, Sequence

import httpx

PublicKeyJwk = dict[str, Any]

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_ALPHABET_MAP = {char: index for index, char in enumerate(BASE58_ALPHABET)}


class KeyResolutionError(Exception):
    """Raised, with a stable machine-readable reason, whenever a key cannot be resolved."""


def _fail(reason: str) -> None:
    raise KeyResolutionError(reason)


@dataclass(frozen=True)
class MinimalVerificationMethod:
    id: str
    controller: Optional[str] = None
    public_key_jwk: Optional[Mapping[str, Any]] = None
    public_key_multibase: Optional[str] = None
    public_key_base58: Optional[str] = None


@dataclass(frozen=True)
class MinimalDidDocument:
    id: str
    verification_method: Sequence[MinimalVerificationMethod] = field(default_factory=tuple)


class DidWebResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


FetchDidWebDocument = Callable[[str], Awaitable[DidWebResponse]]
ResolveDidCheqd = Callable[[str], Awaitable[Optional[MinimalDidDocument]]]


async def _default_fetch_did_web(url: str) -> DidWebResponse:
    async with httpx.AsyncClient() as client:
        return await client.get(url)


def create_retrieve_public_key(
    *,
    expected_did: Optional[str] = None,
    fetch_did_web_document: Optional[FetchDidWebDocument] = None,
    resolve_did_cheqd: Optional[ResolveDidCheqd] = None,
) -> Callable[[str, Optional[str]], Awaitable[PublicKeyJwk]]:
    """Build a `retrieve_public_key(kid, jku)` callback. `jku` is accepted for shape
    compatibility and never read.
    """
    fetch_did_web = fetch_did_web_document or _default_fetch_did_web

    async def retrieve_public_key(kid: str, _jku: Optional[str] = None) -> PublicKeyJwk:
        hash_index = kid.find("#")
        if hash_index < 0:
            _fail("kid_missing_fragment")
        did = kid[:hash_index]
        if expected_did is not None and did != expected_did:
            _fail("kid_wrong_did")

        if did.startswith("did:key:"):
            return _resolve_did_key(did, kid)
        if did.startswith("did:web:"):
            return await _resolve_did_web(did, kid, fetch_did_web)
        if did.startswith("did:cheqd:"):
            if resolve_did_cheqd is None:
                _fail("did_cheqd_resolution_not_configured")
            document = await resolve_did_cheqd(did)
            if document is None:
                _fail("did_cheqd_unresolvable")
            return key_from_document(document, kid)
        _fail("unsupported_did_method")

    return retrieve_public_key


def key_from_document(document: MinimalDidDocument, kid: str) -> PublicKeyJwk:
    """Exported for reuse by other modules that already hold a resolved DID document and a
    `kid` (e.g. the AP2 package's generic DataIntegrityProof verifier).
    """
    method = next(
        (m for m in document.verification_method if _method_id(m, document.id) == kid),
        None,
    )
    if method is None:
        _fail("kid_not_in_document")
    if method.public_key_jwk:
        jwk = dict(method.public_key_jwk)
        if not isinstance(jwk.get("kty"), str):
            _fail("malformed_public_key_jwk")
        return jwk
    if method.public_key_multibase:
        return _jwk_from_ed25519_multibase(method.public_key_multibase)
    if method.public_key_base58:
        return _jwk_from_ed25519_base58(method.public_key_base58)
    _fail("unsupported_key_encoding")


def _method_id(method: MinimalVerificationMethod, did: str) -> str:
    return f"{did}{method.id}" if method.id.startswith("#") else method.id


async def _resolve_did_web(did: str, kid: str, fetch_did_web: FetchDidWebDocument) -> PublicKeyJwk:
    url = _did_web_to_url(did)
    try:
        response = await fetch_did_web(url)
    except Exception:
        _fail("did_web_fetch_failed")
    if response.status_code != 200:
        _fail("did_web_fetch_failed")
    try:
        document = response.json()
    except Exception:
        _fail("did_web_invalid_json")
    parsed = _parse_minimal_did_document(document)
    if parsed is None or parsed.id != did:
        _fail("did_web_document_mismatch")
    return key_from_document(parsed, kid)


def _did_web_to_url(did: str) -> str:
    rest = did[len("did:web:") :]
    if len(rest) == 0:
        _fail("malformed_did_web")
    segments = []
    for segment in rest.split(":"):
        try:
            segments.append(urllib.parse.unquote(segment, errors="strict"))
        except Exception:
            _fail("malformed_did_web")
    host = segments[0] if segments else ""
    if len(host) == 0:
        _fail("malformed_did_web")
    path = segments[1:]
    if not path:
        return f"https://{host}/.well-known/did.json"
    return f"https://{host}/{'/'.join(path)}/did.json"


def _parse_minimal_did_document(value: Any) -> Optional[MinimalDidDocument]:
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        return None
    raw_methods = value.get("verificationMethod")
    if raw_methods is not None and not isinstance(raw_methods, list):
        return None
    methods = []
    for raw in raw_methods or []:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            return None
        methods.append(
            MinimalVerificationMethod(
                id=raw["id"],
                controller=raw.get("controller"),
                public_key_jwk=raw.get("publicKeyJwk"),
                public_key_multibase=raw.get("publicKeyMultibase"),
                public_key_base58=raw.get("publicKeyBase58"),
            )
        )
    return MinimalDidDocument(id=value["id"], verification_method=tuple(methods))


def _resolve_did_key(did: str, kid: str) -> PublicKeyJwk:
    """`did:key` is self-certifying: the DID itself IS the key, under an Ed25519 multicodec
    prefix (varint 0xed01), base58btc-encoded with a leading `z`. No document fetch needed.
    """
    multibase = did[len("did:key:") :]
    if kid != f"{did}#{multibase}":
        _fail("kid_not_in_document")
    return _jwk_from_ed25519_multibase(multibase)


def _jwk_from_ed25519_multibase(multibase: str) -> PublicKeyJwk:
    if not multibase.startswith("z"):
        _fail("unsupported_multibase_encoding")
    decoded = _base58_decode(multibase[1:])
    # Multicodec varint for Ed25519 public key: 0xed 0x01.
    if len(decoded) != 34 or decoded[0] != 0xED or decoded[1] != 0x01:
        _fail("unsupported_key_type")
    x = _base64url_encode(decoded[2:])
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _jwk_from_ed25519_base58(encoded: str) -> PublicKeyJwk:
    """`publicKeyBase58` (the `Ed25519VerificationKey2018` legacy encoding, no multicodec
    prefix, no `z` multibase marker - plain base58btc over the raw 32-byte Ed25519 key).
    """
    decoded = _base58_decode(encoded)
    if len(decoded) != 32:
        _fail("unsupported_key_type")
    return {"kty": "OKP", "crv": "Ed25519", "x": _base64url_encode(decoded)}


def _base58_decode(encoded: str) -> bytes:
    if len(encoded) == 0:
        return b""
    num = 0
    for char in encoded:
        value = BASE58_ALPHABET_MAP.get(char)
        if value is None:
            _fail("invalid_base58")
        num = num * 58 + value
    leading_zeros = 0
    for char in encoded:
        if char != "1":
            break
        leading_zeros += 1
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return bytes(leading_zeros) + body


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
