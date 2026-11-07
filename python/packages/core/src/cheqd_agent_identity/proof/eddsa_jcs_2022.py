"""A generic `DataIntegrityProof`/`eddsa-jcs-2022` verifier for an arbitrary document - the
proof options without `proofValue` (carrying the document's `@context`), and the document
without `proof`, each JCS-canonicalized and SHA-256 hashed; Ed25519 over the concatenation;
`proofValue` base58btc multibase.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Awaitable, Callable, Optional

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cheqd_agent_identity.agent_card.retrieve_public_key import MinimalDidDocument, key_from_document

MAX_PROOF_VALUE_BASE58_LEN = 100
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_ALPHABET_MAP = {char: index for index, char in enumerate(BASE58_ALPHABET)}

ResolveDidDocument = Callable[[str], Awaitable[Optional[MinimalDidDocument]]]


def _base58_decode(encoded: str, max_len: int) -> bytes:
    if len(encoded) > max_len:
        raise ValueError("base58_too_long")
    num = 0
    for char in encoded:
        index = BASE58_ALPHABET_MAP.get(char)
        if index is None:
            raise ValueError("invalid_base58_character")
        num = num * 58 + index
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = 0
    for char in encoded:
        if char != "1":
            break
        leading_zeros += 1
    return bytes(leading_zeros) + body


def _canonicalize(value: Any) -> bytes:
    return rfc8785.dumps(value)


def _issuer_of(document: dict[str, Any]) -> Optional[str]:
    issuer = document.get("issuer")
    if isinstance(issuer, str):
        return issuer
    if isinstance(issuer, dict) and isinstance(issuer.get("id"), str):
        return issuer["id"]
    return None


def _contexts(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


async def verify_eddsa_jcs_2022(document: Any, resolve_did_document: ResolveDidDocument) -> bool:
    """Verify `document`'s `DataIntegrityProof`/`eddsa-jcs-2022` proof. `resolve_did_document`
    resolves the DID the proof's `verificationMethod` names - the caller decides which
    resolver(s) to trust. Fails closed: any malformed, mismatched or unverifiable input returns
    `False`, never raises past this boundary.
    """
    try:
        if not isinstance(document, dict):
            return False
        proof = document.get("proof")
        if not isinstance(proof, dict):
            return False
        if proof.get("type") != "DataIntegrityProof" or proof.get("cryptosuite") != "eddsa-jcs-2022":
            return False
        if proof.get("proofPurpose") != "assertionMethod":
            return False
        proof_value = proof.get("proofValue")
        verification_method = proof.get("verificationMethod")
        if not isinstance(proof_value, str) or not proof_value.startswith("z"):
            return False
        if not isinstance(verification_method, str):
            return False

        issuer = _issuer_of(document)
        did = verification_method.split("#")[0]
        if issuer is None or did != issuer:
            return False

        signature = _base58_decode(proof_value[1:], MAX_PROOF_VALUE_BASE58_LEN)
        if len(signature) != 64:
            return False

        did_document = await resolve_did_document(did)
        if did_document is None:
            return False
        try:
            jwk = key_from_document(did_document, verification_method)
        except Exception:
            return False
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return False

        unsecured = dict(document)
        unsecured.pop("proof", None)
        options = dict(proof)
        options.pop("proofValue", None)
        if options.get("@context") is not None:
            document_contexts = [_canonicalize(c) for c in _contexts(document.get("@context"))]
            options_contexts = [_canonicalize(c) for c in _contexts(options.get("@context"))]
            if len(options_contexts) > len(document_contexts):
                return False
            if not all(oc == document_contexts[i] for i, oc in enumerate(options_contexts)):
                return False
            unsecured["@context"] = options["@context"]
        if unsecured.get("@context") is not None:
            options["@context"] = unsecured["@context"]

        proof_hash = hashlib.sha256(_canonicalize(options)).digest()
        document_hash = hashlib.sha256(_canonicalize(unsecured)).digest()
        signing_input = proof_hash + document_hash

        x = jwk.get("x")
        if not isinstance(x, str):
            return False
        padded = x + "=" * (-len(x) % 4)
        public_key_bytes = base64.urlsafe_b64decode(padded)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(signature, signing_input)
        except InvalidSignature:
            return False
        return True
    except Exception:
        return False
