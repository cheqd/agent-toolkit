"""A generic `DataIntegrityProof`/`eddsa-jcs-2022` verifier for an arbitrary document - the
proof options without `proofValue` (carrying the document's `@context`), and the document
without `proof`, each JCS-canonicalized and SHA-256 hashed; Ed25519 over the concatenation;
`proofValue` base58btc multibase.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cheqd_agent_identity.agent_card.retrieve_public_key import (
    MinimalDidDocument,
    assertion_method_key_from_document,
)

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


def _parse_date_ms(value: Any) -> Optional[float]:
    """Epoch milliseconds, or `None` if `value` is not a parseable date string. `None` must be
    treated by callers as INVALID, never as "not yet expired"/"not in the future" - see the
    class of bug PR #43 fixed in `ledger_anchored.py`'s `validUntil` handling, which this module
    follows for the same reason.
    """
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        return None


@dataclass(frozen=True)
class VerifyEddsaJcs2022Options:
    """Injectable clock returning epoch milliseconds (deterministic tests; default
    `datetime.now(timezone.utc)`). Used to validate `proof.expires`/`proof.created` when either
    is present.
    """

    now: Callable[[], float] = field(default=lambda: datetime.now(timezone.utc).timestamp() * 1000)


async def verify_eddsa_jcs_2022(
    document: Any,
    resolve_did_document: ResolveDidDocument,
    options: Optional[VerifyEddsaJcs2022Options] = None,
) -> bool:
    """Verify `document`'s `DataIntegrityProof`/`eddsa-jcs-2022` proof. `resolve_did_document`
    resolves the DID the proof's `verificationMethod` names - the caller decides which
    resolver(s) to trust. Fails closed: any malformed, mismatched or unverifiable input returns
    `False`, never raises past this boundary.

    `proof.expires`/`proof.created` are optional on the underlying data model and are validated
    only when present, against `options.now()`: an `expires` at or before now, or a `created`
    after now, fails - as does either field being present but not a parseable date string. An
    unparseable value fails CLOSED (treated as invalid), never open.
    """
    now = (options or VerifyEddsaJcs2022Options()).now
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

        expires = proof.get("expires")
        if expires is not None:
            expires_at = _parse_date_ms(expires)
            if expires_at is None or expires_at <= now():
                return False
        created = proof.get("created")
        if created is not None:
            created_at = _parse_date_ms(created)
            if created_at is None or created_at > now():
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
        # The injected resolver decides which DID(s) it trusts and how it resolves them, but
        # nothing about this module's own correctness may depend on it having already enforced
        # that the document it returns actually belongs to the DID it was asked to resolve. A lax
        # or buggy resolver (e.g. a simple in-memory map used in tests) could return a document
        # for a DIFFERENT DID than `did`, whose absolute-id assertion_method entries would
        # otherwise incorrectly pass `assertion_method_key_from_document`'s own
        # controller == document.id check.
        if did_document.id != did:
            return False
        try:
            # MUST be a key the document's own assertionMethod relationship publishes, with a
            # controller equal to the issuer - checking proof.proofPurpose == "assertionMethod"
            # above says what the PROOF claims; it says nothing about whether the key the proof
            # names is actually authorized to make that claim. A key listed only under
            # verification_method (or another relationship such as authentication) MUST NOT
            # verify here, even though it would resolve via the generic Agent Card key lookup.
            jwk = assertion_method_key_from_document(did_document, verification_method)
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
