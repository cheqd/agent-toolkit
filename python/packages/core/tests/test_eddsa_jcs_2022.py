# SPDX-License-Identifier: Apache-2.0
# Tests verify_eddsa_jcs_2022 against a real, hand-signed DataIntegrityProof/eddsa-jcs-2022
# document, signed here (not imported), since this module is a verifier only.
import base64
import hashlib
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity.agent_card.retrieve_public_key import MinimalDidDocument, MinimalVerificationMethod
from cheqd_agent_identity.proof.eddsa_jcs_2022 import verify_eddsa_jcs_2022

DID = "did:web:issuer.example"
KID = f"{DID}#key-1"

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    if len(data) == 0:
        return ""
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        out = BASE58_ALPHABET[remainder] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


def sign(document: dict, verification_method: str, private_key: Ed25519PrivateKey) -> dict:
    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
    }
    proof_hash = hashlib.sha256(rfc8785.dumps(proof_options)).digest()
    document_hash = hashlib.sha256(rfc8785.dumps(document)).digest()
    signature = private_key.sign(proof_hash + document_hash)
    return {**document, "proof": {**proof_options, "proofValue": f"z{base58_encode(signature)}"}}


def world():
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    public_key_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_key_bytes).rstrip(b"=").decode("ascii"),
    }

    async def resolve_did_document(did):
        if did != DID:
            return None
        return MinimalDidDocument(
            id=DID, verification_method=(MinimalVerificationMethod(id=KID, public_key_jwk=public_key_jwk),)
        )

    return private_key, resolve_did_document


async def test_a_validly_signed_document_verifies():
    private_key, resolve_did_document = world()
    document = sign({"issuer": DID, "value": "hello"}, KID, private_key)
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is True


async def test_a_tampered_document_fails():
    private_key, resolve_did_document = world()
    document = sign({"issuer": DID, "value": "hello"}, KID, private_key)
    tampered = {**document, "value": "tampered"}
    assert await verify_eddsa_jcs_2022(tampered, resolve_did_document) is False


async def test_a_verification_method_belonging_to_a_different_did_than_issuer_fails():
    private_key, resolve_did_document = world()
    document = sign({"issuer": "did:web:someone-else.example", "value": "hello"}, KID, private_key)
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


async def test_an_unresolvable_issuer_did_fails():
    private_key, _ = world()
    document = sign({"issuer": DID, "value": "hello"}, KID, private_key)

    async def resolve_none(_did):
        return None

    assert await verify_eddsa_jcs_2022(document, resolve_none) is False


async def test_a_document_with_no_proof_fails():
    _, resolve_did_document = world()
    assert await verify_eddsa_jcs_2022({"issuer": DID, "value": "hello"}, resolve_did_document) is False


async def test_signed_by_a_key_not_published_in_the_resolved_did_document_fails():
    wrong_key = Ed25519PrivateKey.generate()
    _, resolve_did_document = world()
    document = sign({"issuer": DID, "value": "hello"}, KID, wrong_key)
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False
