# SPDX-License-Identifier: Apache-2.0
# End-to-end test of create_cheqd_status_checker: a real eddsa-jcs-2022-signed
# BitstringStatusListCredential, with a real gzip-compressed encodedList, verified by the
# issuer's did:cheqd-resolved key, then read for a specific index - the decision-6 path D10
# originally left unported for lack of a Python consumer. Ported from @kya-os/mcp/card's
# eddsa-jcs-status.ts.
import base64
import gzip
import hashlib
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity.agent_card.retrieve_public_key import MinimalDidDocument, MinimalVerificationMethod
from cheqd_agent_identity.status.eddsa_jcs_status import (
    CheqdStatusCheckerOptions,
    create_cheqd_status_checker,
)
from cheqd_agent_identity.status.ledger_anchored import StatusEntry

DID = "did:cheqd:testnet:issuer"
KID = f"{DID}#key-1"

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    if len(data) == 0:
        return ""
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        out = BASE58_ALPHABET[remainder] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


def _sign(document: dict, verification_method: str, private_key: Ed25519PrivateKey) -> dict:
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
    return {**document, "proof": {**proof_options, "proofValue": f"z{_base58_encode(signature)}"}}


def _encode_list(bits: bytes) -> str:
    compressed = gzip.compress(bits)
    return "u" + base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")


class _Response:
    def __init__(self, body):
        self.ok = True
        self.status = 200
        self._body = body

    async def json(self):
        return self._body


def _world(bits: bytes):
    private_key = Ed25519PrivateKey.generate()
    public_key_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(private_key.public_key().public_bytes_raw())
        .rstrip(b"=")
        .decode("ascii"),
    }
    credential = _sign(
        {
            "issuer": DID,
            "credentialSubject": {"statusPurpose": "revocation", "encodedList": _encode_list(bits)},
        },
        KID,
        private_key,
    )

    async def resolve_did_cheqd(did):
        if did != DID:
            return None
        return MinimalDidDocument(
            id=DID, verification_method=(MinimalVerificationMethod(id=KID, public_key_jwk=public_key_jwk),)
        )

    async def fetch(_url):
        return _Response(credential)

    checker = create_cheqd_status_checker(
        CheqdStatusCheckerOptions(resolve_did_cheqd=resolve_did_cheqd, fetch=fetch)
    )
    return checker


async def test_a_revoked_bit_in_a_genuinely_signed_list_reads_as_revoked():
    checker = _world(bytes([0b10000000]))
    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    verdict = await checker(entry)
    assert verdict.revoked is True


async def test_a_clear_bit_in_a_genuinely_signed_list_reads_as_not_revoked():
    checker = _world(bytes([0b00000000]))
    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    verdict = await checker(entry)
    assert verdict.revoked is False


async def test_a_list_whose_proof_was_tampered_with_fails_closed_to_revoked():
    checker = _world(bytes([0b00000000]))
    # Tamper with the credential AFTER it was signed and fetched, by monkeypatching fetch to
    # return a modified copy - simulates a MITM/compromised host serving altered bits under a
    # still-attached (but now invalid) proof.
    private_key = Ed25519PrivateKey.generate()
    public_key_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(private_key.public_key().public_bytes_raw())
        .rstrip(b"=")
        .decode("ascii"),
    }
    credential = _sign(
        {
            "issuer": DID,
            "credentialSubject": {
                "statusPurpose": "revocation",
                "encodedList": _encode_list(bytes([0b00000000])),
            },
        },
        KID,
        private_key,
    )
    tampered = {
        **credential,
        "credentialSubject": {
            **credential["credentialSubject"],
            "statusPurpose": "revocation",
            "encodedList": _encode_list(bytes([0b10000000])),
        },
    }

    async def resolve_did_cheqd(did):
        if did != DID:
            return None
        return MinimalDidDocument(
            id=DID, verification_method=(MinimalVerificationMethod(id=KID, public_key_jwk=public_key_jwk),)
        )

    async def fetch(_url):
        return _Response(tampered)

    checker = create_cheqd_status_checker(
        CheqdStatusCheckerOptions(resolve_did_cheqd=resolve_did_cheqd, fetch=fetch)
    )
    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    verdict = await checker(entry)
    assert verdict.revoked is True
