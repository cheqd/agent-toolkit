# SPDX-License-Identifier: Apache-2.0
# Tests verify_agent_payment_key_credential and, via it, verify_cnf_continuity's
# authorised-secondary-key tier, against a REAL DataIntegrityProof/eddsa-jcs-2022-signed
# credential (same construction core's eddsa_jcs_2022.py verifies - signed here by hand, since
# core only ships a verifier, not a signer).
import base64
import hashlib
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity.agent_card.retrieve_public_key import MinimalDidDocument, MinimalVerificationMethod
from cheqd_agent_identity_ap2.cnf_fusion import verify_cnf_continuity
from cheqd_agent_identity_ap2.payment_key_authorization import (
    AgentPaymentKeyCredential,
    AgentPaymentKeyCredentialStatus,
    AgentPaymentKeyCredentialSubject,
    PaymentKeyAuthorizationDeps,
    verify_agent_payment_key_credential,
)

PRIMARY_DID = "did:web:agent.example"
PRIMARY_KID = f"{PRIMARY_DID}#key-1"

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


def jwk_of(private_key: Ed25519PrivateKey) -> dict:
    raw = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def sign_eddsa_jcs_2022(document: dict, verification_method: str, private_key: Ed25519PrivateKey) -> dict:
    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
    }
    unsecured = dict(document)
    options = dict(proof_options)
    if unsecured.get("@context") is not None:
        options["@context"] = unsecured["@context"]
    proof_hash = hashlib.sha256(rfc8785.dumps(options)).digest()
    document_hash = hashlib.sha256(rfc8785.dumps(unsecured)).digest()
    signature = private_key.sign(proof_hash + document_hash)
    return {**document, "proof": {**proof_options, "proofValue": f"z{base58_encode(signature)}"}}


def signed_credential(
    *, private_key: Ed25519PrivateKey, payment_key_jwk: dict, valid_until: str | None = None
) -> AgentPaymentKeyCredential:
    unsigned = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "AgentPaymentKeyCredential"],
        "issuer": PRIMARY_DID,
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        **({"validUntil": valid_until} if valid_until else {}),
        "credentialSubject": {"id": PRIMARY_DID, "paymentKeyJwk": payment_key_jwk},
        "credentialStatus": {
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListCredential": "https://status.example/list",
            "statusListIndex": "0",
        },
    }
    raw = sign_eddsa_jcs_2022(unsigned, PRIMARY_KID, private_key)
    return AgentPaymentKeyCredential(
        type=raw["type"],
        issuer=raw["issuer"],
        credential_subject=AgentPaymentKeyCredentialSubject(id=PRIMARY_DID, payment_key_jwk=payment_key_jwk),
        valid_until=raw.get("validUntil"),
        credential_status=AgentPaymentKeyCredentialStatus(
            type="BitstringStatusListEntry",
            status_purpose="revocation",
            status_list_credential="https://status.example/list",
            status_list_index="0",
        ),
        proof=raw["proof"],
        raw=raw,
    )


def deps_for(
    primary_public_key_jwk: dict, *, revoked: bool = False, fresh: bool = True
) -> PaymentKeyAuthorizationDeps:
    async def resolve_did_document(did: str):
        if did != PRIMARY_DID:
            return None
        return MinimalDidDocument(
            id=PRIMARY_DID,
            verification_method=(
                MinimalVerificationMethod(id=PRIMARY_KID, public_key_jwk=primary_public_key_jwk),
            ),
        )

    async def check_revoked(_credential):
        return (revoked, fresh)

    return PaymentKeyAuthorizationDeps(resolve_did_document=resolve_did_document, check_revoked=check_revoked)


async def test_a_validly_signed_non_revoked_payment_key_credential_verifies():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(private_key=private_key, payment_key_jwk=payment_key_jwk)
    result = await verify_agent_payment_key_credential(
        credential, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is True
    assert result.tier == "authorised-secondary-key"
    assert result.payment_key_jwk == payment_key_jwk


async def test_a_tampered_credential_payment_key_jwk_swapped_after_signing_is_rejected():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(private_key=private_key, payment_key_jwk=payment_key_jwk)
    tampered_jwk = jwk_of(Ed25519PrivateKey.generate())
    tampered_raw = {
        **credential.raw,
        "credentialSubject": {**credential.raw["credentialSubject"], "paymentKeyJwk": tampered_jwk},
    }
    tampered = AgentPaymentKeyCredential(
        type=credential.type,
        issuer=credential.issuer,
        credential_subject=AgentPaymentKeyCredentialSubject(id=PRIMARY_DID, payment_key_jwk=tampered_jwk),
        valid_until=credential.valid_until,
        credential_status=credential.credential_status,
        proof=credential.proof,
        raw=tampered_raw,
    )
    result = await verify_agent_payment_key_credential(
        tampered, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "proof_invalid"


async def test_a_revoked_payment_key_credential_is_rejected():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(private_key=private_key, payment_key_jwk=payment_key_jwk)
    result = await verify_agent_payment_key_credential(
        credential, PRIMARY_DID, deps_for(primary_public_key_jwk, revoked=True)
    )
    assert result.ok is False
    assert result.reason == "payment_key_revoked"


async def test_an_expired_payment_key_credential_is_rejected():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(
        private_key=private_key, payment_key_jwk=payment_key_jwk, valid_until="2020-01-01T00:00:00Z"
    )
    result = await verify_agent_payment_key_credential(
        credential, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "credential_expired"


async def test_a_credential_with_no_credential_status_is_rejected_fail_closed_never_optional():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    unsigned = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "AgentPaymentKeyCredential"],
        "issuer": PRIMARY_DID,
        "credentialSubject": {"id": PRIMARY_DID, "paymentKeyJwk": payment_key_jwk},
    }
    raw = sign_eddsa_jcs_2022(unsigned, PRIMARY_KID, private_key)
    credential = AgentPaymentKeyCredential(
        type=raw["type"],
        issuer=raw["issuer"],
        credential_subject=AgentPaymentKeyCredentialSubject(id=PRIMARY_DID, payment_key_jwk=payment_key_jwk),
        credential_status=None,
        proof=raw["proof"],
        raw=raw,
    )
    result = await verify_agent_payment_key_credential(
        credential, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "missing_credential_status"


async def test_verify_cnf_continuity_promotes_a_mandate_cnf_bound_to_the_authorised_secondary_key():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())
    agent_general_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(private_key=private_key, payment_key_jwk=payment_key_jwk)
    result = await verify_cnf_continuity(
        payment_key_jwk, agent_general_key_jwk, PRIMARY_DID, credential, deps_for(primary_public_key_jwk)
    )
    assert result.ok is True
    assert result.tier == "authorised-secondary-key"


async def test_verify_cnf_continuity_rejects_a_mandate_cnf_bound_to_neither_key():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())
    agent_general_key_jwk = jwk_of(Ed25519PrivateKey.generate())
    some_other_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(private_key=private_key, payment_key_jwk=payment_key_jwk)
    result = await verify_cnf_continuity(
        some_other_key_jwk, agent_general_key_jwk, PRIMARY_DID, credential, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "cnf_jwk_not_the_authorised_payment_key"
