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
    AGENT_PAYMENT_KEY_CREDENTIAL_TYPE,
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
    *,
    private_key: Ed25519PrivateKey,
    payment_key_jwk: dict,
    valid_until: str | None = None,
    valid_from: str | None = None,
) -> AgentPaymentKeyCredential:
    unsigned = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "AgentPaymentKeyCredential"],
        "issuer": PRIMARY_DID,
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        **({"validUntil": valid_until} if valid_until else {}),
        **({"validFrom": valid_from} if valid_from else {}),
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
        valid_from=raw.get("validFrom"),
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
                MinimalVerificationMethod(
                    id=PRIMARY_KID,
                    type="JsonWebKey2020",
                    controller=PRIMARY_DID,
                    public_key_jwk=primary_public_key_jwk,
                ),
            ),
            assertion_method=(PRIMARY_KID,),
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


async def test_an_unparseable_valid_until_is_rejected_not_treated_as_still_valid():
    """M3-equivalent regression for the Python port: an unparseable validUntil already fails
    closed here (ValueError -> credential_expired), unlike the TS port before its fix. This
    pins that behaviour down as a regression test.
    """
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(
        private_key=private_key, payment_key_jwk=payment_key_jwk, valid_until="31/12/2025"
    )
    result = await verify_agent_payment_key_credential(
        credential, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "credential_expired"


async def test_a_credential_whose_valid_from_is_in_the_future_is_rejected_as_not_yet_valid():
    """validFrom was never checked at all, so a credential wasn't yet valid (its validity
    window hasn't started) still verified successfully."""
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(
        private_key=private_key, payment_key_jwk=payment_key_jwk, valid_from="2999-01-01T00:00:00Z"
    )
    result = await verify_agent_payment_key_credential(
        credential, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "credential_not_yet_valid"


async def test_a_valid_from_that_cannot_be_parsed_is_rejected_not_treated_as_already_valid():
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(
        private_key=private_key, payment_key_jwk=payment_key_jwk, valid_from="31/12/2025"
    )
    result = await verify_agent_payment_key_credential(
        credential, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "credential_not_yet_valid"


async def test_a_signed_credential_with_mismatched_dataclass_fields_cannot_bypass_checks():
    """H3 regression: decisions and the returned key must be derived from `raw` itself, never
    from the separately-populated dataclass fields - those can diverge from what was actually
    signed. Builds a REAL, correctly-signed credential whose signed (raw) validUntil is in the
    past, then passes dataclass fields claiming no expiry and a different (attacker) payment
    key. Before the fix this returned ok=True with the attacker's key; it must instead reject
    as expired and never surface the attacker's key.
    """
    private_key = Ed25519PrivateKey.generate()
    primary_public_key_jwk = jwk_of(private_key)
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())
    attacker_key_jwk = jwk_of(Ed25519PrivateKey.generate())

    credential = signed_credential(
        private_key=private_key, payment_key_jwk=payment_key_jwk, valid_until="2020-01-01T00:00:00Z"
    )
    mismatched = AgentPaymentKeyCredential(
        type=credential.type,
        issuer=credential.issuer,
        credential_subject=AgentPaymentKeyCredentialSubject(id=PRIMARY_DID, payment_key_jwk=attacker_key_jwk),
        valid_until=None,  # claims no expiry, even though raw's signed validUntil is in the past
        credential_status=credential.credential_status,
        proof=credential.proof,
        raw=credential.raw,  # the real, correctly-signed document - left untouched
    )
    result = await verify_agent_payment_key_credential(
        mismatched, PRIMARY_DID, deps_for(primary_public_key_jwk)
    )
    assert result.ok is False
    assert result.reason == "credential_expired"


async def test_from_dict_parses_a_raw_credential_document_into_the_dataclass():
    private_key = Ed25519PrivateKey.generate()
    payment_key_jwk = jwk_of(Ed25519PrivateKey.generate())
    credential = signed_credential(private_key=private_key, payment_key_jwk=payment_key_jwk)

    parsed = AgentPaymentKeyCredential.from_dict(credential.raw)
    assert parsed.issuer == PRIMARY_DID
    assert parsed.credential_subject.id == PRIMARY_DID
    assert parsed.credential_subject.payment_key_jwk == payment_key_jwk
    assert AGENT_PAYMENT_KEY_CREDENTIAL_TYPE in parsed.type
    assert parsed.raw == credential.raw


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
