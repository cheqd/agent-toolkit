# SPDX-License-Identifier: Apache-2.0
# Tests verify_eddsa_jcs_2022 against a real, hand-signed DataIntegrityProof/eddsa-jcs-2022
# document, signed here (not imported), since this module is a verifier only.
import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity.agent_card.retrieve_public_key import MinimalDidDocument, MinimalVerificationMethod
from cheqd_agent_identity.proof.eddsa_jcs_2022 import VerifyEddsaJcs2022Options, verify_eddsa_jcs_2022

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


def sign(
    document: dict,
    verification_method: str,
    private_key: Ed25519PrivateKey,
    extra_proof_options: Optional[dict] = None,
) -> dict:
    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        **(extra_proof_options or {}),
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
            id=DID,
            verification_method=(
                MinimalVerificationMethod(
                    id=KID, type="JsonWebKey2020", controller=DID, public_key_jwk=public_key_jwk
                ),
            ),
            assertion_method=(KID,),
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


# Regression: this verifier used to accept any key in verification_method, never checking that
# the key is actually listed under assertion_method (W3C Controlled Identifiers v1.0 §3.3). A
# key published only under authentication - a login/session key, not one authorized to make
# assertions - used to verify here; it must not.
async def test_a_key_listed_only_under_authentication_not_assertion_method_fails():
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
            id=DID,
            verification_method=(
                MinimalVerificationMethod(
                    id=KID, type="JsonWebKey2020", controller=DID, public_key_jwk=public_key_jwk
                ),
            ),
            assertion_method=(),  # explicitly NOT listed here
        )

    document = sign({"issuer": DID, "value": "hello"}, KID, private_key)
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


async def test_a_key_whose_controller_is_a_different_did_fails_even_if_listed_under_assertion_method():
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
            id=DID,
            verification_method=(
                MinimalVerificationMethod(
                    id=KID,
                    type="JsonWebKey2020",
                    controller="did:web:someone-else.example",
                    public_key_jwk=public_key_jwk,
                ),
            ),
            assertion_method=(KID,),
        )

    document = sign({"issuer": DID, "value": "hello"}, KID, private_key)
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


async def test_a_document_with_no_assertion_method_at_all_fails_even_with_a_matching_verification_method():
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
            id=DID,
            verification_method=(
                MinimalVerificationMethod(
                    id=KID, type="JsonWebKey2020", controller=DID, public_key_jwk=public_key_jwk
                ),
            ),
        )

    document = sign({"issuer": DID, "value": "hello"}, KID, private_key)
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


# Regression: this verifier never checked that the resolved document's own `id` equals the DID it
# asked `resolve_did_document` to resolve - it relied entirely on the INJECTED resolver already
# having enforced that. A lax/buggy resolver can return a document for a DIFFERENT DID than the
# one requested; if that document's `id` field equals its own (different) DID but it carries an
# absolute-id `assertion_method` entry naming the REQUESTED did's kid with a `controller` equal to
# its own `id`, every existing check (controller == document.id, assertion_method membership)
# passes even though the document resolved does not actually belong to the DID being verified.
async def test_a_resolver_returning_a_document_for_a_different_did_than_requested_fails():
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    public_key_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_key_bytes).rstrip(b"=").decode("ascii"),
    }
    OTHER_DID = "did:web:other.example"

    # Buggy/lax resolver: asked to resolve DID, returns a document whose own id is OTHER_DID, but
    # which (maliciously or by misconfiguration) names the requested kid, absolutely, under its
    # assertion_method relationship, with a verification_method entry whose id is also absolute
    # (so method_id() does not re-derive it from document.id) and whose controller is OTHER_DID.
    async def resolve_did_document(requested_did):
        if requested_did != DID:
            return None
        return MinimalDidDocument(
            id=OTHER_DID,
            verification_method=(
                MinimalVerificationMethod(
                    id=KID, type="JsonWebKey2020", controller=OTHER_DID, public_key_jwk=public_key_jwk
                ),
            ),
            assertion_method=(KID,),
        )

    document = sign({"issuer": DID, "value": "hello"}, KID, private_key)
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


# Regression: proof.expires was ignored entirely - an expired proof verified as if it were still
# valid. `expires` must be included in the SIGNED proof options (not spliced in afterwards),
# otherwise changing the proof after signing would merely break the signature rather than
# exercise the new expiry check.
async def test_a_proof_with_an_expires_timestamp_in_the_past_fails():
    private_key, resolve_did_document = world()
    document = sign(
        {"issuer": DID, "value": "hello"}, KID, private_key, {"expires": "2000-01-01T00:00:00.000Z"}
    )
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


# Regression: an unparseable proof.expires must fail CLOSED (treated as invalid/expired), not
# fail OPEN (treated as "not yet expired"). See PR #43 for the same class of bug in
# ledger_anchored.py's validUntil handling.
async def test_a_proof_with_an_unparseable_expires_fails_closed():
    private_key, resolve_did_document = world()
    document = sign({"issuer": DID, "value": "hello"}, KID, private_key, {"expires": "not-a-date"})
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


# Regression: proof.created was ignored entirely - a proof claiming to have been created in the
# future (clock skew abuse, or a forged timestamp) verified anyway.
async def test_a_proof_with_a_created_timestamp_in_the_future_fails():
    private_key, resolve_did_document = world()
    document = sign(
        {"issuer": DID, "value": "hello"}, KID, private_key, {"created": "2999-01-01T00:00:00.000Z"}
    )
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


# Regression: same fail-closed-on-unparseable requirement as expires, for created.
async def test_a_proof_with_an_unparseable_created_fails_closed():
    private_key, resolve_did_document = world()
    document = sign({"issuer": DID, "value": "hello"}, KID, private_key, {"created": "not-a-date"})
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is False


# A still-valid expires (in the future) must not break the existing happy path.
async def test_a_proof_with_a_future_expires_still_verifies():
    private_key, resolve_did_document = world()
    document = sign(
        {"issuer": DID, "value": "hello"}, KID, private_key, {"expires": "2999-01-01T00:00:00.000Z"}
    )
    assert await verify_eddsa_jcs_2022(document, resolve_did_document) is True


# An injected clock lets tests control "now" deterministically instead of racing the system
# clock. `created` is pinned to a fixed past instant (rather than the real wall-clock `sign()`
# would otherwise stamp it with) so both injected "now"s below sit after it, isolating the
# assertion to the `expires` check.
async def test_an_injected_now_is_used_to_evaluate_expires_and_created():
    private_key, resolve_did_document = world()
    document = sign(
        {"issuer": DID, "value": "hello"},
        KID,
        private_key,
        {"created": "2019-01-01T00:00:00.000Z", "expires": "2020-06-01T00:00:00.000Z"},
    )
    before_expiry = datetime.fromisoformat("2020-01-01T00:00:00.000+00:00").timestamp() * 1000
    after_expiry = datetime.fromisoformat("2020-12-01T00:00:00.000+00:00").timestamp() * 1000
    assert (
        await verify_eddsa_jcs_2022(
            document, resolve_did_document, VerifyEddsaJcs2022Options(now=lambda: before_expiry)
        )
        is True
    )
    assert (
        await verify_eddsa_jcs_2022(
            document, resolve_did_document, VerifyEddsaJcs2022Options(now=lambda: after_expiry)
        )
        is False
    )
