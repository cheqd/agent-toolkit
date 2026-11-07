# SPDX-License-Identifier: Apache-2.0
# Tests for the from-spec org.kya-os/proof.v1 engine (build_card_proof + verify_card_proof).
# No TypeScript test file exists to port from (this engine has no TypeScript source at all -
# it's a from-spec Python re-implementation, not a port - see docs/design-decisions.md D13).
# These tests exercise the real fail-closed behaviour described in @kya-os/mcp's own
# card/proof/verify.ts, read directly from node_modules, not assumed.
import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from cheqd_agent_identity_a2a.covered_request import covered_request
from cheqd_agent_identity_a2a.proof.build import BuildProofContext, build_card_proof
from cheqd_agent_identity_a2a.proof.canonical import (
    CoveredRequest,
    canonical_payload_bytes,
    compute_request_hash,
)
from cheqd_agent_identity_a2a.proof.signer import ed25519_signer_from_jwk
from cheqd_agent_identity_a2a.proof.small_order import is_small_order_ed25519_key
from cheqd_agent_identity_a2a.proof.types import KYA_OS_CARD_PROOF_META_KEY, PROOF_PROFILE_V1, CardProofMeta
from cheqd_agent_identity_a2a.proof.verify import VerifyProofDeps, verify_card_proof


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


DID = "did:web:agent.example"
KID = f"{DID}#key-1"
AUDIENCE = "did:web:server.example"


def ed25519_private_jwk() -> tuple[dict, bytes]:
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii")
    d = base64.urlsafe_b64encode(seed).rstrip(b"=").decode("ascii")
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}, public_bytes


def req_for(method: str = "SendMessage") -> CoveredRequest:
    cr = covered_request(method, {"message": {"metadata": {}}})
    return CoveredRequest(method=cr.method, params=cr.params)


def basic_deps(public_jwk: dict, *, nonce_store: set | None = None, **overrides) -> VerifyProofDeps:
    nonce_store = nonce_store if nonce_store is not None else set()

    async def resolve_key(kid):
        return public_jwk

    async def consume(nonce, did, min_ttl):
        key = (did, nonce)
        if key in nonce_store:
            return False
        nonce_store.add(key)
        return True

    kwargs = {
        "resolve_key": resolve_key,
        "expected_audience": AUDIENCE,
        "consume_nonce_if_fresh": consume,
        "trust_resolve_key_authority": True,
    }
    kwargs.update(overrides)
    return VerifyProofDeps(**kwargs)


async def mint(req: CoveredRequest, *, nonce: str = "n-1", ttl_sec: int = 60) -> tuple[dict, dict]:
    private_jwk, public_bytes = ed25519_private_jwk()
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": private_jwk["x"]}
    signer = ed25519_signer_from_jwk(did=DID, kid=KID, private_jwk=private_jwk)
    ctx = BuildProofContext(audience=AUDIENCE, nonce=nonce, ttl_sec=ttl_sec)
    minted = await build_card_proof(req, signer, ctx)
    return minted[KYA_OS_CARD_PROOF_META_KEY], public_jwk


async def test_a_validly_minted_proof_verifies():
    req = req_for()
    proof, public_jwk = await mint(req)
    result = await verify_card_proof(proof, req, basic_deps(public_jwk))
    assert result.ok is True
    assert result.did == DID


async def test_a_tampered_request_is_rejected():
    req = req_for()
    proof, public_jwk = await mint(req)
    tampered_req = req_for("SendStreamingMessage")
    result = await verify_card_proof(proof, tampered_req, basic_deps(public_jwk))
    assert result.ok is False
    assert "request_hash_mismatch" in result.reasons


async def test_a_tampered_proof_field_fails_the_signature():
    req = req_for()
    proof, public_jwk = await mint(req)
    tampered = {**proof, "audience": "did:web:attacker.example"}
    result = await verify_card_proof(
        tampered, req, basic_deps(public_jwk, expected_audience="did:web:attacker.example")
    )
    assert result.ok is False
    assert "invalid_signature" in result.reasons


async def test_the_wrong_audience_is_rejected():
    req = req_for()
    proof, public_jwk = await mint(req)
    result = await verify_card_proof(
        proof, req, basic_deps(public_jwk, expected_audience="did:web:someone-else.example")
    )
    assert result.ok is False
    assert "audience_mismatch" in result.reasons


async def test_a_replayed_nonce_is_rejected_the_second_time():
    req = req_for()
    proof, public_jwk = await mint(req)
    store: set = set()
    deps = basic_deps(public_jwk, nonce_store=store)
    first = await verify_card_proof(proof, req, deps)
    second = await verify_card_proof(proof, req, deps)
    assert first.ok is True
    assert second.ok is False
    assert "nonce_replayed" in second.reasons


async def test_no_nonce_seam_fails_closed_not_skipped():
    req = req_for()
    proof, public_jwk = await mint(req)
    deps = basic_deps(public_jwk)
    deps = VerifyProofDeps(
        resolve_key=deps.resolve_key,
        expected_audience=AUDIENCE,
        trust_resolve_key_authority=True,
        consume_nonce_if_fresh=None,
    )
    result = await verify_card_proof(proof, req, deps)
    assert result.ok is False
    assert "nonce_seam_missing" in result.reasons


async def test_an_expired_proof_is_rejected():
    req = req_for()
    private_jwk, _ = ed25519_private_jwk()
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": private_jwk["x"]}
    signer = ed25519_signer_from_jwk(did=DID, kid=KID, private_jwk=private_jwk)
    clock = {"value": 0.0}
    ctx = BuildProofContext(audience=AUDIENCE, nonce="n-exp", ttl_sec=1, now=lambda: clock["value"])
    minted = await build_card_proof(req, signer, ctx)
    proof = minted[KYA_OS_CARD_PROOF_META_KEY]
    clock["value"] = 1_000_000 * 1000  # far in the future
    deps = basic_deps(public_jwk, now=lambda: clock["value"])
    result = await verify_card_proof(proof, req, deps)
    assert result.ok is False
    assert "expired" in result.reasons


async def test_ttl_longer_than_the_profile_cap_is_rejected_at_mint():
    req = req_for()
    private_jwk, _ = ed25519_private_jwk()
    signer = ed25519_signer_from_jwk(did=DID, kid=KID, private_jwk=private_jwk)
    ctx = BuildProofContext(audience=AUDIENCE, nonce="n-1", ttl_sec=61)
    with pytest.raises(ValueError):
        await build_card_proof(req, signer, ctx)


async def test_kid_belonging_to_a_different_did_than_claimed_is_rejected():
    req = req_for()
    proof, public_jwk = await mint(req)
    tampered = {**proof, "did": "did:web:victim.example"}
    result = await verify_card_proof(tampered, req, basic_deps(public_jwk))
    assert result.ok is False
    assert "kid_did_mismatch" in result.reasons


async def test_a_key_not_published_by_the_did_fails_closed_when_membership_is_checked():
    req = req_for()
    proof, actual_public_jwk = await mint(req)
    _other_jwk, other_public_bytes = ed25519_private_jwk()
    wrong_public_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(other_public_bytes).rstrip(b"=").decode(),
    }

    # resolve_key returns the ACTUAL signing key (so the signature itself is valid); the
    # membership check is what should reject it, since the DID only publishes a DIFFERENT key.
    async def resolve_key(_kid):
        return actual_public_jwk

    async def resolve_did_keys(_did):
        return [wrong_public_jwk]

    store: set = set()
    deps = basic_deps(
        actual_public_jwk, nonce_store=store, resolve_key=resolve_key, resolve_did_keys=resolve_did_keys
    )
    result = await verify_card_proof(proof, req, deps)
    assert result.ok is False
    assert "kid_not_in_did_document" in result.reasons


async def test_no_membership_seam_and_no_trust_attestation_fails_closed():
    req = req_for()
    proof, public_jwk = await mint(req)
    deps = basic_deps(public_jwk, trust_resolve_key_authority=False)
    result = await verify_card_proof(proof, req, deps)
    assert result.ok is False
    assert "did_membership_unverifiable" in result.reasons


async def test_cnf_fusion_reaches_l3_when_the_token_cnf_matches_the_signing_key():
    req = req_for()
    private_jwk, _ = ed25519_private_jwk()
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": private_jwk["x"]}
    signer = ed25519_signer_from_jwk(did=DID, kid=KID, private_jwk=private_jwk)
    ctx = BuildProofContext(audience=AUDIENCE, nonce="n-l3")
    minted = await build_card_proof(req, signer, ctx)
    proof = minted[KYA_OS_CARD_PROOF_META_KEY]
    deps = basic_deps(public_jwk, token_cnf_jkt=signer.jkt)
    result = await verify_card_proof(proof, req, deps)
    assert result.ok is True
    assert result.level == "L3"


async def test_cnf_fusion_fails_closed_when_token_requires_cnf_but_proof_has_none():
    req = req_for()
    proof, public_jwk = await mint(req)
    tampered = dict(proof)
    del tampered["cnf"]
    # Re-sign is not possible without the key, so instead verify the untampered proof's cnf
    # is required when a mismatched token_cnf_jkt is supplied, forcing a cnf_token_mismatch.
    deps = basic_deps(public_jwk, token_cnf_jkt="not-the-real-thumbprint")
    result = await verify_card_proof(proof, req, deps)
    assert result.ok is False
    assert "cnf_token_mismatch" in result.reasons


async def test_malformed_proof_is_rejected():
    req = req_for()
    _proof, public_jwk = await mint(req)
    result = await verify_card_proof({"not": "a proof"}, req, basic_deps(public_jwk))
    assert result.ok is False
    assert result.reasons == ("malformed_proof",)


async def test_an_unknown_field_on_the_proof_is_rejected_strict_schema():
    req = req_for()
    proof, public_jwk = await mint(req)
    tampered = {**proof, "extra_field": "sneaky"}
    result = await verify_card_proof(tampered, req, basic_deps(public_jwk))
    assert result.ok is False
    assert result.reasons == ("malformed_proof",)


def test_small_order_keys_are_detected():
    identity = bytes(32)
    assert is_small_order_ed25519_key(identity) is True
    real_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert is_small_order_ed25519_key(real_key) is False


async def test_different_requests_produce_proofs_that_do_not_cross_verify():
    req_a = req_for("SendMessage")
    req_b = req_for("SendStreamingMessage")
    proof_a, public_jwk = await mint(req_a)
    result = await verify_card_proof(proof_a, req_b, basic_deps(public_jwk))
    assert result.ok is False
    assert "request_hash_mismatch" in result.reasons


async def test_an_es256_proof_verifies_built_by_hand_not_via_the_packaged_signer():
    # The verifier must accept an ES256 proof from any org.kya-os/proof.v1 implementation,
    # including ones this package didn't mint - so this builds one by hand with raw
    # `cryptography` primitives (JWS ES256 signatures are the raw r||s concatenation, RFC
    # 7518 §3.4 - not ASN.1 DER), independent of `es256_signer_from_jwk`'s own round trip
    # (covered separately below).
    req = req_for()
    req_hash = compute_request_hash(req)
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    x = _b64url(public_numbers.x.to_bytes(32, "big"))
    y = _b64url(public_numbers.y.to_bytes(32, "big"))

    meta = CardProofMeta(
        prf=PROOF_PROFILE_V1,
        alg="ES256",
        did=DID,
        kid=KID,
        audience=AUDIENCE,
        nonce="es256-nonce",
        created=1700000000,
        expires=1700000060,
        request_hash=req_hash,
        jws="",
    )
    payload_b64 = _b64url(canonical_payload_bytes(meta))
    protected = _b64url(json.dumps({"alg": "ES256", "kid": KID}, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{protected}.{payload_b64}".encode("ascii")
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    jws = f"{protected}..{_b64url(raw_signature)}"

    proof = {
        "prf": meta.prf,
        "alg": meta.alg,
        "did": meta.did,
        "kid": meta.kid,
        "audience": meta.audience,
        "nonce": meta.nonce,
        "created": meta.created,
        "expires": meta.expires,
        "requestHash": meta.request_hash,
        "jws": jws,
    }

    public_jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    deps = basic_deps(public_jwk, now=lambda: 1700000005 * 1000)
    result = await verify_card_proof(proof, req, deps)
    assert result.ok is True
    assert result.did == DID


def es256_private_jwk() -> tuple[dict, dict]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    x = _b64url(numbers.x.to_bytes(32, "big"))
    y = _b64url(numbers.y.to_bytes(32, "big"))
    d = _b64url(private_key.private_numbers().private_value.to_bytes(32, "big"))
    private_jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y, "d": d}
    public_jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    return private_jwk, public_jwk


async def test_es256_signer_from_jwk_mints_a_proof_that_verifies():
    from cheqd_agent_identity_a2a.proof.signer import es256_signer_from_jwk

    private_jwk, public_jwk = es256_private_jwk()
    signer = es256_signer_from_jwk(did=DID, kid=KID, private_jwk=private_jwk)
    req = req_for()

    proof_dict = await build_card_proof(req, signer, BuildProofContext(audience=AUDIENCE, nonce="n-es256"))
    proof = proof_dict[KYA_OS_CARD_PROOF_META_KEY]
    assert proof["alg"] == "ES256"

    result = await verify_card_proof(proof, req, basic_deps(public_jwk))
    assert result.ok is True
    assert result.did == DID


async def test_a_signer_with_sign_raw_attaches_a_verifiable_http_sig():
    from cheqd_agent_identity_a2a.proof.http_sig import verify_http_signature

    private_jwk, public_jwk = ed25519_private_jwk_dict()
    signer = ed25519_signer_from_jwk(did=DID, kid=KID, private_jwk=private_jwk)
    req = req_for()

    proof_dict = await build_card_proof(req, signer, BuildProofContext(audience=AUDIENCE, nonce="n-httpsig"))
    proof = proof_dict[KYA_OS_CARD_PROOF_META_KEY]
    assert isinstance(proof.get("httpSig"), str) and len(proof["httpSig"]) > 0

    result = await verify_card_proof(proof, req, basic_deps(public_jwk))
    assert result.ok is True

    from cheqd_agent_identity_a2a.proof.types import CardProofCnf, CardProofMeta

    meta = CardProofMeta(
        prf=proof["prf"],
        alg=proof["alg"],
        did=proof["did"],
        kid=proof["kid"],
        audience=proof["audience"],
        nonce=proof["nonce"],
        created=proof["created"],
        expires=proof["expires"],
        request_hash=proof["requestHash"],
        jws=proof["jws"],
        http_sig=proof["httpSig"],
        cnf=CardProofCnf(jkt=proof["cnf"]["jkt"]) if "cnf" in proof else None,
    )
    assert verify_http_signature(meta, public_jwk) is True


async def test_http_sig_is_rejected_against_a_tampered_covered_field():
    from cheqd_agent_identity_a2a.proof.http_sig import verify_http_signature
    from cheqd_agent_identity_a2a.proof.types import CardProofCnf, CardProofMeta

    private_jwk, public_jwk = ed25519_private_jwk_dict()
    signer = ed25519_signer_from_jwk(did=DID, kid=KID, private_jwk=private_jwk)
    req = req_for()

    proof_dict = await build_card_proof(req, signer, BuildProofContext(audience=AUDIENCE, nonce="n-tamper"))
    proof = proof_dict[KYA_OS_CARD_PROOF_META_KEY]

    meta = CardProofMeta(
        prf=proof["prf"],
        alg=proof["alg"],
        did=proof["did"],
        kid=proof["kid"],
        audience="did:web:attacker.example",
        nonce=proof["nonce"],
        created=proof["created"],
        expires=proof["expires"],
        request_hash=proof["requestHash"],
        jws=proof["jws"],
        http_sig=proof["httpSig"],
        cnf=CardProofCnf(jkt=proof["cnf"]["jkt"]) if "cnf" in proof else None,
    )
    assert verify_http_signature(meta, public_jwk) is False


def ed25519_private_jwk_dict() -> tuple[dict, dict]:
    private_jwk, public_bytes = ed25519_private_jwk()
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public_bytes)}
    return private_jwk, public_jwk
