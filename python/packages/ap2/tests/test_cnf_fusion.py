# SPDX-License-Identifier: Apache-2.0
# Tests for verify_same_key_continuity/verify_cnf_continuity against real generated Ed25519
# keys.
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cheqd_agent_identity_ap2.cnf_fusion import verify_cnf_continuity, verify_same_key_continuity
from cheqd_agent_identity_ap2.payment_key_authorization import PaymentKeyAuthorizationDeps


def new_jwk() -> dict:
    public_key = Ed25519PrivateKey.generate().public_key()
    raw = public_key.public_bytes_raw()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


async def test_same_key_continuity_passes_when_the_mandate_cnf_jwk_equals_the_resolved_agent_key():
    key = new_jwk()
    result = await verify_same_key_continuity(key, key)
    assert result.ok is True
    assert result.tier == "same-key"


async def test_same_key_continuity_fails_on_a_genuinely_different_key():
    a = new_jwk()
    b = new_jwk()
    result = await verify_same_key_continuity(a, b)
    assert result.ok is False
    assert result.reason == "cnf_jwk_thumbprint_mismatch"


async def test_verify_cnf_continuity_falls_back_to_same_key_failure_with_no_payment_key_credential_supplied():
    a = new_jwk()
    b = new_jwk()

    async def resolve_did_document(_did):
        return None

    async def check_revoked(_credential):
        return (False, True)

    deps = PaymentKeyAuthorizationDeps(resolve_did_document=resolve_did_document, check_revoked=check_revoked)
    result = await verify_cnf_continuity(a, b, "did:example:agent", None, deps)
    assert result.ok is False


async def test_verify_cnf_continuity_accepts_same_key_without_needing_a_payment_key_credential_at_all():
    key = new_jwk()

    async def resolve_did_document(_did):
        return None

    async def check_revoked(_credential):
        return (False, True)

    deps = PaymentKeyAuthorizationDeps(resolve_did_document=resolve_did_document, check_revoked=check_revoked)
    result = await verify_cnf_continuity(key, key, "did:example:agent", None, deps)
    assert result.ok is True
    assert result.tier == "same-key"
