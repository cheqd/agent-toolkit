# SPDX-License-Identifier: Apache-2.0
# Tests create_revocation_checker + evaluate_revocation_chain (revocation.py), ported from
# @kya-os/mcp/card/revocation.ts - read directly, not reconstructed from prose.
import base64
import gzip

from cheqd_agent_identity.status.ledger_anchored import StatusEntry
from cheqd_agent_identity.status.revocation import create_revocation_checker, evaluate_revocation_chain


def _encode(bits: bytes) -> str:
    compressed = gzip.compress(bits)
    return "u" + base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")


class _Response:
    def __init__(self, *, ok: bool, status: int, body):
        self.ok = ok
        self.status = status
        self._body = body

    async def json(self):
        return self._body


def _credential(
    *,
    encoded_list: str,
    purpose: str = "revocation",
    valid_until=None,
    valid_from=None,
    issuer=None,
    list_id=None,
):
    subject = {"statusPurpose": purpose, "encodedList": encoded_list}
    credential = {"credentialSubject": subject}
    if valid_until is not None:
        credential["validUntil"] = valid_until
    if valid_from is not None:
        credential["validFrom"] = valid_from
    if issuer is not None:
        credential["issuer"] = issuer
    if list_id is not None:
        credential["id"] = list_id
    return credential


async def test_a_clear_bit_reads_as_not_revoked_and_fresh():
    bits = bytes([0b00000000])
    credential = _credential(
        encoded_list=_encode(bits), valid_until="2999-01-01T00:00:00Z", valid_from="2000-01-01T00:00:00Z"
    )

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch)
    verdict = await check(entry)
    assert verdict.revoked is False
    assert verdict.fresh is True


async def test_a_set_bit_reads_as_revoked():
    bits = bytes([0b10000000])
    credential = _credential(encoded_list=_encode(bits))

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch)
    verdict = await check(entry)
    assert verdict.revoked is True


async def test_an_unreachable_list_fails_closed_to_revoked():
    async def fetch(_url):
        return _Response(ok=False, status=500, body=None)

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch)
    verdict = await check(entry)
    assert verdict.revoked is True
    assert verdict.fresh is False


async def test_a_mismatched_status_purpose_fails_closed():
    bits = bytes([0b00000000])
    credential = _credential(encoded_list=_encode(bits), purpose="suspension")

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch)
    verdict = await check(entry)
    assert verdict.revoked is True


async def test_a_rejected_status_list_proof_fails_closed():
    bits = bytes([0b00000000])
    credential = _credential(encoded_list=_encode(bits))

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    async def verify_status_list(_credential):
        return False

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch, verify_status_list=verify_status_list)
    verdict = await check(entry)
    assert verdict.revoked is True


async def test_a_stale_list_is_not_fresh_but_still_readable():
    bits = bytes([0b00000000])
    credential = _credential(
        encoded_list=_encode(bits), valid_until="2000-01-01T00:00:00Z", valid_from="1999-01-01T00:00:00Z"
    )

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch)
    verdict = await check(entry)
    assert verdict.revoked is False
    assert verdict.fresh is False


async def test_evaluate_revocation_chain_on_an_empty_chain_is_ok_but_not_fresh():
    async def check(_entry, _credential_issuer=None):
        raise AssertionError("should not be called")

    result = await evaluate_revocation_chain([], check)
    assert result.ok is True
    assert result.fresh is False


async def test_evaluate_revocation_chain_short_circuits_on_the_first_revoked_hop():
    from cheqd_agent_identity.status.revocation import RevocationVerdict

    calls = []

    async def check(entry, _credential_issuer=None):
        calls.append(entry.status_list_index)
        if entry.status_list_index == "0":
            return RevocationVerdict(revoked=False, fresh=True)
        return RevocationVerdict(revoked=True, fresh=True)

    entries = [
        StatusEntry(status_list_credential="c", status_list_index="0", status_purpose="revocation"),
        StatusEntry(status_list_credential="c", status_list_index="1", status_purpose="revocation"),
        StatusEntry(status_list_credential="c", status_list_index="2", status_purpose="revocation"),
    ]
    result = await evaluate_revocation_chain(entries, check)
    assert result.ok is False
    assert calls == ["0", "1"]


async def test_evaluate_revocation_chain_threads_each_hops_own_credential_issuer():
    from cheqd_agent_identity.status.revocation import RevocationChainEntry, RevocationVerdict

    seen_issuers = []

    async def check(_entry, credential_issuer=None):
        seen_issuers.append(credential_issuer)
        return RevocationVerdict(revoked=False, fresh=True)

    entries = [
        RevocationChainEntry(
            entry=StatusEntry(
                status_list_credential="c0", status_list_index="0", status_purpose="revocation"
            ),
            credential_issuer="did:example:root",
        ),
        RevocationChainEntry(
            entry=StatusEntry(
                status_list_credential="c1", status_list_index="0", status_purpose="revocation"
            ),
            credential_issuer="did:example:leaf",
        ),
    ]
    result = await evaluate_revocation_chain(entries, check)
    assert result.ok is True
    assert seen_issuers == ["did:example:root", "did:example:leaf"]


async def test_an_entry_with_an_unsupported_status_size_fails_closed():
    bits = bytes([0b00000000])
    credential = _credential(encoded_list=_encode(bits))

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    entry = StatusEntry(
        status_list_credential="https://example/list",
        status_list_index="0",
        status_purpose="revocation",
        status_size=2,
    )
    check = create_revocation_checker(fetch=fetch)
    verdict = await check(entry)
    assert verdict.revoked is True


async def test_verify_status_list_without_a_credential_issuer_fails_closed():
    bits = bytes([0b00000000])
    credential = _credential(encoded_list=_encode(bits), issuer="did:example:real-issuer")

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    async def verify_status_list(_credential):
        return True

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch, verify_status_list=verify_status_list)
    # No credential_issuer passed - must fail closed, not silently skip the binding.
    verdict = await check(entry)
    assert verdict.revoked is True


async def test_a_status_list_from_an_attacker_controlled_issuer_fails_closed():
    """The core issuer-binding regression: a validly self-signed list from the WRONG issuer
    must not be accepted just because its own proof verifies."""
    bits = bytes([0b00000000])  # attacker's own list clears the bit
    credential = _credential(encoded_list=_encode(bits), issuer="did:example:attacker")

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    async def verify_status_list(_credential):
        return True  # the attacker's own proof over their own list verifies fine

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch, verify_status_list=verify_status_list)
    verdict = await check(entry, "did:example:real-issuer")
    assert verdict.revoked is True


async def test_a_status_list_from_the_bound_issuer_is_accepted():
    bits = bytes([0b00000000])
    credential = _credential(encoded_list=_encode(bits), issuer="did:example:real-issuer")

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    async def verify_status_list(_credential):
        return True

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch, verify_status_list=verify_status_list)
    verdict = await check(entry, "did:example:real-issuer")
    assert verdict.revoked is False


async def test_a_same_issuer_list_served_at_the_wrong_url_fails_closed_on_id_mismatch():
    """The id-binding regression: the issuer-equality check alone is not enough. The SAME
    issuer may keep more than one genuine, validly-signed list (or an older revision of this
    one); whoever controls what `entry.status_list_credential`'s URL actually returns (a host,
    CDN, cache, or injected-fetch bug) can serve a DIFFERENT list of theirs - one that is not
    the list that was actually requested - and, before this fix, Python accepted it purely
    because the issuer matched. The list below states its OWN `id` as a different URL than the
    one it was fetched from, so it must be refused even though its issuer and proof are fine.
    """
    bits = bytes([0b00000000])  # the substituted list clears the bit
    credential = _credential(
        encoded_list=_encode(bits),
        issuer="did:example:real-issuer",
        list_id="https://example/some-other-list-the-same-issuer-also-keeps",
    )

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    async def verify_status_list(_credential):
        return True  # the substituted list's own proof verifies fine - it IS genuine, just not THIS one

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch, verify_status_list=verify_status_list)
    verdict = await check(entry, "did:example:real-issuer")
    assert verdict.revoked is True


async def test_a_list_whose_stated_id_matches_the_requested_url_is_accepted():
    bits = bytes([0b00000000])
    credential = _credential(
        encoded_list=_encode(bits),
        issuer="did:example:real-issuer",
        list_id="https://example/list",
    )

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    async def verify_status_list(_credential):
        return True

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch, verify_status_list=verify_status_list)
    verdict = await check(entry, "did:example:real-issuer")
    assert verdict.revoked is False


async def test_a_list_that_states_no_id_is_still_accepted():
    """A list is free to omit `id` entirely (W3C Bitstring Status List v1.0 SS2.2 makes it
    optional); the id check only rejects a STATED id that names a different URL, mirroring
    `@kya-os/mcp`'s `idRejection` for the "keeper is unconditionally the credential's own
    issuer" case this module implements."""
    bits = bytes([0b00000000])
    credential = _credential(encoded_list=_encode(bits), issuer="did:example:real-issuer")

    async def fetch(_url):
        return _Response(ok=True, status=200, body=credential)

    async def verify_status_list(_credential):
        return True

    entry = StatusEntry(
        status_list_credential="https://example/list", status_list_index="0", status_purpose="revocation"
    )
    check = create_revocation_checker(fetch=fetch, verify_status_list=verify_status_list)
    verdict = await check(entry, "did:example:real-issuer")
    assert verdict.revoked is False
