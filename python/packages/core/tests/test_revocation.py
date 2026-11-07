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


def _credential(*, encoded_list: str, purpose: str = "revocation", valid_until=None, valid_from=None):
    subject = {"statusPurpose": purpose, "encodedList": encoded_list}
    credential = {"credentialSubject": subject}
    if valid_until is not None:
        credential["validUntil"] = valid_until
    if valid_from is not None:
        credential["validFrom"] = valid_from
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
    async def check(_entry):
        raise AssertionError("should not be called")

    result = await evaluate_revocation_chain([], check)
    assert result.ok is True
    assert result.fresh is False


async def test_evaluate_revocation_chain_short_circuits_on_the_first_revoked_hop():
    from cheqd_agent_identity.status.revocation import RevocationVerdict

    calls = []

    async def check(entry):
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
