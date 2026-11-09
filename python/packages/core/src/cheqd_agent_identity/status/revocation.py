"""KYA-OS Entity Card — REVOCATION seam (W3C Bitstring Status List v1.0).

Ported from `@kya-os/mcp/card/revocation.ts`, read directly from `node_modules/@kya-os/mcp/
dist` - see `statuslist_bits.py`'s module docstring and docs/design-decisions.md D10 for why
this exists now. `create_revocation_checker` is the DEFAULT implementation over W3C Bitstring
Status List v1.0: resolves the entry's `status_list_credential` through the injected `fetch`
seam, checks the list's proof through the injected `verify_status_list` seam when one is
given, inflates the multibase/GZIP `encodedList` bitstring, and reads the bit at
`status_list_index`.

FAIL-CLOSED is the invariant: an unreachable status list, a malformed credential, a list
whose proof is rejected, a mismatched `statusPurpose`, or an out-of-range index all resolve
to `revoked=True, fresh=False` - the absence of proof-of-liveness is treated as revoked,
never as "probably fine".

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Literal, Optional, Protocol, Sequence, Union

from cheqd_agent_identity.status.ledger_anchored import StatusEntry
from cheqd_agent_identity.status.statuslist_bits import (
    Decompress,
    assert_status_purpose,
    decode_status_list_payload,
    parse_status_list_index,
    read_status_bit,
)

STATUS_PURPOSE_REVOCATION = "revocation"
"""The `statusPurpose` this checker evaluates by default (revocation, not suspension)."""

_FAIL_CLOSED_REVOKED = True
_FAIL_CLOSED_FRESH = False


class FetchResponse(Protocol):
    ok: bool
    status: int

    async def json(self) -> Any: ...


Fetch = Callable[[str], Awaitable[FetchResponse]]
VerifyStatusList = Callable[[Any], Awaitable[bool]]


@dataclass(frozen=True)
class RevocationVerdict:
    revoked: bool
    fresh: bool
    """`True` only when read from a LIVE, in-validity-window status list. A stale (past
    `valid_until`) or not-yet-valid list still yields a readable bit but `fresh=False`."""


RevocationChecker = Callable[[StatusEntry], Awaitable[RevocationVerdict]]


def _now_ms() -> float:
    return time.time() * 1000


def create_revocation_checker(
    *,
    fetch: Fetch,
    verify_status_list: Optional[VerifyStatusList] = None,
    now: Callable[[], float] = _now_ms,
    status_purpose: str = STATUS_PURPOSE_REVOCATION,
    decompress: Optional[Decompress] = None,
) -> RevocationChecker:
    """Build the default `RevocationChecker` over W3C Bitstring Status List v1.0. Any
    failure on the path (unreachable, non-2xx, malformed, wrong purpose, out-of-range index)
    resolves fail-closed (`revoked=True, fresh=False`).
    """

    async def check(entry: StatusEntry) -> RevocationVerdict:
        try:
            credential = await _fetch_status_list(entry.status_list_credential, fetch)
            if verify_status_list is not None and (await verify_status_list(credential)) is not True:
                raise ValueError("revocation: status-list proof rejected")
            subject = _status_list_subject(credential)
            assert_status_purpose(subject.get("statusPurpose"), status_purpose)
            bits = _decode_status_list(credential, decompress)
            revoked = read_status_bit(bits, parse_status_list_index(entry.status_list_index))
            return RevocationVerdict(revoked=revoked, fresh=_is_live(credential, now()))
        except Exception:
            return RevocationVerdict(revoked=_FAIL_CLOSED_REVOKED, fresh=_FAIL_CLOSED_FRESH)

    return check


@dataclass(frozen=True)
class ChainResult:
    ok: bool
    fresh: bool
    reasons: Sequence[str]


async def evaluate_revocation_chain(entries: Sequence[StatusEntry], check: RevocationChecker) -> ChainResult:
    """Walk a delegation/capability chain root->leaf and fail-close on the first revoked or
    unresolvable hop (cascading - a revoked ancestor invalidates the subtree, so the walk
    short-circuits). `fresh` is the AND of every checked hop's liveness.

    An empty set of status entries is trivially `ok` (nothing is revoked - an offline/L2-
    acceptable verdict) but is NOT `fresh`: freshness is a LIVE-check signal, and zero checks
    obtained no live signal.
    """
    fresh = len(entries) > 0
    for hop, entry in enumerate(entries):
        status = await check(entry)
        fresh = fresh and status.fresh
        if status.revoked:
            return ChainResult(
                ok=False,
                fresh=False,
                reasons=(
                    f"revocation: hop {hop} ({entry.status_list_credential}#{entry.status_list_index}) "
                    "is revoked or unresolvable - fail-closed, subtree invalidated",
                ),
            )
    return ChainResult(ok=True, fresh=fresh, reasons=())


async def _fetch_status_list(url: str, fetch: Fetch) -> dict[str, Any]:
    response = await fetch(url)
    if not response.ok:
        raise ValueError(f"revocation: status-list GET {url} -> {response.status}")
    body = await response.json()
    if not isinstance(body, dict):
        raise ValueError("revocation: status-list credential is not an object")
    return body


def _status_list_subject(credential: dict[str, Any]) -> dict[str, Any]:
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict):
        raise ValueError("revocation: status-list has no credentialSubject")
    return subject


def _decode_status_list(credential: dict[str, Any], decompress: Optional[Decompress]) -> bytes:
    encoded = _status_list_subject(credential).get("encodedList")
    if not isinstance(encoded, str) or len(encoded) == 0:
        raise ValueError("revocation: status-list has no encodedList")
    if decompress is None:
        return decode_status_list_payload(encoded)
    return decode_status_list_payload(encoded, decompress)


def _is_live(credential: dict[str, Any], now_ms: float) -> bool:
    """True iff `now_ms` falls inside the credential's `[valid_from, valid_until]` window (if
    declared). A bound that is PRESENT but not a parseable date is not "absent": the list's
    validity window is then unknown, so it cannot vouch for a live read (`False`, never an
    open window).
    """
    valid_until = _parse_date(_first_present(credential.get("validUntil"), credential.get("expirationDate")))
    valid_from = _parse_date(_first_present(credential.get("validFrom"), credential.get("issuanceDate")))
    if valid_until is False or valid_from is False:
        return False
    if valid_until is not None and valid_until < now_ms:
        return False
    if valid_from is not None and valid_from > now_ms:
        return False
    return True


def _first_present(current: Any, legacy: Any) -> Any:
    """The VC 2.0 property when present, else its VC 1.1 predecessor."""
    return current if current is not None else legacy


def _parse_date(value: Any) -> Union[float, None, Literal[False]]:
    """Parse an ISO-8601/RFC-1123 date to epoch ms: `None` when absent, `False` when present
    but unparseable (distinguished from `None` so `_is_live` can fail closed on "present but
    garbage" without mistaking it for "absent").
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return False
    try:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return parsed.timestamp() * 1000
    except ValueError:
        try:
            return parsedate_to_datetime(value).timestamp() * 1000
        except (ValueError, TypeError):
            return False
