"""KYA-OS Entity Card — REVOCATION seam (W3C Bitstring Status List v1.0).

Ported from `@kya-os/mcp/card/revocation.ts`, read directly from `node_modules/@kya-os/mcp/
dist` - see `statuslist_bits.py`'s module docstring and docs/design-decisions.md D10 for why
this exists now. `create_revocation_checker` is the DEFAULT implementation over W3C Bitstring
Status List v1.0: resolves the entry's `status_list_credential` through the injected `fetch`
seam, checks the list's proof through the injected `verify_status_list` seam when one is
given, inflates the multibase/GZIP `encodedList` bitstring, and reads the bit at
`status_list_index`.

FAIL-CLOSED is the invariant: an unreachable status list, a malformed credential, a list
whose proof is rejected, a status list that does not come from the entry's bound issuer, an
entry whose `statusSize` is not 1, a mismatched `statusPurpose`, or an out-of-range index all
resolve to `revoked=True, fresh=False` - the absence of proof-of-liveness is treated as
revoked, never as "probably fine".

ISSUER BINDING: a status list's proof shows only who SIGNED it, not that it is the list bound
to the entry being checked (W3C Bitstring Status List v1.0 §2.2/§3.2 explicitly allow the
signer to differ from the credential's own issuer). Without a check tying the fetched list to
the entry, whoever controls what `entry.status_list_credential`'s URL returns can serve their
OWN validly self-signed list with the bit cleared, and its proof verifies - the proof alone
never meant "this is the correct list". When `verify_status_list` is given, `check()` therefore
REQUIRES its caller to also name `credential_issuer` (the DID of the credential whose status is
being asked about) and only accepts a fetched list whose own `issuer` equals it; a call that
omits `credential_issuer` fails closed rather than silently skipping the binding. Ported from
(a scoped-down subset of) `@kya-os/mcp`'s 1.23.0+ `statusListIssuers`/`acceptStatusList`
machinery - this module implements only the single, default "list held to the credential's own
issuer" case that is actually used anywhere in this repository today, not the full configurable
multi-root/configured-URL keeper DSL `@kya-os/mcp` also offers.

ID BINDING: the issuer check above proves a fetched list was signed by the credential's own
issuer, but NOT that it is the particular list version bound to `entry.status_list_credential` -
that same issuer may keep several lists (or several revisions of one), so whoever controls what
the URL actually returns (the host, a CDN, a cache, or an injected-`fetch` bug) can instead serve
a DIFFERENT, equally genuine list from that issuer where the entry's index happens to read clear.
W3C Bitstring Status List v1.0 SS2.2 lets a list optionally state its own `id`; `@kya-os/mcp`'s
`idRejection` (ported here) therefore requires that when a fetched list STATES an `id`, it must
equal, byte-for-byte, the URL the list was requested from - even in this module's default
credential-issuer-matches case - and fails closed on a mismatch. A list that states no `id` is
still accepted (as `@kya-os/mcp` allows whenever, as here, the keeper of every URL is
unconditionally the credential's own issuer): the `id` only rules out a list that belongs to some
OTHER url, and the issuer check already rules out every list but this one issuer's.

`statusSize`: an entry whose `statusSize` is present and not `1` keeps its status at a
different bit position than the one this module reads (W3C Bitstring Status List v1.0 §3.2
step 10: the bit read is at `statusListIndex * statusSize`, not merely `statusListIndex`).
Rather than compute that multi-bit offset, every reader in `@kya-os/mcp` 1.23.0+ refuses such
an entry before any fetch (`acceptEntrySize`) - ported here as `_accept_entry_size`.

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


RevocationChecker = Callable[[StatusEntry, Optional[str]], Awaitable[RevocationVerdict]]


def _now_ms() -> float:
    return time.time() * 1000


def _accept_entry_size(status_size: Optional[int]) -> Optional[str]:
    """`None` when `status_size` may be read as one bit (absent or `1`); otherwise the
    fail-closed reason. Mirrors `@kya-os/mcp`'s `acceptEntrySize`: W3C Bitstring Status List
    v1.0 SS2.1 requires an integer greater than zero when present; SS3.2 step 10 reads the bit at
    `statusListIndex * statusSize`, which this module does not compute, so any value other than
    1 is refused rather than misread.
    """
    if status_size is None or status_size == 1:
        return None
    if isinstance(status_size, int) and not isinstance(status_size, bool) and status_size > 0:
        return f"the entry's statusSize is {status_size}, and only an entry of one bit is read"
    return f"the entry's statusSize ({status_size!r}) is not an integer greater than zero"


def _issuer_of(credential: dict[str, Any]) -> Optional[str]:
    issuer = credential.get("issuer")
    if isinstance(issuer, str):
        return issuer
    if isinstance(issuer, dict) and isinstance(issuer.get("id"), str):
        return issuer["id"]
    return None


def create_revocation_checker(
    *,
    fetch: Fetch,
    verify_status_list: Optional[VerifyStatusList] = None,
    now: Callable[[], float] = _now_ms,
    status_purpose: str = STATUS_PURPOSE_REVOCATION,
    decompress: Optional[Decompress] = None,
) -> RevocationChecker:
    """Build the default `RevocationChecker` over W3C Bitstring Status List v1.0. Any
    failure on the path (unreachable, non-2xx, malformed, wrong purpose, wrong `statusSize`,
    out-of-range index) resolves fail-closed (`revoked=True, fresh=False`).

    When `verify_status_list` is given, every call MUST also pass `credential_issuer` - the DID
    of the credential whose status is being asked about - so the fetched list can be held to
    it; see the module doc comment. A call that omits it fails closed, it does not silently skip
    the binding.
    """

    async def check(entry: StatusEntry, credential_issuer: Optional[str] = None) -> RevocationVerdict:
        try:
            size_rejection = _accept_entry_size(entry.status_size)
            if size_rejection is not None:
                raise ValueError(f"revocation: {size_rejection}")
            credential = await _fetch_status_list(entry.status_list_credential, fetch)
            if verify_status_list is not None:
                if credential_issuer is None:
                    raise ValueError(
                        "revocation: no credential issuer named to hold the status list to - a "
                        "resolver or checker that wraps this one must pass credential_issuer on"
                    )
                list_issuer = _issuer_of(credential)
                if list_issuer != credential_issuer:
                    raise ValueError(
                        f"revocation: status list issuer {list_issuer!r} does not keep this "
                        f"entry's URL: expected the credential's issuer {credential_issuer!r}"
                    )
                list_id = credential.get("id")
                if list_id is not None and list_id != entry.status_list_credential:
                    raise ValueError(
                        f"revocation: status list id {list_id!r} is not the URL it was "
                        f"requested from ({entry.status_list_credential!r})"
                    )
                if (await verify_status_list(credential)) is not True:
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


@dataclass(frozen=True)
class RevocationChainEntry:
    """One hop of a chain passed to `evaluate_revocation_chain`, paired with the DID that
    issued the credential this hop's status entry belongs to - so the checker can hold the
    hop's status list to THAT issuer, not the leaf's or some other hop's. A bare `StatusEntry`
    (no `RevocationChainEntry` wrapper) is checked with no bound issuer, which a checker given
    `verify_status_list` fails closed on.
    """

    entry: StatusEntry
    credential_issuer: Optional[str] = None
    position: Optional[int] = None


async def evaluate_revocation_chain(
    entries: Sequence[Union[StatusEntry, RevocationChainEntry]], check: RevocationChecker
) -> ChainResult:
    """Walk a delegation/capability chain root->leaf and fail-close on the first revoked or
    unresolvable hop (cascading - a revoked ancestor invalidates the subtree, so the walk
    short-circuits). `fresh` is the AND of every checked hop's liveness.

    An empty set of status entries is trivially `ok` (nothing is revoked - an offline/L2-
    acceptable verdict) but is NOT `fresh`: freshness is a LIVE-check signal, and zero checks
    obtained no live signal.
    """
    fresh = len(entries) > 0
    for index, item in enumerate(entries):
        if isinstance(item, RevocationChainEntry):
            entry = item.entry
            credential_issuer = item.credential_issuer
            hop = item.position if item.position is not None else index
        else:
            entry = item
            credential_issuer = None
            hop = index
        status = await check(entry, credential_issuer)
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
