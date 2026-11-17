"""Persistent, per-mandate consumption tracking (WS5 decision 4/E). A single A2A proof's
replay window (60s, `@cheqd/agent-identity`'s `FileNonceCacheProvider`) is the wrong lifetime
for an AP2 Open Mandate: the mandate itself can be presented across many A2A calls over its own
much longer validity window, so "has this mandate already authorised a payment" and "how much
has it spent so far" need their own store, not a reuse of the A2A proof nonce cache.

Two operations, with two different atomicity guarantees:
- `consume_once` (non-recurring mandates): exclusive-create (`O_CREAT | O_EXCL`), the SAME
  atomic test-and-set `FileNonceCacheProvider` uses - safe across concurrent processes on one
  filesystem.
- `record_use` (recurring/budget-constrained mandates, via `MandateContext`): a read-modify-
  write guarded by an in-process lock per mandate id. This is correct for concurrent callers
  WITHIN one process; it is NOT a cross-process atomic increment. A genuinely distributed
  deployment needs `record_use` backed by a real transactional store, not this file-based
  implementation.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Literal, Optional, Protocol, Sequence, Union

from cheqd_agent_identity_ap2.types import MandateContext


def _assert_valid_amount(amount_minor_units: float) -> None:
    """`amount_minor_units` must be a finite, non-negative integer.

    Rejects `NaN` (which `json.dumps` writes as the literal `NaN` and `json.loads` reads back as
    a float that is never greater than any budget, permanently defeating the budget check - see
    the `_validate_stored_total` corruption guard below), `inf`, non-integral floats, and negative
    amounts (which would act as a budget refund rather than a use).
    """
    is_valid = (
        not isinstance(amount_minor_units, bool)
        and isinstance(amount_minor_units, (int, float))
        and math.isfinite(amount_minor_units)
        and amount_minor_units == int(amount_minor_units)
        and amount_minor_units >= 0
    )
    if not is_valid:
        raise ValueError(
            f"amount_minor_units must be a finite, non-negative integer (got {amount_minor_units!r})"
        )


def _validate_stored_total(value: Any, field: str) -> float:
    """Validates a value read back from a persisted context as a non-negative integer, failing
    closed (raising) rather than silently coercing corrupt data to `0`.

    `None` (the field was never written) is treated as a fresh/absent value and defaults to `0` -
    that is not corruption, just a mandate with no prior recorded field. Anything else that is
    present but not a valid non-negative integer (including the `NaN` `json.loads` reads back from
    a pre-validation bug's `json.dumps(float("nan"))`, or a negative number) is corrupt and must
    not be silently reset, since doing so erases budget history instead of refusing to proceed.
    """
    if value is None:
        return 0
    is_valid = (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value == int(value)
        and value >= 0
    )
    if not is_valid:
        raise ValueError(
            f"Corrupt mandate consumption record: {field} is not a non-negative integer (got {value!r})"
        )
    return value


@dataclass(frozen=True)
class CheckAndRecordUseOk:
    ok: Literal[True]
    context: MandateContext


@dataclass(frozen=True)
class CheckAndRecordUseRejected:
    ok: Literal[False]
    violations: Sequence[str]


CheckAndRecordUseResult = Union[CheckAndRecordUseOk, CheckAndRecordUseRejected]


class MandateConsumptionStore(Protocol):
    async def consume_once(self, mandate_id: str) -> bool:
        """Atomically consumes a one-time-use mandate. Returns `False` if already consumed."""
        ...

    async def record_use(self, mandate_id: str, amount_minor_units: float) -> MandateContext:
        """Records one use of amount `amount_minor_units` against `mandate_id`, returning the
        updated context.

        Composing this with an earlier `get_context()` call and an external constraint check
        (read context, check it yourself, then call this) is NOT safe: two concurrent callers
        can both read the same context before either records, so both can pass a budget check
        that only one of them should have (found by review - two concurrent $90 payments
        against a $100 budget both reading `total_amount: 0` both pass, both record, spend ends
        at $180). Use :meth:`check_and_record_use` for anything that needs the check and the
        record to be atomic together; keep this for cases with no check to race.
        """
        ...

    async def get_context(self, mandate_id: str) -> MandateContext:
        """Reads the current context without recording a use. Absent mandate -> zeroed
        context.
        """
        ...

    async def check_and_record_use(
        self,
        mandate_id: str,
        amount_minor_units: float,
        check: Callable[[MandateContext], Sequence[str]],
    ) -> CheckAndRecordUseResult:
        """Atomically checks `check(context)` against the mandate's current context and, only
        if it returns no violations, records the use and returns the updated context - both
        under the same per-mandate-id lock `record_use` uses, so no other
        `record_use`/`check_and_record_use` call for the same mandate can run between the check
        and the record. This is the race-free replacement for a `get_context()` + external
        check + `record_use()` composition.
        """
        ...


class _FileMandateConsumptionStore:
    def __init__(self, directory: str | Path, now: Optional[Callable[[], float]] = None) -> None:
        self._directory = Path(directory)
        self._now = now or (lambda: time.time() * 1000)
        self._ready = False
        self._ready_lock = asyncio.Lock()
        # Per-mandate-id in-process serialization for record_use's read-modify-write. Entries are
        # reference-counted via `_lock_refcounts` and pruned once the count drops to zero (no
        # caller currently holding or waiting on that key's lock), so these dicts do not grow
        # without bound across the lifetime of a long-running process.
        self._locks: dict[str, asyncio.Lock] = {}
        self._lock_refcounts: dict[str, int] = {}

    async def _ensure_directory(self) -> None:
        if self._ready:
            return
        async with self._ready_lock:
            if self._ready:
                return
            await asyncio.to_thread(self._directory.mkdir, parents=True, exist_ok=True)
            self._ready = True

    def _consumed_path(self, mandate_id: str) -> Path:
        key = hashlib.sha256(f"consumed\x00{mandate_id}".encode("utf-8")).hexdigest()
        return self._directory / f"{key}.json"

    def _context_path(self, mandate_id: str) -> Path:
        key = hashlib.sha256(f"context\x00{mandate_id}".encode("utf-8")).hexdigest()
        return self._directory / f"{key}.json"

    @asynccontextmanager
    async def _locked(self, mandate_id: str) -> AsyncIterator[None]:
        """Acquires the per-mandate-id lock, reference-counted so the backing `asyncio.Lock`
        (and its refcount entry) is pruned from `self._locks`/`self._lock_refcounts` once no
        caller is holding or waiting on it any more.

        The refcount increment below happens synchronously, before the lock is acquired (and
        therefore before this coroutine can be suspended) - so a concurrent caller for the same
        `mandate_id` always observes a non-zero refcount and reuses the same lock instance rather
        than racing to create a second one, or pruning the lock out from under a caller that is
        about to wait on it. This must not reintroduce the #34 check-then-record race: deletion
        only ever happens after the refcount returns to zero, i.e. after every holder for this key
        has fully released the lock, so a key's serialization is never dropped while any caller
        is still mid-flight on it.
        """
        self._lock_refcounts[mandate_id] = self._lock_refcounts.get(mandate_id, 0) + 1
        lock = self._locks.get(mandate_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[mandate_id] = lock
        try:
            async with lock:
                yield
        finally:
            remaining = self._lock_refcounts[mandate_id] - 1
            if remaining == 0:
                del self._lock_refcounts[mandate_id]
                del self._locks[mandate_id]
            else:
                self._lock_refcounts[mandate_id] = remaining

    async def _read_context(self, mandate_id: str) -> MandateContext:
        try:
            raw = await asyncio.to_thread(self._context_path(mandate_id).read_text)
        except FileNotFoundError:
            return MandateContext(total_amount=0, total_uses=0)
        parsed = json.loads(raw)
        context: MandateContext = {
            "total_amount": _validate_stored_total(parsed.get("total_amount"), "total_amount"),
            "total_uses": _validate_stored_total(parsed.get("total_uses"), "total_uses"),
        }
        if isinstance(parsed.get("last_used_date"), (int, float)):
            context["last_used_date"] = parsed["last_used_date"]
        return context

    async def consume_once(self, mandate_id: str) -> bool:
        await self._ensure_directory()
        path = self._consumed_path(mandate_id)
        try:
            fd = await asyncio.to_thread(os.open, path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        try:
            await asyncio.to_thread(os.write, fd, json.dumps({"consumedAt": self._now()}).encode("utf-8"))
        finally:
            await asyncio.to_thread(os.close, fd)
        return True

    async def record_use(self, mandate_id: str, amount_minor_units: float) -> MandateContext:
        _assert_valid_amount(amount_minor_units)
        await self._ensure_directory()
        async with self._locked(mandate_id):
            current = await self._read_context(mandate_id)
            updated: MandateContext = {
                "total_amount": current["total_amount"] + amount_minor_units,
                "total_uses": current["total_uses"] + 1,
                "last_used_date": self._now(),
            }
            await asyncio.to_thread(self._context_path(mandate_id).write_text, json.dumps(updated))
            return updated

    async def get_context(self, mandate_id: str) -> MandateContext:
        await self._ensure_directory()
        return await self._read_context(mandate_id)

    async def check_and_record_use(
        self,
        mandate_id: str,
        amount_minor_units: float,
        check: Callable[[MandateContext], Sequence[str]],
    ) -> CheckAndRecordUseResult:
        _assert_valid_amount(amount_minor_units)
        await self._ensure_directory()
        async with self._locked(mandate_id):
            current = await self._read_context(mandate_id)
            violations = check(current)
            if len(violations) > 0:
                return CheckAndRecordUseRejected(ok=False, violations=violations)
            updated: MandateContext = {
                "total_amount": current["total_amount"] + amount_minor_units,
                "total_uses": current["total_uses"] + 1,
                "last_used_date": self._now(),
            }
            await asyncio.to_thread(self._context_path(mandate_id).write_text, json.dumps(updated))
            return CheckAndRecordUseOk(ok=True, context=updated)


def create_mandate_consumption_store(
    *, directory: str | Path, now: Optional[Callable[[], float]] = None
) -> MandateConsumptionStore:
    return _FileMandateConsumptionStore(directory, now)
