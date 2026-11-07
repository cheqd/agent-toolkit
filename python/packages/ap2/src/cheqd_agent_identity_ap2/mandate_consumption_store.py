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
import os
import time
from pathlib import Path
from typing import Callable, Optional, Protocol

from cheqd_agent_identity_ap2.types import MandateContext


class MandateConsumptionStore(Protocol):
    async def consume_once(self, mandate_id: str) -> bool:
        """Atomically consumes a one-time-use mandate. Returns `False` if already consumed."""
        ...

    async def record_use(self, mandate_id: str, amount_minor_units: float) -> MandateContext:
        """Records one use of amount `amount_minor_units` against `mandate_id`, returning the
        updated context.
        """
        ...

    async def get_context(self, mandate_id: str) -> MandateContext:
        """Reads the current context without recording a use. Absent mandate -> zeroed
        context.
        """
        ...


class _FileMandateConsumptionStore:
    def __init__(self, directory: str | Path, now: Optional[Callable[[], float]] = None) -> None:
        self._directory = Path(directory)
        self._now = now or (lambda: time.time() * 1000)
        self._ready = False
        self._ready_lock = asyncio.Lock()
        # Per-mandate-id in-process serialization for record_use's read-modify-write.
        self._locks: dict[str, asyncio.Lock] = {}

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

    def _lock_for(self, mandate_id: str) -> asyncio.Lock:
        lock = self._locks.get(mandate_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[mandate_id] = lock
        return lock

    async def _read_context(self, mandate_id: str) -> MandateContext:
        try:
            raw = await asyncio.to_thread(self._context_path(mandate_id).read_text)
        except FileNotFoundError:
            return MandateContext(total_amount=0, total_uses=0)
        parsed = json.loads(raw)
        context: MandateContext = {
            "total_amount": parsed.get("total_amount", 0)
            if isinstance(parsed.get("total_amount"), (int, float))
            else 0,
            "total_uses": parsed.get("total_uses", 0)
            if isinstance(parsed.get("total_uses"), (int, float))
            else 0,
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
        await self._ensure_directory()
        async with self._lock_for(mandate_id):
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


def create_mandate_consumption_store(
    *, directory: str | Path, now: Optional[Callable[[], float]] = None
) -> MandateConsumptionStore:
    return _FileMandateConsumptionStore(directory, now)
