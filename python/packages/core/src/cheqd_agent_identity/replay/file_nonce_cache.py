"""A persistent (file-backed) replay cache: `NonceCacheProvider`, implemented over one small
file per `(agent_did, nonce)` pair instead of memory, so a consumed nonce survives a process
restart.

Atomicity: `consume()` uses `os.open(path, O_CREAT | O_EXCL)` - exclusive create, which fails
with `FileExistsError` if the file already exists. That failure IS the atomic test-and-set: the
filesystem, not this module, decides which of two concurrent callers wins. This gives
race-free behaviour for concurrent callers on ONE filesystem - it is not a distributed lock
across independent storage backends.

Reclaiming an EXPIRED file left by a previous claim is the one case needing care: reading the
expiry and then replacing the file is two steps, so two callers can both observe "expired" at
the same moment. `consume()` therefore serializes its ENTIRE body - including the initial
exclusive-create attempt - through an in-process `asyncio.Lock` keyed by `(agent_did, nonce)`
(the same per-key-lock pattern `cheqd_agent_identity_ap2`'s `mandate_consumption_store.py` uses
for `record_use`): at most one `consume()` call for a given key runs its body at a time WITHIN
this process. That closes the race for every caller sharing this `FileNonceCacheProvider`
instance, which is what the two concurrency scenarios that matter in practice - multiple
in-flight requests in one server process, and this module's own test suite - actually exercise.

Found by review: an earlier version read the expiry, then did `path.unlink()` followed by
`os.open(path, O_CREAT | O_EXCL)`, with no serialization at all. Caller A's `unlink()` could run,
caller A's `open()` could succeed and write a FRESH, valid, non-expired record, and only THEN
caller B's own (concurrently in-flight) `unlink()` for the same path could run and delete that
fresh record A just wrote - clearing the way for B's own `open()` to also succeed. The reclaim
step below uses `os.rename()` to atomically claim the expired file (rather than deleting it)
before creating the fresh record, as defense in depth for genuinely separate OS processes
sharing this directory, which the in-process lock cannot help: `rename()` on the same source
path is still atomic across processes, so at most one process's reclaim of a given expired file
can win even without the lock. But `rename()` alone, without the lock, is not sufficient: it
only checks that the source path exists, not that the thing at it is still the stale snapshot a
caller examined - a second caller could still rename away a different caller's brand-new live
record. The lock removes that exposure entirely for in-process callers, which is why both pieces
are kept.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from cheqd_agent_identity.replay.nonce_cache_provider import NonceCacheProvider


@dataclass(frozen=True)
class _Record:
    expires_at: float


class FileNonceCacheProvider(NonceCacheProvider):
    def __init__(self, *, directory: str | Path, now: Optional[Callable[[], float]] = None) -> None:
        self._directory = Path(directory)
        self._now = now or (lambda: time.time() * 1000)
        self._ready = False
        self._ready_lock = asyncio.Lock()
        # Per-(agent_did, nonce) in-process serialization for consume()'s read-reclaim-create
        # sequence - see the module doc comment for why the whole body, not just the individual
        # filesystem calls, must be serialized.
        self._locks: dict[str, asyncio.Lock] = {}

    async def _ensure_directory(self) -> None:
        if self._ready:
            return
        async with self._ready_lock:
            if self._ready:
                return
            await asyncio.to_thread(self._directory.mkdir, parents=True, exist_ok=True)
            self._ready = True

    def _lock_for(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def _path_for(self, nonce: str, agent_did: Optional[str] = None) -> Path:
        # Hash rather than use the nonce/DID directly as a filename: both are attacker-
        # influenced, and neither is safe as a raw path segment.
        key = hashlib.sha256(f"{agent_did or ''}\x00{nonce}".encode("utf-8")).hexdigest()
        return self._directory / f"{key}.json"

    async def consume(self, nonce: str, ttl_seconds: int, agent_did: Optional[str] = None) -> bool:
        await self._ensure_directory()
        path = self._path_for(nonce, agent_did)
        async with self._lock_for(str(path)):
            record = _Record(expires_at=self._now() + ttl_seconds * 1000)
            if await asyncio.to_thread(self._try_create, path, record):
                return True
            # The file exists. If it has expired, try once to reclaim it - see the module doc
            # comment for why the lock above, not this check alone, is what makes the reclaim
            # safe. A record that exists but cannot be parsed is treated the same as "not
            # expired" (blocks reclaim).
            if not await self._is_reclaimable(path):
                return False
            return await asyncio.to_thread(self._reclaim, path, record)

    @staticmethod
    def _try_create(path: Path, record: _Record) -> bool:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        try:
            os.write(fd, json.dumps({"expiresAt": record.expires_at}).encode("utf-8"))
        finally:
            os.close(fd)
        return True

    @staticmethod
    def _reclaim(path: Path, record: _Record) -> bool:
        # Claim the expired slot by moving it aside first - see the module doc comment for why
        # this, not a plain unlink() then open(), is the atomic step for cross-process safety.
        claim_path = path.with_name(f"{path.name}.reclaim-{secrets.token_hex(8)}")
        try:
            os.rename(path, claim_path)
        except FileNotFoundError:
            return False  # another caller already claimed (or cleared) this slot
        claim_path.unlink(missing_ok=True)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            # A third caller's brand-new (non-reclaim) consume() of this same nonce could have
            # won the path in between our rename and our open - its record is now the live one.
            return False
        try:
            os.write(fd, json.dumps({"expiresAt": record.expires_at}).encode("utf-8"))
        finally:
            os.close(fd)
        return True

    async def has(self, nonce: str, agent_did: Optional[str] = None) -> bool:
        await self._ensure_directory()
        return not await self._is_reclaimable(self._path_for(nonce, agent_did))

    async def add(self, nonce: str, ttl_seconds: int, agent_did: Optional[str] = None) -> None:
        await self._ensure_directory()
        record = _Record(expires_at=self._now() + ttl_seconds * 1000)
        await asyncio.to_thread(
            self._path_for(nonce, agent_did).write_text, json.dumps({"expiresAt": record.expires_at})
        )

    async def cleanup(self) -> None:
        """Deletes every entry PROVEN expired. A record that cannot be parsed is left in place
        rather than deleted: deleting it would make the nonce look unconsumed again, reopening a
        replay window to save a few bytes of disk - the wrong trade.
        """
        await self._ensure_directory()
        entries = await asyncio.to_thread(list, self._directory.glob("*.json"))
        for path in entries:
            record = await self._read_record(path)
            if record is not None and record.expires_at <= self._now():
                await asyncio.to_thread(path.unlink, True)

    async def destroy(self) -> None:
        """No open handles are kept between calls, so there is nothing to release."""

    async def _is_reclaimable(self, path: Path) -> bool:
        """`True` only when the record is provably absent or expired - the one case it is safe
        to overwrite. A record that exists but cannot be parsed is NOT reclaimable.
        """
        record = await self._read_record(path)
        return record is None or record.expires_at <= self._now()

    async def _read_record(self, path: Path) -> Optional[_Record]:
        """`None` only when the file genuinely does not exist. A file that exists but fails to
        parse returns a record whose `expires_at` is `inf` - present, never expired.
        """
        try:
            raw = await asyncio.to_thread(path.read_text)
        except FileNotFoundError:
            return None
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and isinstance(parsed.get("expiresAt"), (int, float)):
                return _Record(expires_at=float(parsed["expiresAt"]))
        except Exception:
            pass
        return _Record(expires_at=math.inf)
