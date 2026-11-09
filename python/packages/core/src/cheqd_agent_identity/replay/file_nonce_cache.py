"""A persistent (file-backed) replay cache: `NonceCacheProvider`, implemented over one small
file per `(agent_did, nonce)` pair instead of memory, so a consumed nonce survives a process
restart.

Atomicity: `consume()` uses `os.open(path, O_CREAT | O_EXCL)` - exclusive create, which fails
with `FileExistsError` if the file already exists. That failure IS the atomic test-and-set: the
filesystem, not this module, decides which of two concurrent callers wins. This gives
race-free behaviour for concurrent callers on ONE filesystem - it is not a distributed lock
across independent storage backends.

The one case this cannot resolve atomically: a caller claims an EXPIRED file left by a previous
claim. Reading the expiry and then deleting-and-recreating is two steps, so two callers can both
observe "expired" and both attempt to reclaim it; one `O_EXCL` wins, the other correctly sees
`FileExistsError` and is told `False` for that attempt even though the slot is free again. This
fails CLOSED (a legitimate nonce reuse after expiry is occasionally rejected, never a replay
incorrectly accepted), which is the safe direction to be wrong in for a replay cache.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
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

    async def _ensure_directory(self) -> None:
        if self._ready:
            return
        async with self._ready_lock:
            if self._ready:
                return
            await asyncio.to_thread(self._directory.mkdir, parents=True, exist_ok=True)
            self._ready = True

    def _path_for(self, nonce: str, agent_did: Optional[str] = None) -> Path:
        # Hash rather than use the nonce/DID directly as a filename: both are attacker-
        # influenced, and neither is safe as a raw path segment.
        key = hashlib.sha256(f"{agent_did or ''}\x00{nonce}".encode("utf-8")).hexdigest()
        return self._directory / f"{key}.json"

    async def consume(self, nonce: str, ttl_seconds: int, agent_did: Optional[str] = None) -> bool:
        await self._ensure_directory()
        path = self._path_for(nonce, agent_did)
        record = _Record(expires_at=self._now() + ttl_seconds * 1000)
        if await asyncio.to_thread(self._try_create, path, record):
            return True
        # The file exists. If it has expired, try once to reclaim it - see the module doc
        # comment for why this one retry is not itself atomic, and why that is the safe failure
        # direction. A record that exists but cannot be parsed is treated the same as "not
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
        try:
            path.unlink(missing_ok=True)
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
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
