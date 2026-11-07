"""The nonce-cache provider contract this package's gates use.

The TypeScript side implements `@kya-os/mcp`'s `NonceCacheProvider` interface directly, since
that package ships it. No Python equivalent of `@kya-os/mcp` exists (checked PyPI directly -
see `docs/design-decisions.md`), so this module defines the same contract as a plain Python
ABC: `consume` atomically records an unseen `(agent_did, nonce)` for `ttl_seconds`, returning
`True` only when this call records it; `has`/`add` are inspection and the non-atomic fallback
when a verifier's own fallback path is used instead of `consume`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class NonceCacheProvider(ABC):
    async def consume(self, nonce: str, ttl_seconds: int, agent_did: Optional[str] = None) -> bool:
        """Atomically record an unseen `(agent_did, nonce)` for `ttl_seconds`. Return `True`
        only when this call records it, `False` when an unexpired record already exists.
        Optional for compatibility - a subclass that does not override this falls back to
        `has()` then `add()`, which cannot stop concurrent duplicates of one proof.
        """
        if await self.has(nonce, agent_did):
            return False
        await self.add(nonce, ttl_seconds, agent_did)
        return True

    @abstractmethod
    async def has(self, nonce: str, agent_did: Optional[str] = None) -> bool: ...

    @abstractmethod
    async def add(self, nonce: str, ttl_seconds: int, agent_did: Optional[str] = None) -> None: ...

    async def cleanup(self) -> None:
        """Deletes every entry PROVEN expired. Safe to call periodically to bound storage size."""

    async def destroy(self) -> None:
        """Releases any held resources (open handles, connections). No-op by default."""
