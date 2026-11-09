"""A `did:cheqd` resolver, for the opt-in slot in `create_retrieve_public_key` (and anywhere
else that needs a `did:cheqd` document). Fetches from a universal-resolver-shaped endpoint (the
public `resolver.cheqd.net` or an equivalent), accepting either a DID Resolution Result
(`{ "didDocument": ... }`) or a raw DID document - the public resolver has returned both shapes
across versions, so this reads whichever is present rather than assuming one.

Deliberately NOT the default for `create_retrieve_public_key`'s `resolve_did_cheqd` option:
`did:cheqd` resolution needs an explicit, injected resolver URL the caller trusts, not a
hardcoded endpoint this package reaches for on its own.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional, Protocol

import httpx

from cheqd_agent_identity.agent_card.retrieve_public_key import (
    MinimalDidDocument,
    _parse_minimal_did_document,
)

__all__ = ["MinimalDidDocument", "create_did_cheqd_resolver"]


class DidCheqdResolverResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


DidCheqdFetch = Callable[[str], Awaitable[DidCheqdResolverResponse]]


async def _default_fetch(url: str) -> DidCheqdResolverResponse:
    async with httpx.AsyncClient() as client:
        return await client.get(url)


def create_did_cheqd_resolver(
    *,
    resolver_url: str,
    fetch: Optional[DidCheqdFetch] = None,
) -> Callable[[str], Awaitable[Optional[MinimalDidDocument]]]:
    """Build a `resolve_did_cheqd(did)` callback. Fails closed - returns `None`, never raises
    past its own boundary - on a non-200 response, invalid JSON, a document with no `id`, or a
    document whose `id` does not match the DID actually requested.
    """
    do_fetch = fetch or _default_fetch
    base = resolver_url.rstrip("/")

    async def resolve_did_cheqd(did: str) -> Optional[MinimalDidDocument]:
        if not did.startswith("did:cheqd:"):
            return None
        try:
            response = await do_fetch(f"{base}/{did}")
        except Exception:
            return None
        if response.status_code != 200:
            return None
        try:
            body = response.json()
        except Exception:
            return None
        if not isinstance(body, dict):
            return None
        # Universal Resolver shape, or a raw DID document - read whichever is present.
        candidate = body["didDocument"] if isinstance(body.get("didDocument"), dict) else body
        document = _parse_minimal_did_document(candidate)
        if document is None or document.id != did:
            return None
        return document

    return resolve_did_cheqd
