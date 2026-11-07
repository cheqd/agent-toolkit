"""Adapts `verify_ledger_anchored_status` (`ledger_anchored.py`) to `@kya-os/mcp`'s
`StatusListResolver` seam (`check_status(status) -> bool`), so delegation chain verification
can use the ledger-anchored check in place of a signed-proof-based one.

Ported from `@kya-os/mcp/cheqd`'s `status-list-resolver.ts`, read directly from
`node_modules/@kya-os/mcp/dist` - see docs/design-decisions.md D10. One resolver instance per
trusted issuer DID - the same shape `@kya-os/mcp/cheqd`'s own `createCheqdStatusListResolver`
uses, so swapping between the ledger-anchored and proof-based (`eddsa_jcs_status.py`) paths
needs no call-site change.

Fails closed per the seam's contract: RAISES (never returns a value) on anything unprovable,
so a delegation-chain verifier denies rather than treating an unresolvable status as "not
revoked".

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Literal, Optional

from cheqd_agent_identity.status.ledger_anchored import (
    LedgerAnchoredStatusOptions,
    StatusEntry,
    verify_ledger_anchored_status,
)


@dataclass(frozen=True)
class MinimalCredentialStatus:
    """The subset of `@kya-os/mcp`'s `CredentialStatus` this resolver reads."""

    status_list_index: str
    status_list_credential: str
    status_purpose: Literal["revocation", "suspension"]
    status_size: Optional[int] = None


StatusListResolverLike = Callable[[MinimalCredentialStatus], Awaitable[bool]]
"""`check_status(status) -> revoked`."""


def create_ledger_anchored_status_list_resolver(
    *, expected_issuer_did: str, options: LedgerAnchoredStatusOptions
) -> StatusListResolverLike:
    """`expected_issuer_did`: only status entries issued by this DID are trusted."""

    async def check_status(status: MinimalCredentialStatus) -> bool:
        entry = StatusEntry(
            status_list_credential=status.status_list_credential,
            status_list_index=status.status_list_index,
            status_purpose=status.status_purpose,
            status_size=status.status_size,
        )
        result = await verify_ledger_anchored_status(entry, expected_issuer_did, options)
        if not result.ok:
            raise ValueError(f"ledger_anchored_status_unresolvable: {','.join(result.reasons)}")
        return result.revoked

    return check_status
