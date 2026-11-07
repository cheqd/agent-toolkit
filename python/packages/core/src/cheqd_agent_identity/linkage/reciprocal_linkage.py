"""Reciprocal `alsoKnownAs` linkage between two DID documents (e.g. a `did:cheqd` anchoring
identity and a `did:web` canonical identity, or any other pair).

A one-directional claim - "my `did:cheqd` document's `alsoKnownAs` names this `did:web` DID" -
proves nothing on its own: anyone can list any DID in their own document's `alsoKnownAs`.
Linkage is only trustworthy when it is RECIPROCAL - each document names the other - because
that requires control of BOTH identities, not just the one making the claim.

This module only checks the two documents it is given; resolving them is the caller's job.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence, Union


@dataclass(frozen=True)
class LinkageDidDocument:
    id: str
    also_known_as: Optional[Sequence[str]] = field(default=None)


@dataclass(frozen=True)
class LinkageOk:
    ok: bool = True


@dataclass(frozen=True)
class LinkageFailed:
    reasons: Sequence[str]
    ok: bool = False


ReciprocalLinkageResult = Union[LinkageOk, LinkageFailed]


def verify_reciprocal_linkage(a: LinkageDidDocument, b: LinkageDidDocument) -> ReciprocalLinkageResult:
    """Check that `a` and `b` each name the other in their own `alsoKnownAs`. Order does not
    matter. Fails closed: a missing or malformed `alsoKnownAs` on either side, or a
    one-directional claim, is rejected with a reason - never silently treated as linked.
    """
    reasons: list[str] = []
    if a.id == b.id:
        reasons.append("same_did")
    if not _names_did(a.also_known_as, b.id):
        reasons.append("a_does_not_name_b")
    if not _names_did(b.also_known_as, a.id):
        reasons.append("b_does_not_name_a")
    return LinkageOk() if not reasons else LinkageFailed(reasons=tuple(reasons))


def _names_did(also_known_as: Optional[Sequence[str]], did: str) -> bool:
    return isinstance(also_known_as, (list, tuple)) and did in also_known_as
