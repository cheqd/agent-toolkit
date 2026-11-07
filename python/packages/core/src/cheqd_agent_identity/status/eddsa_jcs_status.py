"""The decision-6 status-list path: `@kya-os/mcp`'s generic card-layer status checker
(`create_revocation_checker` + `create_status_list_proof_verifier`), wired to this package's
own `did:cheqd` resolver so a `BitstringStatusListCredential`'s `DataIntegrityProof`/
`eddsa-jcs-2022` proof is checked against the issuer's on-chain key before any bit is read -
never the ledger-anchoring-only path `verify_ledger_anchored_status` takes (see that
module's doc comment; the two are for different list-integrity evidence, not alternatives
for the same one).

Ported from `@kya-os/mcp/card`'s `eddsa-jcs-status.ts`, read directly from
`node_modules/@kya-os/mcp/dist` - see docs/design-decisions.md D10 for why this exists now
(a Python consumer needing the proof-based status-list path specifically), after D10
originally left it unported for lack of one.

`did-provider-cheqd` does not yet produce a list this verifier accepts: 4.8.0 signs the
credential before `credentialSubject.encodedList` is attached, so the proof does not cover
the bits (cheqd/did-provider-cheqd#657). `cheqd/did-provider-cheqd#658` (open, unmerged) fixes
that with an opt-in `eddsa-jcs-2022` proof; this module is written against the format #658
produces, matching the TypeScript original's own scoping - there is nothing left to change
here once #658 ships: swap a synthetic fixture for a real on-chain resource, same verifier.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from cheqd_agent_identity.proof.eddsa_jcs_2022 import ResolveDidDocument
from cheqd_agent_identity.status.revocation import (
    Decompress,
    Fetch,
    RevocationChecker,
    create_revocation_checker,
)
from cheqd_agent_identity.status.status_list_proof import create_status_list_proof_verifier


@dataclass(frozen=True)
class CheqdStatusCheckerOptions:
    resolve_did_cheqd: ResolveDidDocument
    """Resolves the status list issuer's `did:cheqd` document, e.g.
    `create_did_cheqd_resolver`'s result."""
    fetch: Fetch
    """Fetches the `statusListCredential` URL. Injected so no runtime fetch dependency is
    assumed."""
    now: Optional[Callable[[], float]] = None
    """Epoch milliseconds. Defaults to `time.time() * 1000`."""
    decompress: Optional[Decompress] = None
    """Overrides the default `gzip`-based inflation."""


def create_cheqd_status_checker(options: CheqdStatusCheckerOptions) -> RevocationChecker:
    """Build a `RevocationChecker` that fails closed unless the fetched status list's
    `eddsa-jcs-2022` proof verifies against the pinned issuer's resolved `did:cheqd` key -
    per spec §5.6 option 1, the proof-based alternative to ledger-anchoring-only trust.
    """
    verify_status_list = create_status_list_proof_verifier(options.resolve_did_cheqd)
    return create_revocation_checker(
        fetch=options.fetch,
        verify_status_list=verify_status_list,
        now=options.now if options.now is not None else lambda: time.time() * 1000,
        decompress=options.decompress,
    )
