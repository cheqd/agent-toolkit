"""KYA-OS Entity Card — status-list PROOF check (W3C Data Integrity, `eddsa-jcs-2022`).

Ported from `@kya-os/mcp/card/status-list-proof.ts`, read directly from `node_modules/
@kya-os/mcp/dist` - see docs/design-decisions.md D10. W3C Bitstring Status List v1.0 has a
verifier check every proof on the status-list credential before it reads a bit: the list is
what says a credential is revoked, so a list nobody verified lets whoever serves it clear a
revocation. `create_revocation_checker` (`revocation.py`) takes that check as its
`verify_status_list` seam; `create_status_list_proof_verifier` is this package's
implementation for lists signed with `DataIntegrityProof`/`eddsa-jcs-2022` by an Ed25519 key
in the list issuer's DID document.

Unlike the TypeScript original, this does not reimplement the cryptosuite construction
itself - `proof/eddsa_jcs_2022.py`'s `verify_eddsa_jcs_2022` already IS that construction
(built earlier for agent-card verification, read line-by-line from the identical TypeScript
cryptosuite logic), so this module is a thin adapter from that generic verifier to the
`RevocationChecker`'s `verify_status_list` seam shape, not a second implementation of it.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import Any

from cheqd_agent_identity.proof.eddsa_jcs_2022 import ResolveDidDocument, verify_eddsa_jcs_2022
from cheqd_agent_identity.status.revocation import VerifyStatusList


def create_status_list_proof_verifier(resolve_did_document: ResolveDidDocument) -> VerifyStatusList:
    """Build a `VerifyStatusList` for `DataIntegrityProof`/`eddsa-jcs-2022` status lists. Pass
    it to `create_revocation_checker` (`revocation.py`) as `verify_status_list`.
    """

    async def verify_status_list(credential: Any) -> bool:
        return await verify_eddsa_jcs_2022(credential, resolve_did_document)

    return verify_status_list
