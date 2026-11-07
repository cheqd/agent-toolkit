"""cheqd_agent_identity - Shared identity core: DID resolution, reciprocal did:web <-> did:cheqd
linkage, DID-Linked Resource policy, credential status and key resolution.

DRAFT - early exploration, not reviewed or stable. The public API may change completely.
Do not depend on this package. See the repository README for how the packages relate.

Python port of @cheqd/agent-identity. Does NOT port `status/status-list-resolver.ts` or
`status/eddsa-jcs-status.ts`: both exist only to adapt this package's own logic to
`@kya-os/mcp`'s provider seams, and no Python equivalent of that package exists to adapt to -
see docs/design-decisions.md.

SPDX-License-Identifier: Apache-2.0
"""

from cheqd_agent_identity.agent_card.retrieve_public_key import (
    KeyResolutionError,
    MinimalDidDocument,
    MinimalVerificationMethod,
    PublicKeyJwk,
    create_retrieve_public_key,
    key_from_document,
)
from cheqd_agent_identity.did_cheqd.resolve import create_did_cheqd_resolver
from cheqd_agent_identity.dlr.resolve_manifest import (
    ManifestCache,
    ManifestCacheOptions,
    ManifestKind,
    ManifestPrimitives,
    ManifestResolverResponse,
    ResolveManifestFailed,
    ResolveManifestOk,
    ResolveManifestOptions,
    ResolveManifestResult,
    create_manifest_cache,
    resolve_manifest,
)
from cheqd_agent_identity.linkage.reciprocal_linkage import (
    LinkageDidDocument,
    LinkageFailed,
    LinkageOk,
    ReciprocalLinkageResult,
    verify_reciprocal_linkage,
)
from cheqd_agent_identity.proof.eddsa_jcs_2022 import verify_eddsa_jcs_2022
from cheqd_agent_identity.replay.file_nonce_cache import FileNonceCacheProvider
from cheqd_agent_identity.replay.nonce_cache_provider import NonceCacheProvider
from cheqd_agent_identity.status.ledger_anchored import (
    LEDGER_LIST_RESOURCE_TYPE,
    LedgerAnchoredStatusFailed,
    LedgerAnchoredStatusOk,
    LedgerAnchoredStatusOptions,
    LedgerAnchoredStatusResult,
    StatusEntry,
    StatusListPrimitives,
    StatusListResponse,
    verify_ledger_anchored_status,
)

__all__ = [
    "KeyResolutionError",
    "MinimalDidDocument",
    "MinimalVerificationMethod",
    "PublicKeyJwk",
    "create_retrieve_public_key",
    "key_from_document",
    "create_did_cheqd_resolver",
    "ManifestCache",
    "ManifestCacheOptions",
    "ManifestKind",
    "ManifestPrimitives",
    "ManifestResolverResponse",
    "ResolveManifestFailed",
    "ResolveManifestOk",
    "ResolveManifestOptions",
    "ResolveManifestResult",
    "create_manifest_cache",
    "resolve_manifest",
    "LinkageDidDocument",
    "LinkageFailed",
    "LinkageOk",
    "ReciprocalLinkageResult",
    "verify_reciprocal_linkage",
    "verify_eddsa_jcs_2022",
    "FileNonceCacheProvider",
    "NonceCacheProvider",
    "LEDGER_LIST_RESOURCE_TYPE",
    "LedgerAnchoredStatusFailed",
    "LedgerAnchoredStatusOk",
    "LedgerAnchoredStatusOptions",
    "LedgerAnchoredStatusResult",
    "StatusEntry",
    "StatusListPrimitives",
    "StatusListResponse",
    "verify_ledger_anchored_status",
]
