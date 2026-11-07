"""cheqd_agent_identity - Shared identity core: DID resolution, reciprocal did:web <-> did:cheqd
linkage, DID-Linked Resource policy, credential status and key resolution.

DRAFT - early exploration, not reviewed or stable. The public API may change completely.
Do not depend on this package. See the repository README for how the packages relate.

Python port of @cheqd/agent-identity. `status/status_list_resolver.py` and
`status/eddsa_jcs_status.py` (plus the `revocation.py`/`status_list_proof.py`/
`statuslist_bits.py` modules they depend on) re-specify the `@kya-os/mcp` provider seams they
adapt to locally, the same way `replay/nonce_cache_provider.py` already did for
`NonceCacheProvider` - no Python package implementing that framework exists to depend on, so
this package defines just the seams its own modules actually use - see
docs/design-decisions.md D10.

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
from cheqd_agent_identity.status.eddsa_jcs_status import (
    CheqdStatusCheckerOptions,
    create_cheqd_status_checker,
)
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
from cheqd_agent_identity.status.revocation import (
    STATUS_PURPOSE_REVOCATION,
    ChainResult,
    RevocationChecker,
    RevocationVerdict,
    create_revocation_checker,
    evaluate_revocation_chain,
)
from cheqd_agent_identity.status.status_list_proof import create_status_list_proof_verifier
from cheqd_agent_identity.status.status_list_resolver import (
    MinimalCredentialStatus,
    StatusListResolverLike,
    create_ledger_anchored_status_list_resolver,
)
from cheqd_agent_identity.status.statuslist_bits import (
    MAX_STATUS_LIST_BYTES,
    assert_status_purpose,
    decode_status_list_payload,
    parse_status_list_index,
    read_status_bit,
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
    "CheqdStatusCheckerOptions",
    "create_cheqd_status_checker",
    "STATUS_PURPOSE_REVOCATION",
    "ChainResult",
    "RevocationChecker",
    "RevocationVerdict",
    "create_revocation_checker",
    "evaluate_revocation_chain",
    "create_status_list_proof_verifier",
    "MinimalCredentialStatus",
    "StatusListResolverLike",
    "create_ledger_anchored_status_list_resolver",
    "MAX_STATUS_LIST_BYTES",
    "assert_status_purpose",
    "decode_status_list_payload",
    "parse_status_list_index",
    "read_status_bit",
]
