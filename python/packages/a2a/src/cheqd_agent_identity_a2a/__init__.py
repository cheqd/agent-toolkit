"""cheqd_agent_identity_a2a - A2A binding: canonical request shape and the
`https://cheqd.io/a2a/ext/trust/v1` extension's per-DID checks.

DRAFT - early exploration, not reviewed or stable. PARTIAL Python port of
@cheqd/agent-identity-a2a: the actual holder-of-key proof verification gate
(`createVerifyingUserBuilder`, the gRPC equivalent, the enforcing wrapper, the client
interceptor) is NOT ported here, because it is built entirely on `@kya-os/mcp`'s
`org.kya-os/proof.v1` profile implementation, and no Python equivalent of that package exists.
See docs/design-decisions.md D12.

SPDX-License-Identifier: Apache-2.0
"""

from cheqd_agent_identity_a2a.covered_request import (
    LEGACY_PROOF_META_KEY,
    PROOF_META_KEY,
    RESPONSE_PROOF_META_KEY,
    CoveredRequest,
    covered_request,
    covered_result,
)
from cheqd_agent_identity_a2a.trust_extension import (
    TrustExtensionActivation,
    TrustExtensionCache,
    TrustExtensionDeps,
    TrustExtensionFailed,
    TrustExtensionOk,
    TrustExtensionResult,
    create_trust_extension_cache,
    verify_trust_extension,
)

__all__ = [
    "LEGACY_PROOF_META_KEY",
    "PROOF_META_KEY",
    "RESPONSE_PROOF_META_KEY",
    "CoveredRequest",
    "covered_request",
    "covered_result",
    "TrustExtensionActivation",
    "TrustExtensionCache",
    "TrustExtensionDeps",
    "TrustExtensionFailed",
    "TrustExtensionOk",
    "TrustExtensionResult",
    "create_trust_extension_cache",
    "verify_trust_extension",
]
