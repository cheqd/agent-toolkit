"""cheqd_agent_identity_a2a - A2A binding: canonical request shape, the
`https://cheqd.io/a2a/ext/trust/v1` extension's per-DID checks, and a from-spec
`org.kya-os/proof.v1` holder-of-key proof engine (mint + verify).

DRAFT - early exploration, not reviewed or stable. PARTIAL Python port of
@cheqd/agent-identity-a2a: the TypeScript package's `userBuilder`/wrapper/client gate wiring
(`createVerifyingUserBuilder`, the gRPC equivalent, the enforcing wrapper, the client
interceptor) is NOT ported here. Those exist to wire this proof engine into `@a2a-js/sdk`'s
specific hooks; the `proof` subpackage below is the engine itself, re-implemented from spec
(not ported from TypeScript, which depends on `@kya-os/mcp` - no Python equivalent of that
package exists). See docs/design-decisions.md D12/D13.

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
from cheqd_agent_identity_a2a.proof.build import BuildProofContext, build_card_proof
from cheqd_agent_identity_a2a.proof.signer import ProofSigner, ed25519_signer_from_jwk
from cheqd_agent_identity_a2a.proof.types import (
    DEFAULT_SKEW_SEC,
    DEFAULT_TTL_SEC,
    KYA_OS_CARD_PROOF_META_KEY,
    LEGACY_CARD_PROOF_META_KEY,
    MAX_TTL_SEC,
    NONCE_RETENTION_SEC,
    PROOF_PROFILE_V1,
)
from cheqd_agent_identity_a2a.proof.verify import (
    ProofVerifyFailed,
    ProofVerifyOk,
    ProofVerifyResult,
    VerifyProofDeps,
    verify_card_proof,
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
    "BuildProofContext",
    "build_card_proof",
    "ProofSigner",
    "ed25519_signer_from_jwk",
    "DEFAULT_SKEW_SEC",
    "DEFAULT_TTL_SEC",
    "KYA_OS_CARD_PROOF_META_KEY",
    "LEGACY_CARD_PROOF_META_KEY",
    "MAX_TTL_SEC",
    "NONCE_RETENTION_SEC",
    "PROOF_PROFILE_V1",
    "ProofVerifyFailed",
    "ProofVerifyOk",
    "ProofVerifyResult",
    "VerifyProofDeps",
    "verify_card_proof",
    "TrustExtensionActivation",
    "TrustExtensionCache",
    "TrustExtensionDeps",
    "TrustExtensionFailed",
    "TrustExtensionOk",
    "TrustExtensionResult",
    "create_trust_extension_cache",
    "verify_trust_extension",
]
