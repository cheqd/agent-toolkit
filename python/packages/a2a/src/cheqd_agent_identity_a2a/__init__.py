"""cheqd_agent_identity_a2a - A2A binding: canonical request shape, the
`https://cheqd.io/a2a/ext/trust/v1` extension's per-DID checks, a from-spec
`org.kya-os/proof.v1` holder-of-key proof engine (mint + verify), a from-spec
`org.kya-os/response-proof` engine, and the gate/client wiring that composes them.

DRAFT - early exploration, not reviewed or stable. Python port of
@cheqd/agent-identity-a2a, structured differently from the TypeScript original in one respect:
`gate.py` collapses TypeScript's `user-builder.ts` + `wrapper.ts` into one layer, because
Python's `a2a-sdk` builds its `ServerCallContext` synchronously, unlike TypeScript's async
Express `userBuilder` seam. `gate.py`/`client.py` operate on plain JSON-safe dicts, not the
real `a2a-sdk`'s protobuf-typed objects - converting between them is the integrator's job.
See docs/design-decisions.md D12-D15.

SPDX-License-Identifier: Apache-2.0
"""

from cheqd_agent_identity_a2a.client import (
    ProofInterceptor,
    ProofInterceptorOptions,
    ProofInterceptorState,
    ResponseProofCheck,
)
from cheqd_agent_identity_a2a.covered_request import (
    LEGACY_PROOF_META_KEY,
    PROOF_META_KEY,
    RESPONSE_PROOF_META_KEY,
    CoveredRequest,
    covered_request,
    covered_result,
)
from cheqd_agent_identity_a2a.gate import (
    AgentIdentityGate,
    GateEnforcementError,
    GateUser,
    ResponseProofOptions,
    TrustExtensionGate,
    VerifiedCaller,
    enforce,
    verify_caller,
)
from cheqd_agent_identity_a2a.proof.build import BuildProofContext, build_card_proof
from cheqd_agent_identity_a2a.proof.response import (
    RESPONSE_PROOF_PROFILE_BODY,
    RESPONSE_PROOF_PROFILE_ENVELOPE,
    ResponseProofIdentity,
    ResponseProofSession,
    ResponseProofVerifyFailed,
    ResponseProofVerifyOk,
    generate_response_proof,
    verify_response_proof,
)
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
    "ProofInterceptor",
    "ProofInterceptorOptions",
    "ProofInterceptorState",
    "ResponseProofCheck",
    "LEGACY_PROOF_META_KEY",
    "PROOF_META_KEY",
    "RESPONSE_PROOF_META_KEY",
    "CoveredRequest",
    "covered_request",
    "covered_result",
    "AgentIdentityGate",
    "GateEnforcementError",
    "GateUser",
    "ResponseProofOptions",
    "TrustExtensionGate",
    "VerifiedCaller",
    "enforce",
    "verify_caller",
    "BuildProofContext",
    "build_card_proof",
    "RESPONSE_PROOF_PROFILE_BODY",
    "RESPONSE_PROOF_PROFILE_ENVELOPE",
    "ResponseProofIdentity",
    "ResponseProofSession",
    "ResponseProofVerifyFailed",
    "ResponseProofVerifyOk",
    "generate_response_proof",
    "verify_response_proof",
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
