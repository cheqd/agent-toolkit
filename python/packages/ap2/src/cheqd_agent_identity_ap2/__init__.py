"""cheqd_agent_identity_ap2 - AP2 (Agent Payments Protocol) binding: `cnf` key continuity, the
authorised-secondary-key tier, and open/closed mandate chain verification.

DRAFT - early exploration, not reviewed or stable. Python port of @cheqd/agent-identity-ap2.

SPDX-License-Identifier: Apache-2.0
"""

from cheqd_agent_identity_ap2.cnf_fusion import (
    CnfFusionFailed,
    CnfFusionOk,
    CnfFusionResult,
    calculate_jwk_thumbprint,
    verify_cnf_continuity,
    verify_same_key_continuity,
)
from cheqd_agent_identity_ap2.constraints import (
    check_checkout_constraints,
    check_payment_constraints,
    check_preset_payment_claims,
    merchant_matches,
)
from cheqd_agent_identity_ap2.mandate_chain import CheckoutMandateChain, PaymentMandateChain, sha256_base64url
from cheqd_agent_identity_ap2.mandate_consumption_store import (
    MandateConsumptionStore,
    create_mandate_consumption_store,
)
from cheqd_agent_identity_ap2.max_flow import evaluate_line_items_max_flow
from cheqd_agent_identity_ap2.payment_key_authorization import (
    AGENT_PAYMENT_KEY_CREDENTIAL_TYPE,
    AgentPaymentKeyCredential,
    AgentPaymentKeyCredentialStatus,
    AgentPaymentKeyCredentialSubject,
    PaymentKeyAuthorizationDeps,
    PaymentKeyAuthorizationFailed,
    PaymentKeyAuthorizationOk,
    PaymentKeyAuthorizationResult,
    verify_agent_payment_key_credential,
)
from cheqd_agent_identity_ap2.sd_jwt_presentation import (
    KeyBinding,
    VerifiedOpenMandatePresentation,
    transaction_data_hash,
    verify_open_checkout_mandate_presentation,
    verify_open_payment_mandate_presentation,
    verify_transaction_data_binding,
)

__all__ = [
    "CnfFusionFailed",
    "CnfFusionOk",
    "CnfFusionResult",
    "calculate_jwk_thumbprint",
    "verify_cnf_continuity",
    "verify_same_key_continuity",
    "check_checkout_constraints",
    "check_payment_constraints",
    "check_preset_payment_claims",
    "merchant_matches",
    "CheckoutMandateChain",
    "PaymentMandateChain",
    "sha256_base64url",
    "MandateConsumptionStore",
    "create_mandate_consumption_store",
    "evaluate_line_items_max_flow",
    "AGENT_PAYMENT_KEY_CREDENTIAL_TYPE",
    "AgentPaymentKeyCredential",
    "AgentPaymentKeyCredentialStatus",
    "AgentPaymentKeyCredentialSubject",
    "PaymentKeyAuthorizationDeps",
    "PaymentKeyAuthorizationFailed",
    "PaymentKeyAuthorizationOk",
    "PaymentKeyAuthorizationResult",
    "verify_agent_payment_key_credential",
    "KeyBinding",
    "VerifiedOpenMandatePresentation",
    "transaction_data_hash",
    "verify_open_checkout_mandate_presentation",
    "verify_open_payment_mandate_presentation",
    "verify_transaction_data_binding",
]
