/**
 * AP2 (Agent Payments Protocol) mandate types - a faithful port of the "open mandate" (human-not
 * present) schema from `google-agentic-commerce/AP2` (`code/sdk/schemas/ap2/*.json`, read
 * directly, commit pinned in the generating evidence - see README), not a reimplementation from
 * memory of the spec prose. Field names, optionality and the Budget-in-major-units /
 * AmountRange-in-minor-units inconsistency are preserved exactly as upstream has them, including
 * the inconsistency - this package verifies what AP2 actually signs, not a cleaned-up version of
 * it.
 *
 * Two parallel open/closed mandate pairs:
 * - `OpenPaymentMandate` (long-lived, `cnf`-bound, carries payment constraints) / `PaymentMandate`
 *   (one per transaction, checked against the open mandate's constraints).
 * - `OpenCheckoutMandate` (long-lived, `cnf`-bound, carries checkout constraints) / `CheckoutMandate`
 *   (wraps a merchant-signed `checkout_jwt`).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export interface Merchant {
	readonly id?: string;
	readonly name: string;
	readonly website?: string;
}

export interface Amount {
	/** Minor units per ISO 4217 (e.g. 27999 = $279.99). */
	readonly amount: number;
	readonly currency: string;
}

export interface PaymentInstrument {
	readonly id: string;
	readonly type: string;
	readonly description?: string;
}

export interface Pisp {
	readonly legal_name: string;
	readonly brand_name: string;
	readonly domain_name: string;
}

// --- Open Payment Mandate constraints (payment.*) --------------------------------------------

export interface AllowedPayees {
	readonly type: 'payment.allowed_payees';
	readonly allowed: readonly Merchant[];
}

export interface AmountRange {
	readonly type: 'payment.amount_range';
	readonly currency: string;
	/** Minor units. */
	readonly max: number;
	/** Minor units. Absent means no minimum. */
	readonly min?: number;
}

export interface PaymentReference {
	readonly type: 'payment.reference';
	/** Digest of the associated Open Checkout Mandate. */
	readonly conditional_transaction_id: string;
}

export type Frequency = 'ON_DEMAND' | 'DAILY' | 'WEEKLY' | 'BIWEEKLY' | 'MONTHLY' | 'QUARTERLY' | 'ANNUALLY';

export interface AgentRecurrence {
	readonly type: 'payment.agent_recurrence';
	readonly frequency: Frequency;
	readonly max_occurrences?: number;
}

export interface Budget {
	readonly type: 'payment.budget';
	/** Major units (NOT minor units - this is how upstream defines it; see constraints.ts). */
	readonly max: number;
	readonly currency: string;
}

export interface ExecutionDateConstraint {
	readonly type: 'payment.execution_date';
	readonly not_before?: string;
	readonly not_after?: string;
}

export interface AllowedPaymentInstruments {
	readonly type: 'payment.allowed_payment_instruments';
	readonly allowed: readonly PaymentInstrument[];
}

export interface AllowedPisps {
	readonly type: 'payment.allowed_pisps';
	readonly allowed: readonly Pisp[];
}

export type PaymentConstraint =
	| AgentRecurrence
	| AllowedPayees
	| AllowedPaymentInstruments
	| AllowedPisps
	| AmountRange
	| Budget
	| ExecutionDateConstraint
	| PaymentReference;

/** `vct: mandate.payment.open.1`. Long-lived, `cnf`-bound. */
export interface OpenPaymentMandate {
	readonly vct: 'mandate.payment.open.1';
	readonly constraints: readonly PaymentConstraint[];
	/** RFC 7800 confirmation claim. */
	readonly cnf: { readonly jwk: Record<string, unknown>; readonly [key: string]: unknown };
	readonly payee?: Merchant;
	readonly payment_amount?: Amount;
	readonly payment_instrument?: PaymentInstrument;
	readonly pisp?: Pisp;
	readonly execution_date?: string;
	readonly risk_data?: Record<string, unknown>;
	readonly iat?: number;
	readonly exp?: number;
}

/** `vct: mandate.payment.1`. One per transaction. */
export interface PaymentMandate {
	readonly vct: 'mandate.payment.1';
	/** base64url hash of the associated checkout_jwt (same hash alg as the sd-jwt's sd_hash, else sha-256). */
	readonly transaction_id: string;
	readonly payee: Merchant;
	readonly pisp?: Pisp;
	readonly payment_amount: Amount;
	readonly payment_instrument: PaymentInstrument;
	readonly execution_date?: string;
	readonly risk_data?: Record<string, unknown>;
	readonly iat?: number;
	readonly exp?: number;
}

// --- Open Checkout Mandate constraints (checkout.*) -------------------------------------------

export interface AllowedMerchants {
	readonly type: 'checkout.allowed_merchants';
	readonly allowed: readonly Merchant[];
}

export interface Item {
	readonly id: string;
	readonly title: string;
}

export interface LineItemRequirements {
	readonly id: string;
	readonly acceptable_items: readonly Item[];
	readonly quantity: number;
}

export interface LineItems {
	readonly type: 'checkout.line_items';
	readonly items: readonly LineItemRequirements[];
}

export type CheckoutConstraint = AllowedMerchants | LineItems;

/** `vct: mandate.checkout.open.1`. Long-lived, `cnf`-bound. */
export interface OpenCheckoutMandate {
	readonly vct: 'mandate.checkout.open.1';
	readonly constraints: readonly CheckoutConstraint[];
	readonly cnf: { readonly jwk: Record<string, unknown>; readonly [key: string]: unknown };
	readonly iat?: number;
	readonly exp?: number;
}

/** `vct: mandate.checkout.1`. The merchant-signed checkout. */
export interface CheckoutMandate {
	readonly vct: 'mandate.checkout.1';
	/** base64url-encoded merchant-signed JWT of the Checkout payload. */
	readonly checkout_jwt: string;
	/** base64url hash of checkout_jwt. */
	readonly checkout_hash: string;
	readonly iat?: number;
	readonly exp?: number;
}

// --- The Checkout object the merchant-signed checkout_jwt decodes to --------------------------

export interface LineItemTotal {
	readonly type: string;
	readonly amount: number;
	readonly [key: string]: unknown;
}

export interface LineItem {
	readonly id: string;
	readonly item: Item;
	readonly quantity: number;
	readonly totals: readonly LineItemTotal[];
	readonly parent_id?: string;
}

export type CheckoutStatus =
	| 'incomplete'
	| 'requires_escalation'
	| 'ready_for_complete'
	| 'complete_in_progress'
	| 'completed'
	| 'canceled';

/** UCP Checkout object (dev.ucp.shopping.checkout); `merchant` is AP2's own extension for mandate binding. */
export interface Checkout {
	readonly id: string;
	readonly merchant?: Merchant;
	readonly line_items: readonly LineItem[];
	readonly status: CheckoutStatus;
	readonly currency: string;
	readonly totals: readonly LineItemTotal[];
	readonly [key: string]: unknown;
}

/** Aggregated usage context for a recurring/budget-constrained mandate - the state
 * `MandateConsumptionStore` (mandate-consumption-store.ts) persists per mandate id. */
export interface MandateContext {
	readonly total_amount: number;
	readonly total_uses: number;
	readonly last_used_date?: number;
}
