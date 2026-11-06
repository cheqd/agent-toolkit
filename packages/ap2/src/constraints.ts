/**
 * Payment and checkout constraint evaluation - a faithful port of AP2's `constraints.py`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { evaluateLineItemsMaxFlow } from './max-flow.js';
import type {
	AgentRecurrence,
	AllowedMerchants,
	AllowedPayees,
	AllowedPaymentInstruments,
	AllowedPisps,
	AmountRange,
	Budget,
	Checkout,
	CheckoutConstraint,
	ExecutionDateConstraint,
	LineItems,
	MandateContext,
	Merchant,
	OpenCheckoutMandate,
	OpenPaymentMandate,
	PaymentConstraint,
	PaymentMandate,
	PaymentReference,
} from './types.js';

/** Match merchants by `id` (preferred), or by `name` + `website` (both present and equal). */
export function merchantMatches(candidate: Merchant, target: Merchant): boolean {
	if (candidate.id && target.id) return candidate.id === target.id;
	return Boolean(candidate.name) && candidate.name === target.name && Boolean(candidate.website) && candidate.website === target.website;
}

function evaluateAmountRange(constraint: AmountRange, closed: PaymentMandate): string[] {
	const violations: string[] = [];
	const amount = closed.payment_amount;
	if (constraint.currency && amount.currency !== constraint.currency) {
		violations.push(`Currency mismatch: expected ${constraint.currency}, got ${amount.currency}`);
	}
	if (constraint.min !== undefined && amount.amount < constraint.min) {
		violations.push(`Amount ${amount.amount} below minimum ${constraint.min}`);
	}
	if (amount.amount > constraint.max) {
		violations.push(`Amount ${amount.amount} exceeds maximum ${constraint.max}`);
	}
	return violations;
}

function evaluateAllowedPayees(constraint: AllowedPayees, closed: PaymentMandate): string[] {
	const payee = closed.payee;
	if (constraint.allowed.some((allowed) => merchantMatches(allowed, payee))) return [];
	return [`Payee ${payee.name} not in allowed list`];
}

/** Binds the payment to a specific open checkout mandate via the `checkout_reference` digest:
 * the closed payment's `transaction_id` must equal `conditional_transaction_id`. */
function evaluatePaymentReference(constraint: PaymentReference, openCheckoutHash: string | undefined): string[] {
	if (!openCheckoutHash) return ['open_checkout_hash is required to evaluate PaymentReference constraints'];
	if (openCheckoutHash !== constraint.conditional_transaction_id) {
		return [`PaymentReference mismatch: expected open checkout hash ${constraint.conditional_transaction_id}, got ${openCheckoutHash}`];
	}
	return [];
}

/** Upstream's own `AgentRecurrenceEvaluator.evaluate` only checks `max_occurrences` against
 * `mandate_context.total_uses` - `frequency` is a required, validated field but is not actually
 * enforced anywhere in `constraints.py` (no period-window check exists there either). Ported
 * faithfully: `frequency` is validated by the type system (`types.ts`'s `Frequency`) but not
 * otherwise used here. */
function evaluateAgentRecurrence(constraint: AgentRecurrence, context: MandateContext | undefined): string[] {
	const limit = constraint.max_occurrences;
	if (limit === undefined) return [];
	if (!context) return ['Missing mandate context required to evaluate recurrence'];
	if (context.total_uses >= limit) return [`Maximum occurrences exceeded: ${context.total_uses} >= ${limit}`];
	return [];
}

function evaluateAllowedPaymentInstruments(constraint: AllowedPaymentInstruments, closed: PaymentMandate): string[] {
	const instrument = closed.payment_instrument;
	if (!instrument) return ['Missing payment instrument in closed mandate'];
	if (constraint.allowed.some((allowed) => allowed.id === instrument.id)) return [];
	return [`Payment instrument ${instrument.id} not in allowed list`];
}

function evaluateAllowedPisps(constraint: AllowedPisps, closed: PaymentMandate): string[] {
	if (!closed.pisp) return ['Missing PISP in closed mandate'];
	const pisp = closed.pisp;
	if (constraint.allowed.some((allowed) => allowed.domain_name === pisp.domain_name && allowed.legal_name === pisp.legal_name && allowed.brand_name === pisp.brand_name)) {
		return [];
	}
	return [`PISP ${JSON.stringify(pisp)} not in allowed list`];
}

/** Upstream's `Budget.max` is in MAJOR units (dollars) while `AmountRange`'s min/max are MINOR
 * units (cents) - a real inconsistency in the AP2 schema itself, preserved here rather than
 * "fixed", since this package verifies what AP2 actually signs. The `* 100` below also assumes
 * a 2-decimal currency (matching upstream's own hardcoded assumption) - not correct for
 * zero-decimal currencies (e.g. JPY), but that is upstream's bug to fix, not ours to paper over. */
function evaluateBudget(constraint: Budget, closed: PaymentMandate, context: MandateContext | undefined): string[] {
	if (closed.payment_amount.currency !== constraint.currency) {
		return [`Budget currency mismatch: expected ${constraint.currency}, got ${closed.payment_amount.currency}`];
	}
	if (!context) return ['Missing mandate context required to evaluate budget'];
	const pastSpend = context.total_amount;
	const totalSpend = pastSpend + closed.payment_amount.amount;
	const budgetMaxCents = Math.trunc(constraint.max * 100);
	if (totalSpend > budgetMaxCents) {
		return [`Cumulative spend ${totalSpend} exceeds budget limit ${budgetMaxCents} (past spend: ${pastSpend})`];
	}
	return [];
}

function evaluateExecutionDate(constraint: ExecutionDateConstraint, closed: PaymentMandate): string[] {
	const execDate = closed.execution_date;
	if (!execDate) return [];
	const violations: string[] = [];
	if (constraint.not_before && execDate < constraint.not_before) {
		violations.push(`Execution date ${execDate} is before allowed window ${constraint.not_before}`);
	}
	if (constraint.not_after && execDate > constraint.not_after) {
		violations.push(`Execution date ${execDate} is after allowed window ${constraint.not_after}`);
	}
	return violations;
}

function evaluatePaymentConstraint(constraint: PaymentConstraint, closed: PaymentMandate, openCheckoutHash: string | undefined, context: MandateContext | undefined): string[] {
	switch (constraint.type) {
		case 'payment.amount_range':
			return evaluateAmountRange(constraint, closed);
		case 'payment.allowed_payees':
			return evaluateAllowedPayees(constraint, closed);
		case 'payment.reference':
			return evaluatePaymentReference(constraint, openCheckoutHash);
		case 'payment.agent_recurrence':
			return evaluateAgentRecurrence(constraint, context);
		case 'payment.allowed_payment_instruments':
			return evaluateAllowedPaymentInstruments(constraint, closed);
		case 'payment.allowed_pisps':
			return evaluateAllowedPisps(constraint, closed);
		case 'payment.budget':
			return evaluateBudget(constraint, closed, context);
		case 'payment.execution_date':
			return evaluateExecutionDate(constraint, closed);
	}
}

/** Pre-set claims the open mandate fixed at issuance must appear unchanged in the closed mandate. */
export function checkPresetPaymentClaims(openMandate: OpenPaymentMandate, closed: PaymentMandate): string[] {
	const violations: string[] = [];
	if (openMandate.payee !== undefined && !merchantMatches(openMandate.payee, closed.payee)) {
		violations.push(`Pre-set payee mismatch: expected ${openMandate.payee.name}, got ${closed.payee.name}`);
	}
	if (openMandate.payment_amount !== undefined && !amountEquals(openMandate.payment_amount, closed.payment_amount)) {
		violations.push(`Pre-set amount mismatch: expected ${JSON.stringify(openMandate.payment_amount)}, got ${JSON.stringify(closed.payment_amount)}`);
	}
	if (openMandate.payment_instrument !== undefined && !instrumentEquals(openMandate.payment_instrument, closed.payment_instrument)) {
		violations.push('Pre-set payment_instrument mismatch');
	}
	if (openMandate.execution_date !== undefined && openMandate.execution_date !== closed.execution_date) {
		violations.push(`Pre-set execution_date mismatch: expected ${openMandate.execution_date}, got ${closed.execution_date}`);
	}
	return violations;
}

function amountEquals(a: { amount: number; currency: string }, b: { amount: number; currency: string }): boolean {
	return a.amount === b.amount && a.currency === b.currency;
}
function instrumentEquals(a: { id: string; type: string }, b: { id: string; type: string }): boolean {
	return a.id === b.id && a.type === b.type;
}

/**
 * Verify the closed payment satisfies the open mandate's constraints, including that any
 * pre-set claims are present and unchanged. `openCheckoutHash` is required only if a
 * `payment.reference` constraint is present; `context` is required only if `agent_recurrence`
 * or `budget` constraints are present.
 */
export function checkPaymentConstraints(
	openMandate: OpenPaymentMandate,
	closedPayment: PaymentMandate,
	openCheckoutHash?: string,
	context?: MandateContext,
): string[] {
	const violations: string[] = [...checkPresetPaymentClaims(openMandate, closedPayment)];

	const hasRecurrence = openMandate.constraints.some((c) => c.type === 'payment.agent_recurrence');
	if (hasRecurrence) {
		const hasAmount = openMandate.constraints.some((c) => c.type === 'payment.amount_range');
		const hasBudget = openMandate.constraints.some((c) => c.type === 'payment.budget');
		if (!hasAmount) violations.push('payment.agent_recurrence requires payment.amount_range constraint');
		if (!hasBudget) violations.push('payment.agent_recurrence requires payment.budget constraint');
	}

	for (const constraint of openMandate.constraints) {
		violations.push(...evaluatePaymentConstraint(constraint, closedPayment, openCheckoutHash, context));
	}
	return violations;
}

function evaluateAllowedMerchants(constraint: AllowedMerchants, checkout: Checkout): string[] {
	const merchant = checkout.merchant;
	if (!merchant) return ['Missing merchant in checkout'];
	if (constraint.allowed.some((allowed) => merchantMatches(allowed, merchant))) return [];
	return [`Merchant ${merchant.name ?? ''} not in allowed list`];
}

function evaluateLineItems(constraint: LineItems, checkout: Checkout): string[] {
	const items = checkout.line_items ?? [];
	if (items.length === 0) return ['Empty cart does not satisfy line_items constraint'];
	return evaluateLineItemsMaxFlow(items, constraint.items);
}

function evaluateCheckoutConstraint(constraint: CheckoutConstraint, checkout: Checkout): string[] {
	switch (constraint.type) {
		case 'checkout.allowed_merchants':
			return evaluateAllowedMerchants(constraint, checkout);
		case 'checkout.line_items':
			return evaluateLineItems(constraint, checkout);
	}
}

/** Verify a decoded Checkout satisfies the open checkout mandate's constraints. */
export function checkCheckoutConstraints(openMandate: OpenCheckoutMandate, checkout: Checkout): string[] {
	const violations: string[] = [];
	for (const constraint of openMandate.constraints) violations.push(...evaluateCheckoutConstraint(constraint, checkout));
	return violations;
}
