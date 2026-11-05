// SPDX-License-Identifier: Apache-2.0
// Unit tests for the constraint evaluators ported from AP2's constraints.py.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkPaymentConstraints, checkCheckoutConstraints, merchantMatches } from '../dist/index.js';

const MERCHANT = { id: 'm1', name: 'Acme', website: 'https://acme.example' };
const OTHER_MERCHANT = { id: 'm2', name: 'Other', website: 'https://other.example' };
const INSTRUMENT = { id: 'card-1', type: 'card' };
const BASE_PAYMENT = {
	vct: 'mandate.payment.1',
	transaction_id: 't1',
	payee: MERCHANT,
	payment_amount: { amount: 1000, currency: 'USD' },
	payment_instrument: INSTRUMENT,
};
function openMandate(constraints, extra = {}) {
	return { vct: 'mandate.payment.open.1', constraints, cnf: { jwk: {} }, ...extra };
}

test('merchantMatches by id takes precedence', () => {
	assert.equal(merchantMatches({ id: 'a', name: 'X' }, { id: 'a', name: 'Y' }), true);
	assert.equal(merchantMatches({ id: 'a', name: 'X' }, { id: 'b', name: 'X' }), false);
});

test('amount_range: within range passes', () => {
	const open = openMandate([{ type: 'payment.amount_range', currency: 'USD', max: 2000, min: 500 }]);
	assert.deepEqual(checkPaymentConstraints(open, BASE_PAYMENT), []);
});

test('amount_range: over max fails', () => {
	const open = openMandate([{ type: 'payment.amount_range', currency: 'USD', max: 500 }]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT);
	assert.ok(violations.some((v) => v.includes('exceeds maximum')));
});

test('amount_range: currency mismatch fails', () => {
	const open = openMandate([{ type: 'payment.amount_range', currency: 'EUR', max: 2000 }]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT);
	assert.ok(violations.some((v) => v.includes('Currency mismatch')));
});

test('allowed_payees: payee in list passes', () => {
	const open = openMandate([{ type: 'payment.allowed_payees', allowed: [MERCHANT] }]);
	assert.deepEqual(checkPaymentConstraints(open, BASE_PAYMENT), []);
});

test('allowed_payees: payee not in list fails', () => {
	const open = openMandate([{ type: 'payment.allowed_payees', allowed: [OTHER_MERCHANT] }]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT);
	assert.ok(violations.some((v) => v.includes('not in allowed list')));
});

test('payment.reference requires an open checkout hash', () => {
	const open = openMandate([{ type: 'payment.reference', conditional_transaction_id: 'abc' }]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT);
	assert.ok(violations.some((v) => v.includes('required to evaluate')));
});

test('payment.reference matches the supplied hash', () => {
	const open = openMandate([{ type: 'payment.reference', conditional_transaction_id: 'abc' }]);
	assert.deepEqual(checkPaymentConstraints(open, BASE_PAYMENT, 'abc'), []);
});

test('agent_recurrence requires amount_range and budget constraints', () => {
	const open = openMandate([{ type: 'payment.agent_recurrence', frequency: 'DAILY' }]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT);
	assert.ok(violations.includes('payment.agent_recurrence requires payment.amount_range constraint'));
	assert.ok(violations.includes('payment.agent_recurrence requires payment.budget constraint'));
});

test('agent_recurrence: max_occurrences exceeded fails', () => {
	const open = openMandate([
		{ type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: 2 },
		{ type: 'payment.amount_range', currency: 'USD', max: 2000 },
		{ type: 'payment.budget', currency: 'USD', max: 100 },
	]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT, undefined, { total_amount: 0, total_uses: 2 });
	assert.ok(violations.some((v) => v.includes('Maximum occurrences exceeded')));
});

test('budget: cumulative spend within budget passes', () => {
	const open = openMandate([
		{ type: 'payment.budget', currency: 'USD', max: 50 },
		{ type: 'payment.amount_range', currency: 'USD', max: 2000 },
		{ type: 'payment.agent_recurrence', frequency: 'DAILY' },
	]);
	// past spend 2000 cents + this 1000 cents = 3000 cents = $30, under the $50 budget.
	assert.deepEqual(checkPaymentConstraints(open, BASE_PAYMENT, undefined, { total_amount: 2000, total_uses: 1 }), []);
});

test('budget: cumulative spend over budget fails', () => {
	// max $5 (500 cents); BASE_PAYMENT spends 1000 cents, which exceeds it.
	const open = openMandate([
		{ type: 'payment.budget', currency: 'USD', max: 5 },
		{ type: 'payment.amount_range', currency: 'USD', max: 2000 },
		{ type: 'payment.agent_recurrence', frequency: 'DAILY' },
	]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT, undefined, { total_amount: 0, total_uses: 0 });
	assert.ok(violations.some((v) => v.includes('exceeds budget limit')));
});

test('allowed_payment_instruments: instrument not allowed fails', () => {
	const open = openMandate([{ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'other-card', type: 'card' }] }]);
	const violations = checkPaymentConstraints(open, BASE_PAYMENT);
	assert.ok(violations.some((v) => v.includes('not in allowed list')));
});

test('execution_date: outside window fails', () => {
	const open = openMandate([{ type: 'payment.execution_date', not_before: '2027-01-01', not_after: '2027-12-31' }]);
	const payment = { ...BASE_PAYMENT, execution_date: '2026-01-01' };
	const violations = checkPaymentConstraints(open, payment);
	assert.ok(violations.some((v) => v.includes('before allowed window')));
});

test('pre-set payee in the open mandate must match the closed mandate', () => {
	const open = openMandate([{ type: 'payment.amount_range', currency: 'USD', max: 2000 }], { payee: OTHER_MERCHANT });
	const violations = checkPaymentConstraints(open, BASE_PAYMENT);
	assert.ok(violations.some((v) => v.includes('Pre-set payee mismatch')));
});

test('checkout allowed_merchants: merchant not allowed fails', () => {
	const open = { vct: 'mandate.checkout.open.1', constraints: [{ type: 'checkout.allowed_merchants', allowed: [OTHER_MERCHANT] }], cnf: { jwk: {} } };
	const checkout = { id: 'c1', merchant: MERCHANT, line_items: [], status: 'incomplete', currency: 'USD', totals: [] };
	const violations = checkCheckoutConstraints(open, checkout);
	assert.ok(violations.some((v) => v.includes('not in allowed list')));
});

test('checkout line_items: wildcard requirement satisfied by any item', () => {
	const open = {
		vct: 'mandate.checkout.open.1',
		constraints: [{ type: 'checkout.line_items', items: [{ id: 'req1', acceptable_items: [], quantity: 1 }] }],
		cnf: { jwk: {} },
	};
	const checkout = {
		id: 'c1',
		line_items: [{ id: 'li1', item: { id: 'sku-1', title: 'Shoe' }, quantity: 1, totals: [] }],
		status: 'incomplete',
		currency: 'USD',
		totals: [],
	};
	assert.deepEqual(checkCheckoutConstraints(open, checkout), []);
});

test('checkout line_items: unsatisfiable requirement fails', () => {
	const open = {
		vct: 'mandate.checkout.open.1',
		constraints: [{ type: 'checkout.line_items', items: [{ id: 'req1', acceptable_items: [{ id: 'sku-X', title: 'X' }], quantity: 1 }] }],
		cnf: { jwk: {} },
	};
	const checkout = {
		id: 'c1',
		line_items: [{ id: 'li1', item: { id: 'sku-1', title: 'Shoe' }, quantity: 1, totals: [] }],
		status: 'incomplete',
		currency: 'USD',
		totals: [],
	};
	const violations = checkCheckoutConstraints(open, checkout);
	assert.ok(violations.length > 0);
});
