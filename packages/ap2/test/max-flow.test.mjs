// SPDX-License-Identifier: Apache-2.0
// Tests for evaluateLineItemsMaxFlow, including the "complex" (ambiguous-match) path that
// actually exercises the Dinic max-flow solver, not just the greedy degree-1 shortcut.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateLineItemsMaxFlow } from '../dist/index.js';

const item = (id, title = id) => ({ id, title });
const lineItem = (skuId, quantity) => ({ id: `li-${skuId}`, item: item(skuId), quantity, totals: [] });
const requirement = (id, acceptableSkus, quantity) => ({ id, acceptable_items: acceptableSkus.map((s) => item(s)), quantity });

test('an item with no matching requirement at all is rejected before any flow computation', () => {
	const cart = [lineItem('a', 1)];
	const reqs = [requirement('r1', ['b'], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.ok(violations.some((v) => v.includes('not in any requirement')));
});

test('an item acceptable to two requirements is routed via max flow and passes', () => {
	// sku "a" is acceptable to both r1 and r2 - ambiguous, forces the complex/max-flow path.
	// The check is "can every cart item be assigned somewhere", not "is every requirement
	// slot filled" (confirmed against max_flow_helper.py: unassigned_items is built only from
	// leftover CART quantity, never from unmet requirement capacity) - so the single unit of
	// "a" finding a home in either r1 or r2 is sufficient; neither slot being fully staffed is
	// not itself a violation.
	const cart = [lineItem('a', 1)];
	const reqs = [requirement('r1', ['a'], 1), requirement('r2', ['a'], 1)];
	assert.deepEqual(evaluateLineItemsMaxFlow(cart, reqs), []);
});

test('two ambiguous items can satisfy two ambiguous requirements via max flow', () => {
	const cart = [lineItem('a', 1), lineItem('b', 1)];
	const reqs = [requirement('r1', ['a', 'b'], 1), requirement('r2', ['a', 'b'], 1)];
	assert.deepEqual(evaluateLineItemsMaxFlow(cart, reqs), []);
});

test('a requirement needing more than the cart holds is not itself a violation', () => {
	// Same semantics as above: only leftover (unassignable) CART quantity is ever flagged. A
	// requirement asking for more than the cart contains, with every cart unit still placed
	// into that requirement's slot, has no leftover - so this passes, which is a genuinely
	// surprising property of the upstream algorithm (ported faithfully, not "fixed" here).
	// Uses an explicit acceptable_items list rather than an empty one: see the H2 tests below for
	// why an empty acceptable_items array must never be treated as "accepts anything".
	const cart = [lineItem('a', 1)];
	const reqs = [requirement('r1', ['a'], 2)];
	assert.deepEqual(evaluateLineItemsMaxFlow(cart, reqs), []);
});

test('a cart item left over after every requirement slot fills is a violation', () => {
	// Two units of "a", but the only requirement slot (qty 1) fills after one unit - the second
	// unit has nowhere to go, which IS the leftover case this algorithm actually checks for.
	const cart = [lineItem('a', 2)];
	const reqs = [requirement('r1', ['a'], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.ok(violations.some((v) => v.includes('could not be assigned')));
});

// --- Security regression tests -----------------------------------------------------------------
// H2: an empty acceptable_items array must fail closed (reject), not be treated as a wildcard.
// SD-JWT libraries drop undisclosed array elements, so a holder withholding every disclosure for
// acceptable_items makes the verified payload show acceptable_items: [] - indistinguishable at
// this layer from an issuer-intended wildcard. Treating that as "anything is acceptable" lets a
// holder launder an item the issuer never allowed through non-disclosure.

test('H2: empty acceptable_items fails closed - a cart item is rejected, not treated as wildcard-matched', () => {
	const cart = [lineItem('sku-EVIL', 1)];
	const reqs = [requirement('r1', [], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.ok(
		violations.some((v) => v.includes('sku-EVIL') && v.includes('not in any requirement')),
		`expected a fail-closed violation for sku-EVIL, got: ${JSON.stringify(violations)}`,
	);
});

test('H2: a mandate with only an empty-acceptable_items requirement rejects every cart item', () => {
	// Mirrors the PoC: a mandate that allows only sku-a and sku-b, presented with every
	// acceptable_items disclosure withheld, must not let an unrelated sku-EVIL through.
	const cart = [lineItem('sku-EVIL', 1)];
	const reqs = [requirement('r1', [], 5)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.notDeepEqual(violations, []);
});

// M1: line-item quantities must be validated as integers >= 1 (and item.id as a non-empty
// string) before aggregation. Negative/zero quantities must not be allowed to net out a positive
// quantity for the same SKU, and non-numeric quantities must not be allowed to produce NaN
// arithmetic that silently resolves to "no violations".

test('M1: a negative-quantity line item cannot cancel out a disallowed SKU', () => {
	// sku-EVIL x5 plus sku-EVIL x-5 nets to 0 under naive summation, which used to be skipped
	// entirely (no violation) even though sku-EVIL is not allowed at all.
	const cart = [lineItem('sku-EVIL', 5), lineItem('sku-EVIL', -5)];
	const reqs = [requirement('r1', ['sku-a', 'sku-b'], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.notDeepEqual(violations, []);
});

test('M1: a negative-quantity line item cannot be used to sneak an over-quantity SKU past a requirement', () => {
	// sku-a x10 plus sku-a x-9 nets to 1 under naive summation, which used to satisfy a
	// quantity-1 requirement even though the cart actually contains far more than allowed.
	const cart = [lineItem('a', 10), lineItem('a', -9)];
	const reqs = [requirement('r1', ['a'], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.notDeepEqual(violations, []);
});

test('M1: a zero-quantity line item is rejected rather than silently skipped', () => {
	const cart = [lineItem('a', 0)];
	const reqs = [requirement('r1', ['a'], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.notDeepEqual(violations, []);
});

test('M1: a non-integer quantity is rejected even when ample capacity would otherwise absorb it silently', () => {
	// Capacity (5) comfortably covers 1.5 units with no leftover, so this can only fail via
	// explicit quantity validation - not as a side effect of leftover-capacity arithmetic.
	const cart = [lineItem('a', 1.5)];
	const reqs = [requirement('r1', ['a'], 5)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.notDeepEqual(violations, []);
});

test('M1 (TS-specific): a non-numeric quantity string must not produce NaN arithmetic that resolves to no violations', () => {
	const cart = [{ id: 'li-1', item: item('a'), quantity: '50x', totals: [] }];
	const reqs = [requirement('r1', ['a'], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.notDeepEqual(violations, []);
});

test('M1: a line item with an empty item.id is rejected', () => {
	const cart = [{ id: 'li-1', item: item(''), quantity: 1, totals: [] }];
	const reqs = [requirement('r1', ['a'], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.notDeepEqual(violations, []);
});
