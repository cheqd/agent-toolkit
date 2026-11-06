// SPDX-License-Identifier: Apache-2.0
// Tests for evaluateLineItemsMaxFlow, including the "complex" (ambiguous-match) path that
// actually exercises the Dinic max-flow solver, not just the greedy degree-1 shortcut.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateLineItemsMaxFlow } from '../dist/index.js';

const item = (id, title = id) => ({ id, title });
const lineItem = (skuId, quantity) => ({ id: `li-${skuId}`, item: item(skuId), quantity, totals: [] });
const requirement = (id, acceptableSkus, quantity) => ({ id, acceptable_items: acceptableSkus.map((s) => item(s)), quantity });

test('simple wildcard requirement is satisfied', () => {
	const cart = [lineItem('a', 1)];
	const reqs = [requirement('r1', [], 1)];
	assert.deepEqual(evaluateLineItemsMaxFlow(cart, reqs), []);
});

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

test('a wildcard requirement needing more than the cart holds is not itself a violation', () => {
	// Same semantics as above: only leftover (unassignable) CART quantity is ever flagged. A
	// requirement asking for more than the cart contains, with every cart unit still placed
	// into that requirement's slot, has no leftover - so this passes, which is a genuinely
	// surprising property of the upstream algorithm (ported faithfully, not "fixed" here).
	const cart = [lineItem('a', 1)];
	const reqs = [requirement('r1', [], 2)];
	assert.deepEqual(evaluateLineItemsMaxFlow(cart, reqs), []);
});

test('a cart item left over after every requirement slot fills is a violation', () => {
	// Two units of "a", but the only requirement slot (qty 1) is wildcard-matched and fills
	// after one unit - the second unit has nowhere to go, which IS the leftover case this
	// algorithm actually checks for.
	const cart = [lineItem('a', 2)];
	const reqs = [requirement('r1', [], 1)];
	const violations = evaluateLineItemsMaxFlow(cart, reqs);
	assert.ok(violations.some((v) => v.includes('could not be assigned')));
});
