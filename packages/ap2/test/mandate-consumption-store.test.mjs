// SPDX-License-Identifier: Apache-2.0
// Tests for createMandateConsumptionStore: consumeOnce's exclusive-create atomicity, and
// recordUse's cumulative total_amount/total_uses tracking.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMandateConsumptionStore } from '../dist/index.js';

function store() {
	return createMandateConsumptionStore({ directory: mkdtempSync(join(tmpdir(), 'ap2-mandate-store-')) });
}

test('consumeOnce succeeds the first time and fails every time after', async () => {
	const s = store();
	assert.equal(await s.consumeOnce('mandate-1'), true);
	assert.equal(await s.consumeOnce('mandate-1'), false);
	assert.equal(await s.consumeOnce('mandate-1'), false);
});

test('consumeOnce is independent per mandate id', async () => {
	const s = store();
	assert.equal(await s.consumeOnce('a'), true);
	assert.equal(await s.consumeOnce('b'), true);
});

test('a mandate with no recorded use has a zeroed context', async () => {
	const s = store();
	assert.deepEqual(await s.getContext('never-used'), { total_amount: 0, total_uses: 0 });
});

test('recordUse accumulates total_amount and total_uses', async () => {
	const s = store();
	await s.recordUse('m1', 1000);
	const after2 = await s.recordUse('m1', 500);
	assert.equal(after2.total_amount, 1500);
	assert.equal(after2.total_uses, 2);
	assert.ok(typeof after2.last_used_date === 'number');
});

test('concurrent recordUse calls on the same mandate id do not lose updates', async () => {
	const s = store();
	await Promise.all(Array.from({ length: 20 }, () => s.recordUse('concurrent', 1)));
	const context = await s.getContext('concurrent');
	assert.equal(context.total_uses, 20);
	assert.equal(context.total_amount, 20);
});

// Regression: composing getContext() + an external constraint check + recordUse() has a real
// check-then-record race - two concurrent callers can both read the same stale context before
// either records, so both can pass a budget check only one of them should have. This is the
// exact scenario a reviewer found: two concurrent $90 payments against a $100 budget both
// reading total_amount: 0, both passing, both recording, ending at $180 spent.
const BUDGET_CENTS = 10000; // $100.00
const checkBudget = (context) => (context.total_amount + 9000 > BUDGET_CENTS ? ['over budget'] : []);

test('composing getContext + an external check + recordUse DOES let two concurrent payments both pass a budget only one should fit in (demonstrates the race this test suite now avoids via checkAndRecordUse)', async () => {
	const s = store();
	const attempt = async () => {
		const context = await s.getContext('racy');
		const violations = checkBudget(context);
		if (violations.length > 0) return { ok: false, violations };
		return { ok: true, context: await s.recordUse('racy', 9000) };
	};
	const [a, b] = await Promise.all([attempt(), attempt()]);
	const finalContext = await s.getContext('racy');
	// This assertion documents the race, not endorses it: both attempts can succeed even though
	// only one $90 payment fits in a $100 budget.
	assert.equal(a.ok && b.ok, true, 'both concurrent attempts passed the external check (the race)');
	assert.equal(finalContext.total_amount, 18000, 'both recorded, ending over budget - this is the bug checkAndRecordUse exists to avoid');
});

test('checkAndRecordUse closes the race: of two concurrent $90 payments against a $100 budget, exactly one succeeds', async () => {
	const s = store();
	const attempt = () => s.checkAndRecordUse('atomic', 9000, checkBudget);
	const [a, b] = await Promise.all([attempt(), attempt()]);
	const results = [a, b];
	const succeeded = results.filter((r) => r.ok);
	const failed = results.filter((r) => !r.ok);
	assert.equal(succeeded.length, 1, 'exactly one of the two concurrent payments must succeed');
	assert.equal(failed.length, 1, 'exactly one of the two concurrent payments must be rejected');
	assert.equal(failed[0].violations[0], 'over budget');
	const finalContext = await s.getContext('atomic');
	assert.equal(finalContext.total_amount, 9000, 'only the one successful payment was recorded - never both');
});
