// SPDX-License-Identifier: Apache-2.0
// Tests for createMandateConsumptionStore: consumeOnce's exclusive-create atomicity, and
// recordUse's cumulative total_amount/total_uses tracking.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMandateConsumptionStore } from '../dist/index.js';

function store() {
	return createMandateConsumptionStore({ directory: mkdtempSync(join(tmpdir(), 'ap2-mandate-store-')) });
}

// Mirrors the private `contextPath` hashing in mandate-consumption-store.ts, so tests can plant a
// pre-corrupted context file directly - simulating the result of a pre-fix NaN/negative record.
function contextPathFor(directory, mandateId) {
	const hash = createHash('sha256').update(`context\u0000${mandateId}`).digest('hex');
	return join(directory, `${hash}.json`);
}

// Flushes pending microtasks (a macrotask runs after all queued microtasks drain), so the
// settle -> prune chain in `enqueue` (mandate-consumption-store.ts) has had a chance to run.
function flushMicrotasks() {
	return new Promise((resolve) => setImmediate(resolve));
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
	await flushMicrotasks();
	assert.equal(
		s.__queueSizeForTesting(),
		0,
		'the queue entry for this mandate id must be pruned once 20 concurrent callers all settle',
	);
});

// Regression (M2): recordUse(id, NaN) used to write total_amount: null (JSON.stringify(NaN) ===
// 'null'), and readContext coerced any non-number - including null - back to 0 on the next read,
// silently resetting the spent budget to 0. Reproduced against the pre-fix code; the fix rejects
// a non-finite/non-integer amountMinorUnits outright instead of ever writing it.
test('recordUse rejects a NaN amount instead of silently resetting the stored total to 0', async () => {
	const s = store();
	await s.recordUse('nan-amount', 9000);
	await assert.rejects(() => s.recordUse('nan-amount', NaN));
	const context = await s.getContext('nan-amount');
	assert.equal(
		context.total_amount,
		9000,
		'a rejected NaN amount must not corrupt or reset the previously recorded total',
	);
	assert.equal(context.total_uses, 1);
});

// Regression (M2): a negative amount recorded after a positive one offsets it back down - e.g.
// +9000 then -9000 nets to 0, acting as an unintended budget refund. The fix rejects negative
// amounts outright.
test('recordUse rejects a negative amount instead of letting it refund the recorded total', async () => {
	const s = store();
	await s.recordUse('negative-amount', 9000);
	await assert.rejects(() => s.recordUse('negative-amount', -9000));
	const context = await s.getContext('negative-amount');
	assert.equal(
		context.total_amount,
		9000,
		'a negative amount must not refund (decrease) the previously recorded total',
	);
	assert.equal(context.total_uses, 1);
});

test('recordUse and checkAndRecordUse reject non-finite, non-integer, and negative amounts', async () => {
	const s = store();
	const noViolations = () => [];
	for (const invalid of [NaN, Infinity, -Infinity, -1, 1.5]) {
		await assert.rejects(() => s.recordUse('invalid-amounts', invalid), `recordUse must reject ${invalid}`);
		await assert.rejects(
			() => s.checkAndRecordUse('invalid-amounts', invalid, noViolations),
			`checkAndRecordUse must reject ${invalid}`,
		);
	}
	assert.deepEqual(
		await s.getContext('invalid-amounts'),
		{ total_amount: 0, total_uses: 0 },
		'none of the rejected calls may have recorded anything',
	);
});

// Regression (M2): a corrupt stored total_amount (e.g. the null a pre-fix NaN write left behind)
// must fail closed, not be silently coerced back to 0 - coercing to 0 erases budget history
// instead of refusing to proceed.
test('getContext and recordUse fail closed on a corrupt stored total instead of silently resetting it to 0', async () => {
	const directory = mkdtempSync(join(tmpdir(), 'ap2-mandate-store-'));
	const s = createMandateConsumptionStore({ directory });
	await s.recordUse('corrupt', 1); // establishes the directory and a baseline context file
	await writeFile(
		contextPathFor(directory, 'corrupt'),
		JSON.stringify({ total_amount: null, total_uses: 1 }),
	);
	await assert.rejects(
		() => s.getContext('corrupt'),
		'a corrupt total_amount must reject, not resolve with a reset-to-0 context',
	);
	await assert.rejects(
		() => s.recordUse('corrupt', 1),
		'recordUse must not proceed (and must not overwrite the corrupt record) on an unreadable prior total',
	);
});

// Regression (L3): the per-mandate-id queue map used to retain one entry per mandate id forever
// (the same unbounded-growth bug class fixed for the nonce-cache's queue map in this batch). The
// fix prunes an entry once its chain settles with nothing else queued for that key.
test('the per-mandate-id queue map does not grow without bound as distinct mandate ids are used', async () => {
	const s = store();
	for (let i = 0; i < 50; i++) {
		await s.recordUse(`mandate-${i}`, 1);
		await flushMicrotasks();
	}
	assert.equal(
		s.__queueSizeForTesting(),
		0,
		'every settled mandate id must be pruned from the queue map, not retained forever',
	);
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
	assert.equal(
		finalContext.total_amount,
		18000,
		'both recorded, ending over budget - this is the bug checkAndRecordUse exists to avoid',
	);
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
