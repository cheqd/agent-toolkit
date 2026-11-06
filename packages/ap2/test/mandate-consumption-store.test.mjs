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
