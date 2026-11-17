/**
 * Persistent, per-mandate consumption tracking (WS5 decision 4/E). A single A2A proof's replay
 * window (60s, `@cheqd/agent-identity`'s `FileNonceCacheProvider`) is the wrong lifetime for an
 * AP2 Open Mandate: the mandate itself can be presented across many A2A calls over its own much
 * longer validity window, so "has this mandate already authorised a payment" and "how much has
 * it spent so far" need their own store, not a reuse of the A2A proof nonce cache.
 *
 * Two operations, with two different atomicity guarantees:
 * - `consumeOnce` (non-recurring mandates): exclusive-create (`fs.open(path, 'wx')`), the SAME
 *   atomic test-and-set `FileNonceCacheProvider` uses - safe across concurrent processes on one
 *   filesystem.
 * - `recordUse` (recurring/budget-constrained mandates, via `MandateContext`): a read-modify-
 *   write guarded by an in-process queue per mandate id. This is correct for concurrent callers
 *   WITHIN one process; it is NOT a cross-process atomic increment. A genuinely distributed
 *   deployment needs `recordUse` backed by a real transactional store (a database row with a
 *   compare-and-swap or a dedicated counter service), not this file-based implementation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createHash } from 'node:crypto';
import { mkdir, open, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { MandateContext } from './types.js';

export interface MandateConsumptionStoreOptions {
	readonly directory: string;
	/** Epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

export interface MandateConsumptionStore {
	/** Atomically consumes a one-time-use mandate. Returns `false` if already consumed. */
	consumeOnce(mandateId: string): Promise<boolean>;
	/**
	 * Records one use of amount `amountMinorUnits` against `mandateId`, returning the updated
	 * context. Composing this with an earlier `getContext()` call and an external constraint
	 * check (read context, check it yourself, then call this) is NOT safe: two concurrent
	 * callers can both read the same context before either records, so both can pass a budget
	 * check that only one of them should have (found by review - two concurrent $90 payments
	 * against a $100 budget both reading `total_amount: 0` both pass, both record, spend ends at
	 * $180). Use {@link MandateConsumptionStore.checkAndRecordUse} for anything that needs the
	 * check and the record to be atomic together; keep this for cases with no check to race.
	 */
	recordUse(mandateId: string, amountMinorUnits: number): Promise<MandateContext>;
	/** Reads the current context without recording a use. Absent mandate -> zeroed context. */
	getContext(mandateId: string): Promise<MandateContext>;
	/**
	 * Atomically checks `check(context)` against the mandate's current context and, only if it
	 * returns no violations, records the use and returns the updated context - both under the
	 * same per-mandate-id lock `recordUse` uses, so no other `recordUse`/`checkAndRecordUse` call
	 * for the same mandate can run between the check and the record. This is the race-free
	 * replacement for a `getContext()` + external check + `recordUse()` composition.
	 */
	checkAndRecordUse(
		mandateId: string,
		amountMinorUnits: number,
		check: (context: MandateContext) => readonly string[],
	): Promise<
		| { readonly ok: true; readonly context: MandateContext }
		| { readonly ok: false; readonly violations: readonly string[] }
	>;
}

function isEexist(error: unknown): boolean {
	return typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST';
}
function isEnoent(error: unknown): boolean {
	return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

/**
 * `amountMinorUnits` must be a finite, non-negative integer. Rejects `NaN` (which
 * `JSON.stringify` silently turns into `null`, corrupting the stored total on readback - see the
 * `readContext` corruption guard below), `Infinity`, non-integers, and negative amounts (which
 * would act as a budget refund rather than a use).
 */
function assertValidAmount(amountMinorUnits: number): void {
	if (!Number.isInteger(amountMinorUnits) || amountMinorUnits < 0) {
		throw new RangeError(
			`amountMinorUnits must be a finite, non-negative integer (received ${String(amountMinorUnits)})`,
		);
	}
}

/**
 * Validates a value read back from a persisted context as a non-negative integer, failing
 * closed (throwing) rather than silently coercing corrupt data to `0`. A missing field (`undefined`)
 * is treated as a fresh/absent value and defaults to `0` - that is not corruption, just a mandate
 * with no prior recorded field. Anything else that is present but not a valid non-negative
 * integer (including `null`, the JSON encoding of a `NaN` written by a pre-validation bug, or a
 * negative number) is corrupt and must not be silently reset, since doing so erases budget
 * history instead of refusing to proceed.
 */
function readStoredNonNegativeInt(value: unknown, field: string): number {
	if (value === undefined) return 0;
	if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
		throw new Error(
			`Corrupt mandate consumption record: ${field} is not a valid non-negative integer (stored value: ${JSON.stringify(value)})`,
		);
	}
	return value;
}

export function createMandateConsumptionStore(
	options: MandateConsumptionStoreOptions,
): MandateConsumptionStore {
	const now = options.now ?? Date.now;
	let ready: Promise<void> | undefined;
	const ensureDirectory = async (): Promise<void> => {
		ready ??= mkdir(options.directory, { recursive: true }).then(() => undefined);
		await ready;
	};
	const consumedPath = (mandateId: string) =>
		join(
			options.directory,
			`${createHash('sha256').update(`consumed\u0000${mandateId}`).digest('hex')}.json`,
		);
	const contextPath = (mandateId: string) =>
		join(options.directory, `${createHash('sha256').update(`context\u0000${mandateId}`).digest('hex')}.json`);

	// Per-mandate-id in-process serialization for recordUse's read-modify-write. Entries are
	// pruned once their chain settles with nothing else queued for that key (see below), so this
	// map does not grow without bound across the lifetime of a long-running process.
	const queues = new Map<string, Promise<unknown>>();
	function enqueue<T>(key: string, task: () => Promise<T>): Promise<T> {
		const prior = queues.get(key) ?? Promise.resolve();
		const next = prior.then(task, task);
		// Never-rejecting tail used both as the next caller's `prior` and as the identity we check
		// before pruning. Swallowing the error here (a later `.catch` further down) - not on
		// `next`, which still propagates to this call's own caller - is what lets subsequent calls
		// for the same key keep running after an earlier one throws.
		const settled = next.then(
			() => undefined,
			() => undefined,
		);
		queues.set(key, settled);
		void settled.then(() => {
			// Only prune if nobody enqueued a newer task for this key while we were running: a
			// newer `enqueue` call would have synchronously overwritten `queues.get(key)` with its
			// own `settled` promise before this callback runs. Checking identity, not just
			// presence, is what avoids a window where this key's serialization is lost while
			// another caller is still mid-flight on it (the #34 race this store exists to avoid).
			if (queues.get(key) === settled) {
				queues.delete(key);
			}
		});
		return next;
	}

	async function readContext(mandateId: string): Promise<MandateContext> {
		try {
			const raw = await readFile(contextPath(mandateId), 'utf8');
			const parsed = JSON.parse(raw) as Partial<MandateContext>;
			return {
				total_amount: readStoredNonNegativeInt(parsed.total_amount, 'total_amount'),
				total_uses: readStoredNonNegativeInt(parsed.total_uses, 'total_uses'),
				...(typeof parsed.last_used_date === 'number' ? { last_used_date: parsed.last_used_date } : {}),
			};
		} catch (error) {
			if (isEnoent(error)) return { total_amount: 0, total_uses: 0 };
			throw error;
		}
	}

	const store: MandateConsumptionStore = {
		async consumeOnce(mandateId) {
			await ensureDirectory();
			try {
				const handle = await open(consumedPath(mandateId), 'wx');
				try {
					await handle.writeFile(JSON.stringify({ consumedAt: now() }));
				} finally {
					await handle.close();
				}
				return true;
			} catch (error) {
				if (isEexist(error)) return false;
				throw error;
			}
		},

		async recordUse(mandateId, amountMinorUnits) {
			assertValidAmount(amountMinorUnits);
			await ensureDirectory();
			return enqueue(mandateId, async () => {
				const current = await readContext(mandateId);
				const updated: MandateContext = {
					total_amount: current.total_amount + amountMinorUnits,
					total_uses: current.total_uses + 1,
					last_used_date: now(),
				};
				const handle = await open(contextPath(mandateId), 'w');
				try {
					await handle.writeFile(JSON.stringify(updated));
				} finally {
					await handle.close();
				}
				return updated;
			});
		},

		async getContext(mandateId) {
			await ensureDirectory();
			return readContext(mandateId);
		},

		async checkAndRecordUse(mandateId, amountMinorUnits, check) {
			assertValidAmount(amountMinorUnits);
			await ensureDirectory();
			return enqueue(mandateId, async () => {
				const current = await readContext(mandateId);
				const violations = check(current);
				if (violations.length > 0) return { ok: false as const, violations };
				const updated: MandateContext = {
					total_amount: current.total_amount + amountMinorUnits,
					total_uses: current.total_uses + 1,
					last_used_date: now(),
				};
				const handle = await open(contextPath(mandateId), 'w');
				try {
					await handle.writeFile(JSON.stringify(updated));
				} finally {
					await handle.close();
				}
				return { ok: true as const, context: updated };
			});
		},
	};

	// Test-only diagnostic, not part of the public `MandateConsumptionStore` contract: lets the
	// regression test for the unbounded-queue-map fix (L3) observe that `queues` is pruned back
	// down rather than growing forever, without the test needing a handle on the closure-private
	// `queues` map itself. Non-enumerable so it does not show up in normal iteration/serialization
	// of the returned store.
	Object.defineProperty(store, '__queueSizeForTesting', {
		value: () => queues.size,
		enumerable: false,
	});

	return store;
}
