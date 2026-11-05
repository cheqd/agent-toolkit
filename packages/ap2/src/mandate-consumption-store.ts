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
	/** Records one use of amount `amountMinorUnits` against `mandateId`, returning the updated context. */
	recordUse(mandateId: string, amountMinorUnits: number): Promise<MandateContext>;
	/** Reads the current context without recording a use. Absent mandate -> zeroed context. */
	getContext(mandateId: string): Promise<MandateContext>;
}

function isEexist(error: unknown): boolean {
	return typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST';
}
function isEnoent(error: unknown): boolean {
	return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

export function createMandateConsumptionStore(options: MandateConsumptionStoreOptions): MandateConsumptionStore {
	const now = options.now ?? Date.now;
	let ready: Promise<void> | undefined;
	const ensureDirectory = async (): Promise<void> => {
		ready ??= mkdir(options.directory, { recursive: true }).then(() => undefined);
		await ready;
	};
	const consumedPath = (mandateId: string) => join(options.directory, `${createHash('sha256').update(`consumed\u0000${mandateId}`).digest('hex')}.json`);
	const contextPath = (mandateId: string) => join(options.directory, `${createHash('sha256').update(`context\u0000${mandateId}`).digest('hex')}.json`);

	// Per-mandate-id in-process serialization for recordUse's read-modify-write.
	const queues = new Map<string, Promise<unknown>>();
	function enqueue<T>(key: string, task: () => Promise<T>): Promise<T> {
		const prior = queues.get(key) ?? Promise.resolve();
		const next = prior.then(task, task);
		queues.set(
			key,
			next.catch(() => undefined),
		);
		return next;
	}

	async function readContext(mandateId: string): Promise<MandateContext> {
		try {
			const raw = await readFile(contextPath(mandateId), 'utf8');
			const parsed = JSON.parse(raw) as Partial<MandateContext>;
			return {
				total_amount: typeof parsed.total_amount === 'number' ? parsed.total_amount : 0,
				total_uses: typeof parsed.total_uses === 'number' ? parsed.total_uses : 0,
				...(typeof parsed.last_used_date === 'number' ? { last_used_date: parsed.last_used_date } : {}),
			};
		} catch (error) {
			if (isEnoent(error)) return { total_amount: 0, total_uses: 0 };
			throw error;
		}
	}

	return {
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
	};
}
