/**
 * A persistent (file-backed) replay cache: `@kya-os/mcp`'s `NonceCacheProvider`, implemented over
 * one small file per `(agentDid, nonce)` pair instead of memory, so a consumed nonce survives a
 * process restart. `@kya-os/mcp`'s own `InMemoryNonceCache`/`MemoryNonceCacheProvider` are
 * explicitly single-process/dev-only (their own doc comments say so); this is the WS1 deliverable
 * that needed something that isn't.
 *
 * Atomicity: `consume()` uses `fs.open(path, 'wx')` - exclusive create, which fails with `EEXIST`
 * if the file already exists. That failure IS the atomic test-and-set: the filesystem, not this
 * module, decides which of two concurrent callers wins. This gives race-free behaviour for
 * concurrent callers on ONE filesystem (one machine, or a shared network filesystem with POSIX
 * `O_EXCL` semantics) - it is not a distributed lock across independent storage backends. For a
 * genuinely distributed deployment (multiple machines, no shared filesystem), implement
 * `NonceCacheProvider` directly over whatever shared store you already run (a KV store, a
 * database) instead of reaching for this.
 *
 * Reclaiming an EXPIRED file left by a previous claim is the one case needing care: reading the
 * expiry and then replacing the file is two steps, so two callers can both observe "expired" at
 * the same moment. `consume()` therefore serializes its ENTIRE body - including the initial
 * exclusive-create attempt - through an in-process queue keyed by `(agentDid, nonce)` (the same
 * `enqueue`-per-key pattern `@cheqd/agent-identity-ap2`'s `mandate-consumption-store.ts` uses for
 * `recordUse`): at most one `consume()` call for a given key runs its body at a time WITHIN this
 * process. That closes the race for every caller sharing this `FileNonceCacheProvider` instance,
 * which is what the two concurrency scenarios that matter in practice - multiple in-flight
 * requests in one server process, and this module's own test suite - actually exercise.
 *
 * Found by review: an earlier version used a plain `rm()` then `open(path, 'wx')` to reclaim an
 * expired file, with no serialization at all. Caller A's `rm()` could run, caller A's
 * `open('wx')` could succeed and write a FRESH, valid, non-expired record, and only THEN caller
 * B's own (concurrently in-flight) `rm()` for the same path could run and delete that fresh
 * record A just wrote - clearing the way for B's own `open('wx')` to also succeed. A follow-up
 * attempt replaced the `rm()` with a `rename()`-based atomic claim step (relying on `rename()`'s
 * single-winner semantics on one source path) but WITHOUT the per-key queue below; that still
 * raced, just one step later: caller D could read the file, observe "expired" via `isReclaimable`,
 * and only THEN - after caller A had already renamed the old file away and created its own fresh,
 * live record at the same path - have its own `rename()` succeed, because `rename()` only checks
 * that a source path exists, not that the thing at it is still the stale snapshot D examined. D's
 * rename would silently steal A's brand-new live record out from under it. Both bugs are read-
 * then-act races; serializing the whole operation per key removes the "then-act" step's exposure
 * to any other caller entirely, rather than trying to make each individual filesystem call atomic
 * against every other individual call. The `rename()`-based reclaim is kept as defense in depth
 * for genuinely separate OS processes sharing this directory, which the in-process queue cannot
 * help, but it is NOT a complete fix for that case: each individual `rename()` call is atomic (so
 * two processes can't both rename away the SAME still-stale file), but that is weaker than full
 * safety - the exact "caller D" scenario above (read "expired", then rename AFTER a fresh record
 * has already been written at that path) can still happen across processes, because `rename()`
 * only checks that its source path exists, not that it is still the stale snapshot that process
 * examined. Cross-process reclaim is therefore still racy in principle; the queue below only
 * makes it race-free for callers sharing this one process (which, per the paragraph above, is the
 * scenario this module is actually meant to cover).
 *
 * `cleanup()` goes through the same per-key queue as `consume()`, for the same reason: without
 * it, `cleanup()` could read a record, see it as expired, and then `rm()` it AFTER a concurrent
 * `consume()` had already reclaimed that same slot and written a fresh, live record there -
 * deleting the fresh record and making the nonce look unconsumed again, well within its new TTL.
 * Serializing each file's cleanup check-and-delete through the same queue entry a reclaim of that
 * file would use closes this the same way: by removing the "then-act" step's exposure, not by
 * trying to make the individual read and the individual `rm()` atomic as a pair.
 *
 * The `queues` map itself is pruned as each key's chain settles (see `enqueue()`): nonces are
 * unique by construction, so every distinct `(agentDid, nonce)` that has ever been consumed would
 * otherwise add an entry that is never removed - a caller submitting enough distinct nonces could
 * grow this process-lifetime map without bound.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { NonceCacheProvider } from '@kya-os/mcp/providers';

export interface FileNonceCacheOptions {
	/** Directory the cache's files live in. Created if it does not exist. */
	readonly directory: string;
	/** Injectable clock returning epoch milliseconds (deterministic tests; default `Date.now`). */
	readonly now?: () => number;
}

interface Record_ {
	readonly expiresAt: number;
}

export class FileNonceCacheProvider extends NonceCacheProvider {
	private readonly directory: string;
	private readonly now: () => number;
	private ready: Promise<void> | undefined;
	// Per-(agentDid, nonce) in-process serialization for consume()'s read-reclaim-create sequence
	// and for cleanup()'s per-record check-and-delete - see the class doc comment for why the
	// whole body, not just the filesystem calls, must be serialized. Pruned as each key's chain
	// settles (see enqueue()) so this does not grow without bound.
	private readonly queues = new Map<string, Promise<unknown>>();

	constructor(options: FileNonceCacheOptions) {
		super();
		this.directory = options.directory;
		this.now = options.now ?? Date.now;
	}

	private enqueue<T>(key: string, task: () => Promise<T>): Promise<T> {
		const prior = this.queues.get(key) ?? Promise.resolve();
		const next = prior.then(task, task);
		const settled = next.catch(() => undefined);
		this.queues.set(key, settled);
		// Prune the entry once our tail settles - but only if nobody chained a further task onto
		// this key in the meantime, i.e. the map still points at exactly OUR tail promise. If
		// another enqueue() call for this key came in while we were running, it already replaced
		// this entry with its own tail (read via this.queues.get(key) at ITS call time, before
		// this callback can run - queues.set() and queues.get() are both synchronous, so there is
		// no interleaving within a single call), and that other caller's chain is a closure over
		// `settled` directly, not a re-fetch from the map - so correctness of ordering never
		// depends on the map. This only prevents the map from growing without bound.
		settled.then(() => {
			if (this.queues.get(key) === settled) {
				this.queues.delete(key);
			}
		});
		return next;
	}

	private async ensureDirectory(): Promise<void> {
		this.ready ??= mkdir(this.directory, { recursive: true }).then(() => undefined);
		await this.ready;
	}

	private pathFor(nonce: string, agentDid?: string): string {
		// Hash rather than use the nonce/DID directly as a filename: both are attacker-influenced
		// (a proof's own nonce, and the DID it claims), and neither is safe as a raw path segment.
		const key = createHash('sha256')
			.update(`${agentDid ?? ''}\u0000${nonce}`)
			.digest('hex');
		return join(this.directory, `${key}.json`);
	}

	async consume(nonce: string, ttlSeconds: number, agentDid?: string): Promise<boolean> {
		await this.ensureDirectory();
		const path = this.pathFor(nonce, agentDid);
		return this.enqueue(path, () => this.consumeLocked(path, ttlSeconds));
	}

	private async consumeLocked(path: string, ttlSeconds: number): Promise<boolean> {
		const record: Record_ = { expiresAt: this.now() + ttlSeconds * 1000 };
		try {
			const handle = await open(path, 'wx');
			try {
				await handle.writeFile(JSON.stringify(record));
			} finally {
				await handle.close();
			}
			return true;
		} catch (error) {
			if (!isEexist(error)) throw error;
		}
		// The file exists. If it has expired, try once to reclaim it - see the class doc comment
		// for why this one retry is not itself atomic, and why that is the safe failure direction.
		// A record that exists but cannot be parsed is treated the same as "not expired" (blocks
		// reclaim): the file's existence alone proves some prior claim happened, and the fail-closed
		// direction for a replay cache is to assume it is still live when its expiry can't be read,
		// not to assume it is gone and let the slot be reused.
		if (!(await this.isReclaimable(path))) return false;
		// Claim the expired slot by moving it aside first - see the class doc comment for why
		// this, not a plain rm() then open('wx'), is the atomic step. Only the caller whose
		// rename succeeds proceeds to create the fresh record.
		const claimPath = `${path}.reclaim-${randomBytes(8).toString('hex')}`;
		try {
			await rename(path, claimPath);
		} catch (error) {
			if (isEnoent(error)) return false; // another caller already claimed (or cleared) this slot
			throw error;
		}
		await rm(claimPath, { force: true });
		try {
			const handle = await open(path, 'wx');
			try {
				await handle.writeFile(JSON.stringify(record));
			} finally {
				await handle.close();
			}
			return true;
		} catch (error) {
			// A third caller's brand-new (non-reclaim) consume() of this same nonce could have
			// won the path in between our rename and our open - its record is now the live one.
			if (isEexist(error)) return false;
			throw error;
		}
	}

	async has(nonce: string, agentDid?: string): Promise<boolean> {
		await this.ensureDirectory();
		return !(await this.isReclaimable(this.pathFor(nonce, agentDid)));
	}

	async add(nonce: string, ttlSeconds: number, agentDid?: string): Promise<void> {
		await this.ensureDirectory();
		const record: Record_ = { expiresAt: this.now() + ttlSeconds * 1000 };
		const handle = await open(this.pathFor(nonce, agentDid), 'w');
		try {
			await handle.writeFile(JSON.stringify(record));
		} finally {
			await handle.close();
		}
	}

	/**
	 * Deletes every entry PROVEN expired. Safe to call periodically to bound directory size. A
	 * record that cannot be parsed is left in place rather than deleted: deleting it would make
	 * the nonce look unconsumed again (ENOENT on the next `has`/`consume`), reopening a replay
	 * window to save a few bytes of disk - the wrong trade. It becomes permanent, harmless
	 * clutter instead; that failure mode was never meant to be reachable (every write is this
	 * module's own well-formed JSON), so it is not optimised for.
	 *
	 * Each file's check-and-delete is routed through the same per-path queue `consume()` uses -
	 * see the class doc comment - so a concurrent reclaim of that exact file can never land
	 * between this method reading the (expired) record and deleting it.
	 */
	async cleanup(): Promise<void> {
		await this.ensureDirectory();
		const entries = await readdir(this.directory);
		await Promise.all(
			entries
				.filter((name) => name.endsWith('.json'))
				.map((name) => {
					const path = join(this.directory, name);
					return this.enqueue(path, () => this.cleanupOne(path));
				}),
		);
	}

	private async cleanupOne(path: string): Promise<void> {
		const record = await this.readRecord(path);
		if (record !== undefined && record.expiresAt <= this.now()) await rm(path, { force: true });
	}

	/** No open handles are kept between calls, so there is nothing to release; provided to
	 * satisfy the NonceCacheProvider contract. */
	async destroy(): Promise<void> {
		// Intentionally a no-op: see the doc comment above.
	}

	/** `true` only when the record is provably absent or expired - the one case it is safe to
	 * overwrite. A record that exists but cannot be parsed is NOT reclaimable: see the class and
	 * `cleanup()` doc comments for why "cannot prove" must mean "still blocks", not "free". */
	private async isReclaimable(path: string): Promise<boolean> {
		const record = await this.readRecord(path);
		return record === undefined || record.expiresAt <= this.now();
	}

	/** `undefined` only when the file genuinely does not exist (ENOENT). A file that exists but
	 * fails to parse returns a record whose `expiresAt` is `Infinity` - present, never expired. */
	private async readRecord(path: string): Promise<Record_ | undefined> {
		let raw: string;
		try {
			raw = await readFile(path, 'utf8');
		} catch (error) {
			if (isEnoent(error)) return undefined;
			throw error;
		}
		try {
			const parsed = JSON.parse(raw);
			if (typeof parsed === 'object' && parsed !== null && typeof parsed.expiresAt === 'number') {
				return parsed as Record_;
			}
		} catch {
			// fall through to the "exists but unparseable" case below
		}
		return { expiresAt: Number.POSITIVE_INFINITY };
	}
}

function isEexist(error: unknown): boolean {
	return typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST';
}

function isEnoent(error: unknown): boolean {
	return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}
