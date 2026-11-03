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
 * The one case this cannot resolve atomically: a caller claims an EXPIRED file left by a previous
 * claim. Reading the expiry and then deleting-and-recreating is two steps, so two callers can both
 * observe "expired" and both attempt to reclaim it; one `wx` wins, the other correctly sees
 * `EEXIST` and is told `false` for that attempt even though the slot is free again. This fails
 * CLOSED (a legitimate nonce reuse after expiry is occasionally rejected, never a replay
 * incorrectly accepted), which is the safe direction to be wrong in for a replay cache.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createHash } from 'node:crypto';
import { mkdir, open, readFile, readdir, rm } from 'node:fs/promises';
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

	constructor(options: FileNonceCacheOptions) {
		super();
		this.directory = options.directory;
		this.now = options.now ?? Date.now;
	}

	private async ensureDirectory(): Promise<void> {
		this.ready ??= mkdir(this.directory, { recursive: true }).then(() => undefined);
		await this.ready;
	}

	private pathFor(nonce: string, agentDid?: string): string {
		// Hash rather than use the nonce/DID directly as a filename: both are attacker-influenced
		// (a proof's own nonce, and the DID it claims), and neither is safe as a raw path segment.
		const key = createHash('sha256').update(`${agentDid ?? ''}\u0000${nonce}`).digest('hex');
		return join(this.directory, `${key}.json`);
	}

	async consume(nonce: string, ttlSeconds: number, agentDid?: string): Promise<boolean> {
		await this.ensureDirectory();
		const path = this.pathFor(nonce, agentDid);
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
		try {
			await rm(path, { force: true });
			const handle = await open(path, 'wx');
			try {
				await handle.writeFile(JSON.stringify(record));
			} finally {
				await handle.close();
			}
			return true;
		} catch (error) {
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
	 */
	async cleanup(): Promise<void> {
		await this.ensureDirectory();
		const entries = await readdir(this.directory);
		await Promise.all(
			entries
				.filter((name) => name.endsWith('.json'))
				.map(async (name) => {
					const path = join(this.directory, name);
					const record = await this.readRecord(path);
					if (record !== undefined && record.expiresAt <= this.now()) await rm(path, { force: true });
				}),
		);
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
