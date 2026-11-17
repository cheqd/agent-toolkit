// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileNonceCacheProvider } from '../dist/index.js';

async function withTempDir(fn) {
	const dir = await mkdtemp(join(tmpdir(), 'file-nonce-cache-'));
	try {
		await fn(dir);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}

test('consume() returns true the first time and false on replay', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		assert.equal(await cache.consume('n1', 60, 'did:example:a'), true);
		assert.equal(await cache.consume('n1', 60, 'did:example:a'), false);
	}));

test('the same nonce for a different DID is independent', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		assert.equal(await cache.consume('n1', 60, 'did:example:a'), true);
		assert.equal(await cache.consume('n1', 60, 'did:example:b'), true);
	}));

test('survives a process restart: a fresh instance over the same directory still blocks replay', () =>
	withTempDir(async (dir) => {
		const first = new FileNonceCacheProvider({ directory: dir });
		assert.equal(await first.consume('n1', 60, 'did:example:a'), true);
		const second = new FileNonceCacheProvider({ directory: dir }); // simulates a restart
		assert.equal(await second.consume('n1', 60, 'did:example:a'), false);
	}));

test('an expired nonce can be reclaimed', () =>
	withTempDir(async (dir) => {
		let clock = 0;
		const cache = new FileNonceCacheProvider({ directory: dir, now: () => clock });
		assert.equal(await cache.consume('n1', 1, 'did:example:a'), true); // expires at t=1000
		clock = 2000;
		assert.equal(await cache.consume('n1', 1, 'did:example:a'), true);
	}));

test('an unexpired nonce cannot be reclaimed even after cleanup() runs', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		assert.equal(await cache.consume('n1', 60, 'did:example:a'), true);
		await cache.cleanup();
		assert.equal(await cache.consume('n1', 60, 'did:example:a'), false);
	}));

test('cleanup() deletes expired entries but not live ones', () =>
	withTempDir(async (dir) => {
		let clock = 0;
		const cache = new FileNonceCacheProvider({ directory: dir, now: () => clock });
		await cache.consume('expired', 1, 'did:example:a');
		await cache.consume('alive', 1000, 'did:example:a');
		clock = 2000;
		await cache.cleanup();
		const remaining = (await readdir(dir)).filter((n) => n.endsWith('.json'));
		assert.equal(remaining.length, 1);
		// the expired one is gone, so consuming it again at the same (expired) moment succeeds
		assert.equal(await cache.consume('expired', 1, 'did:example:a'), true);
	}));

test('has() reports true after consume(), false before', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		assert.equal(await cache.has('n1', 'did:example:a'), false);
		await cache.consume('n1', 60, 'did:example:a');
		assert.equal(await cache.has('n1', 'did:example:a'), true);
	}));

test('add() unconditionally writes, for the has()-then-add() fallback path', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		await cache.add('n1', 60, 'did:example:a');
		assert.equal(await cache.has('n1', 'did:example:a'), true);
	}));

test('a malformed record file is treated as still-blocking, not as absent (fail-closed)', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		// Force the directory to exist, then plant a corrupt record at the exact path consume()
		// would use, bypassing the module's own writer.
		await cache.consume('seed', 60, 'did:example:a'); // ensures ensureDirectory() has run
		const files = (await readdir(dir)).filter((n) => n.endsWith('.json'));
		assert.equal(files.length, 1);
		await writeFile(join(dir, files[0]), 'not json', 'utf8');
		assert.equal(await cache.has('seed', 'did:example:a'), true); // still blocks
		assert.equal(await cache.consume('seed', 60, 'did:example:a'), false); // still blocks
	}));

test('cleanup() does not delete a malformed record', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		await cache.consume('seed', 60, 'did:example:a');
		const files = (await readdir(dir)).filter((n) => n.endsWith('.json'));
		await writeFile(join(dir, files[0]), 'not json', 'utf8');
		await cache.cleanup();
		const remaining = (await readdir(dir)).filter((n) => n.endsWith('.json'));
		assert.equal(remaining.length, 1); // still there
	}));

test('concurrent consume() calls for the same nonce: exactly one succeeds', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		const results = await Promise.all(
			Array.from({ length: 20 }, () => cache.consume('n1', 60, 'did:example:a')),
		);
		assert.equal(results.filter(Boolean).length, 1);
	}));

// Regression: reclaiming an expired record used to be rm(path) then open(path, 'wx') - not
// atomic as a pair. One caller's rm() could delete a DIFFERENT caller's freshly-written, valid,
// non-expired record just after that caller won its own create, clearing the way for the first
// caller's own open('wx') to also succeed. Multiple concurrent reclaims of the SAME expired
// nonce could then all return true - a genuine replay accepted, not merely an occasional false
// rejection as the module's own doc comment used to (wrongly) promise. This is a genuinely
// timing-dependent race, not a deterministic one: empirically (see the fix's PR description),
// 8 concurrent callers reproduces it in roughly 2-7 of every 50 rounds against the old code -
// HIGHER concurrency (e.g. 20) reproduces it less reliably, not more, likely because it pushes
// past libuv's default thread-pool size (4) and changes how the queued fs operations interleave.
// 50 rounds of 8 concurrent calls is the empirically-confirmed reproduction; do not "simplify"
// this to fewer/bigger rounds without re-confirming against the old code first.
test('concurrent reclaims of the SAME expired nonce: never more than one succeeds, across many rounds', () =>
	withTempDir(async (dir) => {
		let clock = 0;
		const cache = new FileNonceCacheProvider({ directory: dir, now: () => clock });
		for (let round = 0; round < 50; round++) {
			assert.equal(await cache.consume(`n-round-${round}`, 1, 'did:example:a'), true); // expires at clock+1000
			clock += 2000; // now expired
			const results = await Promise.all(
				Array.from({ length: 8 }, () => cache.consume(`n-round-${round}`, 60, 'did:example:a')),
			);
			assert.equal(
				results.filter(Boolean).length,
				1,
				`round ${round}: exactly one concurrent reclaim of the same expired nonce must succeed, got ${results.filter(Boolean).length}`,
			);
		}
	}));

// Regression: the per-key `queues` map (added by the reclaim-race fix above) used to grow
// without bound - every distinct (agentDid, nonce) key added an entry that was never removed,
// even after that key's consume() call had fully completed and nothing was waiting on it. An
// attacker sending distinct nonces could grow this process-lifetime map arbitrarily. Asserts
// directly on the map (a plain TS `private` field, not a real runtime-private `#` field, so it
// is readable from a compiled-JS test) since there is no public API that reports its size.
test("consume()'s per-key queue entry is pruned once its chain settles, not retained forever", () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		for (let i = 0; i < 2000; i++) {
			await cache.consume(`n-${i}`, 60, 'did:example:a');
		}
		assert.equal(
			cache.queues.size,
			0,
			`expected the queues map to be pruned back to empty, got ${cache.queues.size} entries`,
		);
	}));

test('a burst of concurrent distinct-key consume() calls still prunes the queues map down to empty once all settle', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		await Promise.all(Array.from({ length: 500 }, (_, i) => cache.consume(`n-${i}`, 60, 'did:example:a')));
		assert.equal(
			cache.queues.size,
			0,
			`expected the queues map to be pruned back to empty, got ${cache.queues.size} entries`,
		);
	}));

// Regression: cleanup() used to read a record and decide to delete it with no serialization
// against a concurrent consume() reclaiming that same (now-expired) nonce. If consume() wins the
// race and writes a fresh, live record between cleanup()'s read and its rm(), cleanup() deletes
// that fresh record - the nonce then looks unconsumed again well within its new TTL. This is a
// genuinely timing-dependent race (not deterministic every round), so it is run over many rounds,
// matching the style of the existing reclaim-race regression test above.
test('cleanup() racing a concurrent reclaim of the same expired nonce never deletes the fresh record', () =>
	withTempDir(async (dir) => {
		let clock = 0;
		const cache = new FileNonceCacheProvider({ directory: dir, now: () => clock });
		let reclaimsObserved = 0;
		for (let round = 0; round < 200; round++) {
			const nonce = `n-round-${round}`;
			assert.equal(await cache.consume(nonce, 1, 'did:example:a'), true); // expires at clock+1000
			clock += 2000; // now expired
			// Several concurrent cleanup() calls plus the reclaim: more fs-operation interleaving
			// opportunities than a single cleanup() vs. a single consume(), which widens the window
			// for cleanup()'s unserialized read-then-rm to land between the reclaim's rename and its
			// fresh create.
			const [, , , reclaimed] = await Promise.all([
				cache.cleanup(),
				cache.cleanup(),
				cache.cleanup(),
				cache.consume(nonce, 60, 'did:example:a'),
			]);
			// A concurrent cleanup() can (pre-fix) also make the reclaim itself spuriously fail -
			// e.g. by rm()ing the record out from under the reclaim's own rename() - a related
			// symptom of the same missing-serialization bug but not the one this test targets. Only
			// when OUR reclaim actually won do we check the specific invariant from the finding: a
			// reclaim that just won must not have its brand-new, still-live record deleted by one of
			// the racing cleanup() calls.
			if (reclaimed) {
				reclaimsObserved++;
				assert.equal(
					await cache.has(nonce, 'did:example:a'),
					true,
					`round ${round}: cleanup() must not have deleted the freshly-reclaimed, still-live record`,
				);
			}
		}
		assert.ok(
			reclaimsObserved > 0,
			"no round's reclaim won outright - the test didn't exercise the scenario it targets",
		);
	}));

test('destroy() resolves without throwing', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		await cache.destroy();
	}));
