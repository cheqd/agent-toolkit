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
		const results = await Promise.all(Array.from({ length: 20 }, () => cache.consume('n1', 60, 'did:example:a')));
		assert.equal(results.filter(Boolean).length, 1);
	}));

test('destroy() resolves without throwing', () =>
	withTempDir(async (dir) => {
		const cache = new FileNonceCacheProvider({ directory: dir });
		await cache.destroy();
	}));
