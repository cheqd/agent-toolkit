# SPDX-License-Identifier: Apache-2.0
import asyncio

from cheqd_agent_identity.replay.file_nonce_cache import FileNonceCacheProvider


async def test_consume_returns_true_the_first_time_and_false_on_replay(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    assert await cache.consume("n1", 60, "did:example:a") is True
    assert await cache.consume("n1", 60, "did:example:a") is False


async def test_the_same_nonce_for_a_different_did_is_independent(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    assert await cache.consume("n1", 60, "did:example:a") is True
    assert await cache.consume("n1", 60, "did:example:b") is True


async def test_survives_a_process_restart_a_fresh_instance_over_the_same_directory_still_blocks_replay(
    tmp_path,
):
    first = FileNonceCacheProvider(directory=tmp_path)
    assert await first.consume("n1", 60, "did:example:a") is True
    second = FileNonceCacheProvider(directory=tmp_path)  # simulates a restart
    assert await second.consume("n1", 60, "did:example:a") is False


async def test_an_expired_nonce_can_be_reclaimed(tmp_path):
    clock = {"value": 0.0}
    cache = FileNonceCacheProvider(directory=tmp_path, now=lambda: clock["value"])
    assert await cache.consume("n1", 1, "did:example:a") is True  # expires at t=1000
    clock["value"] = 2000
    assert await cache.consume("n1", 1, "did:example:a") is True


async def test_an_unexpired_nonce_cannot_be_reclaimed_even_after_cleanup_runs(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    assert await cache.consume("n1", 60, "did:example:a") is True
    await cache.cleanup()
    assert await cache.consume("n1", 60, "did:example:a") is False


async def test_cleanup_deletes_expired_entries_but_not_live_ones(tmp_path):
    clock = {"value": 0.0}
    cache = FileNonceCacheProvider(directory=tmp_path, now=lambda: clock["value"])
    await cache.consume("expired", 1, "did:example:a")
    await cache.consume("alive", 1000, "did:example:a")
    clock["value"] = 2000
    await cache.cleanup()
    remaining = list(tmp_path.glob("*.json"))
    assert len(remaining) == 1
    # the expired one is gone, so consuming it again at the same (expired) moment succeeds
    assert await cache.consume("expired", 1, "did:example:a") is True


async def test_has_reports_true_after_consume_false_before(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    assert await cache.has("n1", "did:example:a") is False
    await cache.consume("n1", 60, "did:example:a")
    assert await cache.has("n1", "did:example:a") is True


async def test_add_unconditionally_writes_for_the_has_then_add_fallback_path(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    await cache.add("n1", 60, "did:example:a")
    assert await cache.has("n1", "did:example:a") is True


async def test_a_malformed_record_file_is_treated_as_still_blocking_not_as_absent(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    # Force the directory to exist, then plant a corrupt record at the exact path consume()
    # would use, bypassing the module's own writer.
    await cache.consume("seed", 60, "did:example:a")  # ensures _ensure_directory() has run
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    files[0].write_text("not json")
    assert await cache.has("seed", "did:example:a") is True  # still blocks
    assert await cache.consume("seed", 60, "did:example:a") is False  # still blocks


async def test_cleanup_does_not_delete_a_malformed_record(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    await cache.consume("seed", 60, "did:example:a")
    files = list(tmp_path.glob("*.json"))
    files[0].write_text("not json")
    await cache.cleanup()
    remaining = list(tmp_path.glob("*.json"))
    assert len(remaining) == 1  # still there


async def test_concurrent_consume_calls_for_the_same_nonce_exactly_one_succeeds(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    results = await asyncio.gather(*(cache.consume("n1", 60, "did:example:a") for _ in range(20)))
    assert sum(1 for r in results if r) == 1


async def test_destroy_resolves_without_raising(tmp_path):
    cache = FileNonceCacheProvider(directory=tmp_path)
    await cache.destroy()
