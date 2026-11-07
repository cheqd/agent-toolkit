# SPDX-License-Identifier: Apache-2.0
# Tests for create_mandate_consumption_store: consume_once's exclusive-create atomicity, and
# record_use's cumulative total_amount/total_uses tracking.
import asyncio

from cheqd_agent_identity_ap2.mandate_consumption_store import create_mandate_consumption_store


async def test_consume_once_succeeds_the_first_time_and_fails_every_time_after(tmp_path):
    s = create_mandate_consumption_store(directory=tmp_path)
    assert await s.consume_once("mandate-1") is True
    assert await s.consume_once("mandate-1") is False
    assert await s.consume_once("mandate-1") is False


async def test_consume_once_is_independent_per_mandate_id(tmp_path):
    s = create_mandate_consumption_store(directory=tmp_path)
    assert await s.consume_once("a") is True
    assert await s.consume_once("b") is True


async def test_a_mandate_with_no_recorded_use_has_a_zeroed_context(tmp_path):
    s = create_mandate_consumption_store(directory=tmp_path)
    assert await s.get_context("never-used") == {"total_amount": 0, "total_uses": 0}


async def test_record_use_accumulates_total_amount_and_total_uses(tmp_path):
    s = create_mandate_consumption_store(directory=tmp_path)
    await s.record_use("m1", 1000)
    after2 = await s.record_use("m1", 500)
    assert after2["total_amount"] == 1500
    assert after2["total_uses"] == 2
    assert isinstance(after2["last_used_date"], (int, float))


async def test_concurrent_record_use_calls_on_the_same_mandate_id_do_not_lose_updates(tmp_path):
    s = create_mandate_consumption_store(directory=tmp_path)
    await asyncio.gather(*(s.record_use("concurrent", 1) for _ in range(20)))
    context = await s.get_context("concurrent")
    assert context["total_uses"] == 20
    assert context["total_amount"] == 20
