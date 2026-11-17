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


# Regression: composing get_context() + an external constraint check + record_use() has a real
# check-then-record race - two concurrent callers can both read the same stale context before
# either records, so both can pass a budget check only one of them should have.
BUDGET_CENTS = 10000  # $100.00


def _check_budget(context):
    return ["over budget"] if context["total_amount"] + 9000 > BUDGET_CENTS else []


async def test_composing_get_context_and_an_external_check_and_record_use_lets_both_concurrent_payments_pass_a_budget_only_one_should_fit_in(
    tmp_path,
):
    s = create_mandate_consumption_store(directory=tmp_path)

    async def attempt():
        context = await s.get_context("racy")
        violations = _check_budget(context)
        if violations:
            return {"ok": False, "violations": violations}
        return {"ok": True, "context": await s.record_use("racy", 9000)}

    a, b = await asyncio.gather(attempt(), attempt())
    final_context = await s.get_context("racy")
    # This assertion documents the race, not endorses it: both attempts can succeed even though
    # only one $90 payment fits in a $100 budget.
    assert a["ok"] and b["ok"], "both concurrent attempts passed the external check (the race)"
    assert final_context["total_amount"] == 18000, "both recorded, ending over budget"


async def test_check_and_record_use_closes_the_race_exactly_one_of_two_concurrent_90_dollar_payments_against_a_100_dollar_budget_succeeds(
    tmp_path,
):
    s = create_mandate_consumption_store(directory=tmp_path)
    a, b = await asyncio.gather(
        s.check_and_record_use("atomic", 9000, _check_budget),
        s.check_and_record_use("atomic", 9000, _check_budget),
    )
    results = [a, b]
    succeeded = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    assert len(succeeded) == 1, "exactly one of the two concurrent payments must succeed"
    assert len(failed) == 1, "exactly one of the two concurrent payments must be rejected"
    assert failed[0].violations[0] == "over budget"
    final_context = await s.get_context("atomic")
    assert final_context["total_amount"] == 9000, "only the one successful payment was recorded - never both"
