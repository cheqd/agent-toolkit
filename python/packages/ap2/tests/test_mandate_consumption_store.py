# SPDX-License-Identifier: Apache-2.0
# Tests for create_mandate_consumption_store: consume_once's exclusive-create atomicity, and
# record_use's cumulative total_amount/total_uses tracking.
import asyncio
import hashlib
import json
import math
from pathlib import Path

import pytest

from cheqd_agent_identity_ap2.mandate_consumption_store import create_mandate_consumption_store


def _context_path_for(directory, mandate_id: str) -> Path:
    # Mirrors the private `_context_path` hashing in mandate_consumption_store.py, so tests can
    # plant a pre-corrupted context file directly - simulating the result of a pre-fix NaN or
    # negative record.
    key = hashlib.sha256(f"context\x00{mandate_id}".encode("utf-8")).hexdigest()
    return Path(directory) / f"{key}.json"


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
    # The per-mandate-id lock must be pruned once all 20 concurrent callers settle (L3).
    assert s._locks == {}
    assert s._lock_refcounts == {}


# Regression (M2): record_use(id, float("nan")) used to persist via json.dumps(float("nan")),
# which writes the literal `NaN` token; json.loads then read it back as float("nan") forever
# ("NaN > max" is always False, so the budget check never fails again - reproduced: a $100,000
# payment against a $100 budget returned no violations after one NaN record). The fix rejects a
# non-finite/non-integer amount_minor_units outright instead of ever writing it.
async def test_record_use_rejects_a_nan_amount_instead_of_permanently_corrupting_the_stored_total(tmp_path):
    s = create_mandate_consumption_store(directory=tmp_path)
    await s.record_use("nan-amount", 9000)
    with pytest.raises(ValueError):
        await s.record_use("nan-amount", float("nan"))
    context = await s.get_context("nan-amount")
    assert context["total_amount"] == 9000, (
        "a rejected NaN amount must not corrupt or reset the previously recorded total"
    )
    assert context["total_uses"] == 1


# Regression (M2): a negative amount recorded after a positive one offsets it back down - e.g.
# +9000 then -9000 nets to 0, acting as an unintended budget refund. The fix rejects negative
# amounts outright.
async def test_record_use_rejects_a_negative_amount_instead_of_refunding_the_recorded_total(tmp_path):
    s = create_mandate_consumption_store(directory=tmp_path)
    await s.record_use("negative-amount", 9000)
    with pytest.raises(ValueError):
        await s.record_use("negative-amount", -9000)
    context = await s.get_context("negative-amount")
    assert context["total_amount"] == 9000, (
        "a negative amount must not refund (decrease) the previously recorded total"
    )
    assert context["total_uses"] == 1


async def test_record_use_and_check_and_record_use_reject_non_finite_non_integer_and_negative_amounts(
    tmp_path,
):
    s = create_mandate_consumption_store(directory=tmp_path)

    def _no_violations(_context):
        return []

    for invalid in (float("nan"), math.inf, -math.inf, -1, 1.5):
        with pytest.raises(ValueError):
            await s.record_use("invalid-amounts", invalid)
        with pytest.raises(ValueError):
            await s.check_and_record_use("invalid-amounts", invalid, _no_violations)
    assert await s.get_context("invalid-amounts") == {
        "total_amount": 0,
        "total_uses": 0,
    }, "none of the rejected calls may have recorded anything"


# Regression (M2): a corrupt stored total_amount (e.g. the permanent NaN a pre-fix record left
# behind) must fail closed, not be silently coerced back to 0 - coercing to 0 erases budget
# history instead of refusing to proceed.
async def test_get_context_and_record_use_fail_closed_on_a_corrupt_stored_total_instead_of_resetting_it(
    tmp_path,
):
    s = create_mandate_consumption_store(directory=tmp_path)
    await s.record_use("corrupt", 1)  # establishes the directory and a baseline context file
    _context_path_for(tmp_path, "corrupt").write_text(
        json.dumps({"total_amount": float("nan"), "total_uses": 1})
    )
    with pytest.raises(ValueError):
        await s.get_context("corrupt")
    with pytest.raises(ValueError):
        await s.record_use("corrupt", 1)


# Regression (L3): the per-mandate-id lock map used to retain one asyncio.Lock per mandate id
# forever (the same unbounded-growth bug class fixed for the nonce-cache's lock map in this
# batch). The fix prunes an entry once its holder count drops to zero.
async def test_the_per_mandate_id_lock_maps_do_not_grow_without_bound_as_distinct_mandate_ids_are_used(
    tmp_path,
):
    s = create_mandate_consumption_store(directory=tmp_path)
    for i in range(50):
        await s.record_use(f"mandate-{i}", 1)
    assert s._locks == {}, "every settled mandate id's lock must be pruned, not retained forever"
    assert s._lock_refcounts == {}


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
