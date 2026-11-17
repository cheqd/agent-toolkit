# SPDX-License-Identifier: Apache-2.0
# Tests for evaluate_line_items_max_flow, including the "complex" (ambiguous-match) path that
# actually exercises the Dinic max-flow solver, not just the greedy degree-1 shortcut.
from cheqd_agent_identity_ap2.max_flow import evaluate_line_items_max_flow


def item(id_, title=None):
    return {"id": id_, "title": title or id_}


def line_item(sku_id, quantity):
    return {"id": f"li-{sku_id}", "item": item(sku_id), "quantity": quantity, "totals": []}


def requirement(id_, acceptable_skus, quantity):
    return {"id": id_, "acceptable_items": [item(s) for s in acceptable_skus], "quantity": quantity}


def test_an_item_with_no_matching_requirement_at_all_is_rejected_before_any_flow_computation():
    cart = [line_item("a", 1)]
    reqs = [requirement("r1", ["b"], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert any("not in any requirement" in v for v in violations)


def test_an_item_acceptable_to_two_requirements_is_routed_via_max_flow_and_passes():
    # sku "a" is acceptable to both r1 and r2 - ambiguous, forces the complex/max-flow path.
    # The check is "can every cart item be assigned somewhere", not "is every requirement slot
    # filled" - so the single unit of "a" finding a home in either r1 or r2 is sufficient.
    cart = [line_item("a", 1)]
    reqs = [requirement("r1", ["a"], 1), requirement("r2", ["a"], 1)]
    assert evaluate_line_items_max_flow(cart, reqs) == []


def test_two_ambiguous_items_can_satisfy_two_ambiguous_requirements_via_max_flow():
    cart = [line_item("a", 1), line_item("b", 1)]
    reqs = [requirement("r1", ["a", "b"], 1), requirement("r2", ["a", "b"], 1)]
    assert evaluate_line_items_max_flow(cart, reqs) == []


def test_a_requirement_needing_more_than_the_cart_holds_is_not_itself_a_violation():
    # Only leftover (unassignable) CART quantity is ever flagged. A requirement asking for more
    # than the cart contains, with every cart unit still placed into that requirement's slot,
    # has no leftover - so this passes, a genuinely surprising property of the upstream
    # algorithm (ported faithfully, not "fixed" here). Uses an explicit acceptable_items list
    # rather than an empty one: see the H2 tests below for why an empty acceptable_items array
    # must never be treated as "accepts anything".
    cart = [line_item("a", 1)]
    reqs = [requirement("r1", ["a"], 2)]
    assert evaluate_line_items_max_flow(cart, reqs) == []


def test_a_cart_item_left_over_after_every_requirement_slot_fills_is_a_violation():
    # Two units of "a", but the only requirement slot (qty 1) fills after one unit - the second
    # unit has nowhere to go, which IS the leftover case this algorithm actually checks for.
    cart = [line_item("a", 2)]
    reqs = [requirement("r1", ["a"], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert any("could not be assigned" in v for v in violations)


# --- Security regression tests -----------------------------------------------------------------
# H2: an empty acceptable_items array must fail closed (reject), not be treated as a wildcard.
# SD-JWT libraries drop undisclosed array elements, so a holder withholding every disclosure for
# acceptable_items makes the verified payload show acceptable_items: [] - indistinguishable at
# this layer from an issuer-intended wildcard. Treating that as "anything is acceptable" lets a
# holder launder an item the issuer never allowed through non-disclosure.


def test_h2_empty_acceptable_items_fails_closed_not_treated_as_wildcard():
    cart = [line_item("sku-EVIL", 1)]
    reqs = [requirement("r1", [], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert any("sku-EVIL" in v and "not in any requirement" in v for v in violations), violations


def test_h2_mandate_with_only_empty_acceptable_items_requirement_rejects_every_cart_item():
    # Mirrors the PoC: a mandate that allows only sku-a and sku-b, presented with every
    # acceptable_items disclosure withheld, must not let an unrelated sku-EVIL through.
    cart = [line_item("sku-EVIL", 1)]
    reqs = [requirement("r1", [], 5)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert violations != []


# M1: line-item quantities must be validated as integers >= 1 (and item.id as a non-empty
# string) before aggregation. Negative/zero quantities must not be allowed to net out a positive
# quantity for the same SKU.


def test_m1_negative_quantity_line_item_cannot_cancel_out_a_disallowed_sku():
    # sku-EVIL x5 plus sku-EVIL x-5 nets to 0 under naive summation, which used to be skipped
    # entirely (no violation) even though sku-EVIL is not allowed at all.
    cart = [line_item("sku-EVIL", 5), line_item("sku-EVIL", -5)]
    reqs = [requirement("r1", ["sku-a", "sku-b"], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert violations != []


def test_m1_negative_quantity_line_item_cannot_sneak_an_over_quantity_sku_past_a_requirement():
    # sku-a x10 plus sku-a x-9 nets to 1 under naive summation, which used to satisfy a
    # quantity-1 requirement even though the cart actually contains far more than allowed.
    cart = [line_item("a", 10), line_item("a", -9)]
    reqs = [requirement("r1", ["a"], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert violations != []


def test_m1_zero_quantity_line_item_is_rejected_rather_than_silently_skipped():
    cart = [line_item("a", 0)]
    reqs = [requirement("r1", ["a"], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert violations != []


def test_m1_non_integer_quantity_is_rejected_even_when_ample_capacity_would_otherwise_absorb_it_silently():
    # Capacity (5) comfortably covers 1.5 units with no leftover, so this can only fail via
    # explicit quantity validation - not as a side effect of leftover-capacity arithmetic.
    cart = [line_item("a", 1.5)]
    reqs = [requirement("r1", ["a"], 5)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert violations != []


def test_m1_non_numeric_quantity_is_rejected():
    cart = [{"id": "li-1", "item": item("a"), "quantity": "50x", "totals": []}]
    reqs = [requirement("r1", ["a"], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert violations != []


def test_m1_line_item_with_empty_item_id_is_rejected():
    cart = [{"id": "li-1", "item": item(""), "quantity": 1, "totals": []}]
    reqs = [requirement("r1", ["a"], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert violations != []
