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


def test_simple_wildcard_requirement_is_satisfied():
    cart = [line_item("a", 1)]
    reqs = [requirement("r1", [], 1)]
    assert evaluate_line_items_max_flow(cart, reqs) == []


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


def test_a_wildcard_requirement_needing_more_than_the_cart_holds_is_not_itself_a_violation():
    # Only leftover (unassignable) CART quantity is ever flagged. A requirement asking for more
    # than the cart contains, with every cart unit still placed into that requirement's slot,
    # has no leftover - so this passes, a genuinely surprising property of the upstream
    # algorithm (ported faithfully, not "fixed" here).
    cart = [line_item("a", 1)]
    reqs = [requirement("r1", [], 2)]
    assert evaluate_line_items_max_flow(cart, reqs) == []


def test_a_cart_item_left_over_after_every_requirement_slot_fills_is_a_violation():
    # Two units of "a", but the only requirement slot (qty 1) is wildcard-matched and fills
    # after one unit - the second unit has nowhere to go, which IS the leftover case this
    # algorithm actually checks for.
    cart = [line_item("a", 2)]
    reqs = [requirement("r1", [], 1)]
    violations = evaluate_line_items_max_flow(cart, reqs)
    assert any("could not be assigned" in v for v in violations)
