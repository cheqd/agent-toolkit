"""Line-item requirement matching via max-flow bipartite matching - a faithful port of AP2's
`max_flow_helper.py` (`evaluate_line_items_max_flow`, Dinic's algorithm only; the upstream
`edmonds_karp` mode exists there but is never actually selected by any caller in that
codebase, so it is not ported here).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from collections import deque

from cheqd_agent_identity_ap2.types import LineItem, LineItemRequirements

INF = 1e15


def _is_valid_quantity(quantity: object) -> bool:
    """A line-item quantity must be an integer (or an integer-valued float) >= 1. `bool` is
    excluded even though it is a subclass of `int` in Python, since `True`/`False` are never a
    legitimate quantity.
    """
    if isinstance(quantity, bool) or not isinstance(quantity, (int, float)):
        return False
    return float(quantity).is_integer() and quantity >= 1


def evaluate_line_items_max_flow(
    checkout_items: list[LineItem], requirements: list[LineItemRequirements]
) -> list[str]:
    """Checks that every item in `checkout_items` can be assigned to SOME `requirements` slot it
    is acceptable for - NOT that every requirement slot ends up filled. A requirement asking for
    more units than the cart contains is not itself a violation; a cart item with no acceptable,
    not-yet-full requirement slot left for it is. This is upstream's own semantics (preserved
    here rather than "fixed", even though it reads as a surprising property for a constraint
    named `line_items`). Returns violation messages, or an empty list if none.

    Fail-closed validation, deliberately: `acceptable_items` is a selectively-disclosable array
    in the upstream schema, and SD-JWT libraries drop undisclosed array elements - so a holder
    who withholds every disclosure for a requirement's `acceptable_items` makes the verified
    payload show `acceptable_items: []`, indistinguishable at this layer from an issuer-intended
    "accepts anything". An empty array is therefore never treated as a wildcard here; it means
    the requirement accepts nothing. Likewise, `quantity` and `item.id` are validated before
    aggregation rather than summed naively, so a negative/zero/non-integer quantity (or a
    non-string/empty id) can't net out a disallowed SKU or smuggle extra units past a
    requirement's capacity.
    """
    cart_qty: dict[str, float] = {}
    for li in checkout_items:
        sku = li["item"]["id"]
        quantity = li["quantity"]
        if not isinstance(sku, str) or len(sku) == 0:
            return [f"Invalid line item: item.id must be a non-empty string, got {sku!r}"]
        if not _is_valid_quantity(quantity):
            return [f"Invalid line item: quantity for {sku} must be an integer >= 1, got {quantity!r}"]
        cart_qty[sku] = cart_qty.get(sku, 0) + quantity
    sku_list = list(cart_qty.keys())

    # Empty acceptable_items means "accepts nothing", never a wildcard - see the fail-closed note
    # in this function's docstring above.
    req_acceptable: list[set[str]] = [{ai["id"] for ai in req["acceptable_items"]} for req in requirements]

    violations: list[str] = []

    all_acceptable: set[str] = set()
    for acc in req_acceptable:
        all_acceptable |= acc

    for sku, qty in cart_qty.items():
        if qty <= 0:
            continue
        if sku not in all_acceptable:
            violations.append(f"Item {sku} not in any requirement's acceptable items")
    if violations:
        return violations

    # Greedy elimination of degree-1 matching.
    req_remaining_capacity = [req["quantity"] for req in requirements]
    complex_sku_list: list[str] = []
    unassigned_items: list[str] = []

    for sku in sku_list:
        qty = cart_qty.get(sku, 0)
        if qty <= 0:
            continue

        match_idx = -1
        is_complex = False
        for j in range(len(requirements)):
            if sku in req_acceptable[j]:
                if match_idx == -1:
                    match_idx = j
                else:
                    is_complex = True
                    break

        if match_idx != -1 and not is_complex:
            capacity = req_remaining_capacity[match_idx]
            assigned = min(qty, capacity)
            req_remaining_capacity[match_idx] = capacity - assigned
            leftover = qty - assigned
            if leftover > 0:
                unassigned_items.append(f"{sku} ({leftover})")
        else:
            complex_sku_list.append(sku)

    if complex_sku_list:
        max_flow, residual = _line_items_max_flow(
            complex_sku_list, cart_qty, requirements, req_acceptable, req_remaining_capacity
        )
        total_complex_cart = sum(cart_qty.get(sku, 0) for sku in complex_sku_list)

        if max_flow < total_complex_cart:
            source = 0
            sku_offset = 1
            for i in range(len(complex_sku_list)):
                sku_node = sku_offset + i
                remaining = residual[source].get(sku_node, 0)
                if remaining > 0:
                    unassigned_items.append(f"{complex_sku_list[i]} ({remaining})")

    if unassigned_items:
        joined = ", ".join(unassigned_items)
        violations.append(
            f"Cannot satisfy line item constraints: {joined} could not be assigned to any requirement slot"
        )

    return violations


def _line_items_max_flow(
    sku_list: list[str],
    cart_qty: dict[str, float],
    requirements: list[LineItemRequirements],
    req_acceptable: list[set[str]],
    req_remaining_capacity: list[float],
) -> tuple[float, list[dict[int, float]]]:
    s_count = len(sku_list)
    r_count = len(requirements)
    n = 1 + s_count + r_count + 1
    source = 0
    sink = n - 1
    sku_offset = 1
    req_offset = sku_offset + s_count

    graph: list[dict[int, float]] = [{} for _ in range(n)]

    for i in range(s_count):
        u, v = source, sku_offset + i
        graph[u][v] = cart_qty.get(sku_list[i], 0)
        graph[v][u] = 0
    for i in range(s_count):
        sku = sku_list[i]
        for j in range(len(requirements)):
            if sku in req_acceptable[j]:
                u, v = sku_offset + i, req_offset + j
                graph[u][v] = INF
                graph[v][u] = 0
    for j in range(len(requirements)):
        u = req_offset + j
        graph[u][sink] = req_remaining_capacity[j]
        graph[sink][u] = 0

    max_flow = _dinic(graph, source, sink, n)
    return max_flow, graph


def _dinic(graph: list[dict[int, float]], source: int, sink: int, n: int) -> float:
    adj_nodes: list[list[int]] = [list(edges.keys()) for edges in graph]

    def bfs_level() -> list[int] | None:
        level = [-1] * n
        level[source] = 0
        queue = deque([source])
        while queue:
            u = queue.popleft()
            for v in adj_nodes[u]:
                if level[v] == -1 and graph[u].get(v, 0) > 0:
                    level[v] = level[u] + 1
                    queue.append(v)
        return None if level[sink] == -1 else level

    def dfs_block(u: int, pushed: float, level: list[int], it: list[int]) -> float:
        if u == sink or pushed == 0:
            return pushed
        total_pushed = 0.0
        while it[u] < len(adj_nodes[u]):
            idx = it[u]
            v = adj_nodes[u][idx]
            cap = graph[u].get(v, 0)
            if level[v] == level[u] + 1 and cap > 0:
                d = dfs_block(v, min(pushed, cap), level, it)
                if d > 0:
                    graph[u][v] = graph[u].get(v, 0) - d
                    graph[v][u] = graph[v].get(u, 0) + d
                    total_pushed += d
                    pushed -= d
                    if pushed == 0:
                        break
            it[u] = idx + 1
        return total_pushed

    total = 0.0
    while True:
        level = bfs_level()
        if level is None:
            break
        it = [0] * n
        while True:
            f = dfs_block(source, INF, level, it)
            if f == 0:
                break
            total += f
    return total
