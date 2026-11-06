/**
 * Line-item requirement matching via max-flow bipartite matching - a faithful port of AP2's
 * `max_flow_helper.py` (`evaluate_line_items_max_flow`, Dinic's algorithm only; the upstream
 * `edmonds_karp` mode exists there but is never actually selected by any caller in that
 * codebase, so it is not ported here).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import type { LineItem, LineItemRequirements } from './types.js';

const INF = 1e15;

/**
 * Checks that every item in `checkoutItems` can be assigned to SOME `requirements` slot it is
 * acceptable for - NOT that every requirement slot ends up filled. A requirement asking for more
 * units than the cart contains is not itself a violation; a cart item with no acceptable,
 * not-yet-full requirement slot left for it is. This is upstream's own semantics (confirmed
 * against `max_flow_helper.py`: `unassigned_items` is built only from leftover cart quantity),
 * preserved here rather than "fixed", even though it reads as a surprising property for a
 * constraint named `line_items`. Returns violation messages, or an empty array if none.
 */
export function evaluateLineItemsMaxFlow(checkoutItems: readonly LineItem[], requirements: readonly LineItemRequirements[]): string[] {
	const cartQty = new Map<string, number>();
	for (const li of checkoutItems) {
		const sku = li.item.id;
		cartQty.set(sku, (cartQty.get(sku) ?? 0) + li.quantity);
	}
	const skuList = [...cartQty.keys()];

	const reqAcceptable: Set<string>[] = requirements.map((req) => (req.acceptable_items.length > 0 ? new Set(req.acceptable_items.map((ai) => ai.id)) : new Set<string>()));
	const reqIsWildcard: boolean[] = requirements.map((req) => req.acceptable_items.length === 0);

	const violations: string[] = [];

	const hasWildcard = reqIsWildcard.some(Boolean);
	const allAcceptable = new Set<string>();
	if (!hasWildcard) {
		for (const acc of reqAcceptable) for (const id of acc) allAcceptable.add(id);
	}

	for (const [sku, qty] of cartQty) {
		if (qty <= 0) continue;
		if (!hasWildcard && !allAcceptable.has(sku)) violations.push(`Item ${sku} not in any requirement's acceptable items`);
	}
	if (violations.length > 0) return violations;

	// Greedy elimination of degree-1 matching.
	const reqRemainingCapacity = requirements.map((req) => req.quantity);
	const complexSkuList: string[] = [];
	const unassignedItems: string[] = [];

	for (const sku of skuList) {
		const qty = cartQty.get(sku) ?? 0;
		if (qty <= 0) continue;

		let matchIdx = -1;
		let isComplex = false;
		for (let j = 0; j < requirements.length; j++) {
			if (reqIsWildcard[j] || reqAcceptable[j]?.has(sku)) {
				if (matchIdx === -1) matchIdx = j;
				else {
					isComplex = true;
					break;
				}
			}
		}

		if (matchIdx !== -1 && !isComplex) {
			const capacity = reqRemainingCapacity[matchIdx] ?? 0;
			const assigned = Math.min(qty, capacity);
			reqRemainingCapacity[matchIdx] = capacity - assigned;
			const leftover = qty - assigned;
			if (leftover > 0) unassignedItems.push(`${sku} (${leftover})`);
		} else {
			complexSkuList.push(sku);
		}
	}

	if (complexSkuList.length > 0) {
		const { maxFlow, residual } = lineItemsMaxFlow(complexSkuList, cartQty, requirements, reqAcceptable, reqIsWildcard, reqRemainingCapacity);
		const totalComplexCart = complexSkuList.reduce((sum, sku) => sum + (cartQty.get(sku) ?? 0), 0);

		if (maxFlow < totalComplexCart) {
			const source = 0;
			const skuOffset = 1;
			for (let i = 0; i < complexSkuList.length; i++) {
				const skuNode = skuOffset + i;
				const remaining = residual[source]?.get(skuNode) ?? 0;
				if (remaining > 0) unassignedItems.push(`${complexSkuList[i]} (${remaining})`);
			}
		}
	}

	if (unassignedItems.length > 0) {
		violations.push(`Cannot satisfy line item constraints: ${unassignedItems.join(', ')} could not be assigned to any requirement slot`);
	}

	return violations;
}

function lineItemsMaxFlow(
	skuList: readonly string[],
	cartQty: Map<string, number>,
	requirements: readonly LineItemRequirements[],
	reqAcceptable: readonly Set<string>[],
	reqIsWildcard: readonly boolean[],
	reqRemainingCapacity: readonly number[],
): { maxFlow: number; residual: Map<number, number>[] } {
	const sCount = skuList.length;
	const rCount = requirements.length;
	const n = 1 + sCount + rCount + 1;
	const source = 0;
	const sink = n - 1;
	const skuOffset = 1;
	const reqOffset = skuOffset + sCount;

	const graph: Map<number, number>[] = Array.from({ length: n }, () => new Map<number, number>());

	for (let i = 0; i < sCount; i++) {
		const u = source;
		const v = skuOffset + i;
		graph[u]?.set(v, cartQty.get(skuList[i] ?? '') ?? 0);
		graph[v]?.set(u, 0);
	}
	for (let i = 0; i < sCount; i++) {
		const sku = skuList[i] ?? '';
		for (let j = 0; j < requirements.length; j++) {
			if (reqIsWildcard[j] || reqAcceptable[j]?.has(sku)) {
				const u = skuOffset + i;
				const v = reqOffset + j;
				graph[u]?.set(v, INF);
				graph[v]?.set(u, 0);
			}
		}
	}
	for (let j = 0; j < requirements.length; j++) {
		const u = reqOffset + j;
		graph[u]?.set(sink, reqRemainingCapacity[j] ?? 0);
		graph[sink]?.set(u, 0);
	}

	const maxFlow = dinic(graph, source, sink, n);
	return { maxFlow, residual: graph };
}

function dinic(graph: Map<number, number>[], source: number, sink: number, n: number): number {
	const adjNodes: number[][] = graph.map((edges) => [...edges.keys()]);

	function bfsLevel(): number[] | undefined {
		const level = new Array<number>(n).fill(-1);
		level[source] = 0;
		const queue: number[] = [source];
		while (queue.length > 0) {
			const u = queue.shift() as number;
			for (const v of adjNodes[u] ?? []) {
				if (level[v] === -1 && (graph[u]?.get(v) ?? 0) > 0) {
					level[v] = (level[u] ?? 0) + 1;
					queue.push(v);
				}
			}
		}
		return level[sink] === -1 ? undefined : level;
	}

	function dfsBlock(u: number, pushed: number, level: number[], it: number[]): number {
		if (u === sink || pushed === 0) return pushed;
		let totalPushed = 0;
		while ((it[u] ?? 0) < (adjNodes[u]?.length ?? 0)) {
			const idx = it[u] ?? 0;
			const v = adjNodes[u]?.[idx] as number;
			const cap = graph[u]?.get(v) ?? 0;
			if (level[v] === (level[u] ?? 0) + 1 && cap > 0) {
				const d = dfsBlock(v, Math.min(pushed, cap), level, it);
				if (d > 0) {
					graph[u]?.set(v, (graph[u]?.get(v) ?? 0) - d);
					graph[v]?.set(u, (graph[v]?.get(u) ?? 0) + d);
					totalPushed += d;
					pushed -= d;
					if (pushed === 0) break;
				}
			}
			it[u] = idx + 1;
		}
		return totalPushed;
	}

	let total = 0;
	for (;;) {
		const level = bfsLevel();
		if (!level) break;
		const it = new Array<number>(n).fill(0);
		for (;;) {
			const f = dfsBlock(source, INF, level, it);
			if (f === 0) break;
			total += f;
		}
	}
	return total;
}
