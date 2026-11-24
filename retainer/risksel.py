"""精确“总风险优先”组合选择。

题眼：不能把分片当作可单独保留的完整样本。因此一个样本的代价是其**全部分片
大小之和**，价值是该样本的风险分；选择单位永远是“整个样本”（全保留或全不保留）。

本模块只做纯计算，不碰磁盘，便于穷举测试。我们提供：

- :func:`brute_force_select`：枚举全部子集的独立基准（短序列穷举神谕）。
- :func:`dp_select`：O(n*budget) 的精确 0/1 背包，带确定性平局规则。
- :func:`exact_select`：按规模自动选择，二者平局规则完全一致。

确定性平局规则（主目标始终是“总风险最大”，绝不以平局牺牲最优性）：
1. 总风险（value）更大；
2. 总占用字节（cost）更小；
3. 样本 ID 升序排列后的元组按字典序更小。

在代价严格为正（保险库中每个样本至少 1 字节）的前提下，基于“每一代价只保留
规范最优状态”的滚动 DP 与上述字典序规则严格一致；该一致性由穷举测试逐例核对。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True)
class Item:
    """一个可保留的完整样本（cost 必须是全分片字节总和）。"""

    id: str
    cost: int
    value: int


@dataclass(frozen=True)
class Selection:
    chosen: tuple[str, ...]
    total_cost: int
    total_value: int
    budget: int
    algorithm: str

    @property
    def count(self) -> int:
        return len(self.chosen)

    def contains(self, sample_id: str) -> bool:
        return sample_id in self.chosen_set()

    def chosen_set(self) -> frozenset[str]:
        return frozenset(self.chosen)


def _normalize(items: Sequence[Item]) -> list[Item]:
    norm = list(items)
    if any(not isinstance(x, Item) for x in norm):
        raise TypeError("items 必须是 Item 实例")
    ids = [x.id for x in norm]
    if len(set(ids)) != len(ids):
        raise ValueError("Item.id 必须唯一（重复样本也应使用不同样本 ID）")
    for x in norm:
        if not isinstance(x.cost, int) or x.cost < 0:
            raise ValueError(f"Item {x.id} 的 cost 必须是非负整数，得到 {x.cost!r}")
        if not isinstance(x.value, int) or x.value < 0:
            raise ValueError(f"Item {x.id} 的 value/risk 必须是非负整数，得到 {x.value!r}")
    norm.sort(key=lambda x: x.id)
    return norm


def _ids_of_mask(items: Sequence[Item], mask: int) -> tuple[str, ...]:
    return tuple(items[i].id for i in range(len(items)) if (mask >> i) & 1)


def _better(cand_a, cand_b, items: Sequence[Item]) -> bool:
    """cand=(value,cost,mask)。返回 a 是否按规范顺序优于 b。None 表示不可行。"""
    if cand_b is None:
        return cand_a is not None
    if cand_a is None:
        return False
    va, ca, ma = cand_a
    vb, cb, mb = cand_b
    if va != vb:
        return va > vb
    if ca != cb:
        return ca < cb
    return _ids_of_mask(items, ma) < _ids_of_mask(items, mb)


def _finalize(items: Sequence[Item], budget: int, value: int, cost: int, mask: int,
              algorithm: str) -> Selection:
    chosen = tuple(sorted(_ids_of_mask(items, mask)))
    # 以实际掩码重算，杜绝构造错误。
    real_cost = sum(items[i].cost for i in range(len(items)) if (mask >> i) & 1)
    real_value = sum(items[i].value for i in range(len(items)) if (mask >> i) & 1)
    assert real_cost == cost, (real_cost, cost)
    assert real_value == value, (real_value, value)
    assert cost <= budget
    return Selection(chosen=chosen, total_cost=cost, total_value=value,
                     budget=budget, algorithm=algorithm)


def brute_force_select(items: Iterable[Item], budget: int) -> Selection:
    """枚举 2^n 全部子集，按完整规范顺序取最优。短序列的独立神谕。"""
    its = _normalize(list(items))
    if not isinstance(budget, int) or budget < 0:
        raise ValueError("budget 必须是非负整数")
    n = len(its)
    best = (0, 0, 0)  # 空集总是可行
    for mask in range(1 << n):
        c = 0
        v = 0
        for i in range(n):
            if (mask >> i) & 1:
                c += its[i].cost
                v += its[i].value
        if c <= budget:
            cand = (v, c, mask)
            if _better(cand, best, its):
                best = cand
    v, c, m = best
    return _finalize(its, budget, v, c, m, "brute-force-2^n")


def dp_select(items: Iterable[Item], budget: int) -> Selection:
    """精确 0/1 背包 DP（按精确代价建状态），带规范平局规则。

    使用滚动数组 prev/cur，正确处理 cost=0（不会在同一层重复使用同一物品）。
    状态 cell[w] 保存“恰好用掉 w 字节”的规范最优候选 (value,cost,mask)。
    """
    its = _normalize(list(items))
    if not isinstance(budget, int) or budget < 0:
        raise ValueError("budget 必须是非负整数")

    # prev[w]：处理完上一批物品后，精确代价为 w 的规范最优候选。
    prev: list[tuple[int, int, int] | None] = [None] * (budget + 1)
    prev[0] = (0, 0, 0)

    for idx, it in enumerate(its):
        c = it.cost
        val = it.value
        cur: list[tuple[int, int, int] | None] = [None] * (budget + 1)
        for w in range(budget + 1):
            best = prev[w]  # 不选当前样本
            if w >= c and prev[w - c] is not None:
                pv, pc, pm = prev[w - c]
                take = (pv + val, pc + c, pm | (1 << idx))
                if _better(take, best, its):
                    best = take
            cur[w] = best
        prev = cur

    best = prev[0]
    for w in range(1, budget + 1):
        if _better(prev[w], best, its):
            best = prev[w]
    assert best is not None
    v, c, m = best
    return _finalize(its, budget, v, c, m, "exact-dp-0/1")


def exact_select(items: Iterable[Item], budget: int, brute_limit: int = 16) -> Selection:
    """规模小时用暴力（最透明），否则用精确 DP；结果规范一致。"""
    its = list(items)
    if budget < 0:
        raise ValueError("exact_select 的 budget 必须非负；义务超预算的缺口由管理层记录")
    if len(its) <= brute_limit:
        return brute_force_select(its, budget)
    return dp_select(its, budget)


def optimal_risk(items: Iterable[Item], budget: int) -> int:
    """便捷函数：只返回精确最大总风险（核验器重算时使用）。"""
    return exact_select(items, budget).total_value
