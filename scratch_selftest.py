"""快速冒烟：穷举短序列核对 DP 与暴力基准。

更完整的 11 万+ 用例穷举由 tests/test_selector_exhaustive.py 执行：
    python -m unittest tests.test_selector_exhaustive -v
"""
import itertools

from retainer.risksel import Item, brute_force_select, dp_select

ALPHABET = [(1, 5), (2, 5), (3, 9), (2, 7), (4, 9), (1, 1)]

checked = 0
for length in range(0, 5):  # 0..4，秒级
    for seq in itertools.product(range(len(ALPHABET)), repeat=length):
        items = [Item(f"s{j:02d}", *ALPHABET[ai]) for j, ai in enumerate(seq)]
        total_cost = sum(i.cost for i in items)
        for budget in range(0, total_cost + 2):  # 含 budget=0 与过剩边界
            b = brute_force_select(items, budget)
            d = dp_select(items, budget)
            assert b.chosen == d.chosen, (seq, budget, b.chosen, d.chosen)
            assert (b.total_value, b.total_cost) == (d.total_value, d.total_cost)
            checked += 1

print(f"scratch selector smoke OK: {checked} cases")
