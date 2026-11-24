import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import itertools
import random
import unittest

from retainer.risksel import Item, brute_force_select, dp_select, exact_select


def ids(res):
    return res.chosen


class ExhaustiveShortSequenceTests(unittest.TestCase):
    """对短序列穷举：容量边界、等价值、重复样本，逐例比对暴力神谕与精确 DP。"""

    ALPHABET = [
        (1, 5),   # A 低代价中风险
        (2, 5),   # B 与 A 等价值但代价更高
        (3, 9),   # C
        (2, 7),   # D 与 B 同代价、价值不同
        (4, 9),   # E 与 C 等价值但代价更高
        (1, 1),   # F
    ]

    def _seq_items(self, seq):
        items = []
        for j, ai in enumerate(seq):
            c, v = self.ALPHABET[ai]
            items.append(Item(id=f"s{j:02d}", cost=c, value=v))
        return items

    def test_exhaustive_product_all_budgets(self):
        checked = 0
        max_len = 5
        for length in range(0, max_len + 1):
            for seq in itertools.product(range(len(self.ALPHABET)), repeat=length):
                items = self._seq_items(seq)
                total_cost = sum(i.cost for i in items)
                # 容量边界全覆盖：0、1…总代价，以及总代价+1（过剩）。
                for budget in range(0, total_cost + 2):
                    b = brute_force_select(items, budget)
                    d = dp_select(items, budget)
                    self.assertEqual(b.chosen, d.chosen,
                                     msg=f"DP 规范选择与暴力不一致 seq={seq} B={budget}")
                    self.assertEqual((b.total_value, b.total_cost),
                                     (d.total_value, d.total_cost))
                    self.assertLessEqual(b.total_cost, budget)
                    checked += 1
        # 明确断言确实执行了大量穷举，而不是被静默跳过。
        self.assertGreater(checked, 100_000, f"穷举用例数过少: {checked}")

    def test_exact_select_dp_dispatch_larger_n(self):
        # n>brute_limit(16) 时 exact_select 走 DP；应与 dp_select 完全一致。
        rng = random.Random(4242)
        for _ in range(20):
            n = rng.randint(17, 24)
            items = [Item(f"j{j:02d}", rng.randint(1, 20), rng.randint(0, 60))
                     for j in range(n)]
            cap = rng.randint(0, sum(i.cost for i in items))
            self.assertEqual(exact_select(items, cap).chosen, dp_select(items, cap).chosen)

    def test_capacity_boundaries_explicit(self):
        items = [
            Item("a", 3, 10), Item("b", 4, 13), Item("c", 2, 6),
            Item("d", 5, 17), Item("e", 1, 4),
        ]
        total = sum(i.cost for i in items)  # 15
        for budget in [0, 1, 2, 3, 6, total - 1, total, total + 1, total + 50]:
            b = brute_force_select(items, budget)
            d = dp_select(items, budget)
            self.assertEqual(b.chosen, d.chosen)
            self.assertLessEqual(d.total_cost, budget)
            # 边界：budget==0 时什么都不能选（代价严格为正）。
            if budget == 0:
                self.assertEqual(d.chosen, ())
                self.assertEqual(d.total_value, 0)
            # 容量足以容纳全部时必须全选，且总风险为总和。
            if budget >= total:
                self.assertEqual(set(d.chosen), {i.id for i in items})
                self.assertEqual(d.total_value, sum(i.value for i in items))

    def test_equal_values_are_deterministic_and_optimal(self):
        # 所有样本风险相同：最优 = 容量内最大化“个数”，等价于优先低代价；
        # 同代价时用确定性字典序平局。
        items = [
            Item("x1", 3, 7), Item("x2", 1, 7), Item("x3", 2, 7),
            Item("x4", 1, 7), Item("x5", 2, 7), Item("x6", 4, 7),
        ]
        for budget in range(0, 14):
            b = brute_force_select(items, budget)
            d = dp_select(items, budget)
            self.assertEqual(b.chosen, d.chosen)
            self.assertEqual(d.total_value, b.total_value)
        # budget=2：能选两个代价 1 的样本 x2、x4（字典序平局）。
        sel = exact_select(items, 2)
        self.assertEqual(sel.chosen, ("x2", "x4"))
        self.assertEqual(sel.count, 2)

    def test_duplicate_samples_independent(self):
        # 重复样本：相同代价/风险，但不同 ID，是各自独立的完整样本。
        for mult in range(1, 9):
            items = [Item(f"dup-{k:02d}", 2, 5) for k in range(mult)]
            for budget in range(0, 2 * mult + 2):
                b = brute_force_select(items, budget)
                d = dp_select(items, budget)
                self.assertEqual(b.chosen, d.chosen)
                expect_count = min(mult, budget // 2)
                self.assertEqual(d.count, expect_count)
                # 确定性：同容量下永远选 ID 最小的那批。
                self.assertEqual(list(d.chosen),
                                 [f"dup-{k:02d}" for k in range(expect_count)])

    def test_random_sequences_crosscheck(self):
        rng = random.Random(20261125)
        for trial in range(70):
            n = rng.randint(1, 14)
            items = [
                Item(f"i{j:02d}", rng.randint(1, 12), rng.randint(0, 30))
                for j in range(n)
            ]
            total = sum(i.cost for i in items)
            budget = rng.randint(0, total + 2)
            b = brute_force_select(items, budget)
            d = dp_select(items, budget)
            self.assertEqual(b.chosen, d.chosen, msg=f"trial={trial} B={budget}")
            self.assertEqual(b.total_value, d.total_value)

    def test_zero_cost_items_value_optimal(self):
        # 零代价样本不应用于义务域（保险库代价恒正），但 DP 仍须保证价值最优、
        # 且滚动数组不会在同一层重复使用同一物品。这里只强校验价值最优。
        items = [Item("z1", 0, 5), Item("z2", 0, 3), Item("p", 2, 7)]
        for budget in range(0, 5):
            b = brute_force_select(items, budget)
            d = dp_select(items, budget)
            self.assertEqual(d.total_value, b.total_value)
            self.assertEqual(d.total_cost, b.total_cost)

    def test_total_risk_not_density_greedy(self):
        # 构造“风险密度贪心”会输、而精确总风险 DP 会赢的经典例子，
        # 证明目标是“精确总风险最大”，不是 risk/size 比率贪心。
        items = [
            Item("dense", 3, 31),   # 密度 ~10.3，最高
            Item("big-a", 5, 53),
            Item("big-b", 5, 53),
        ]
        budget = 10
        sel = exact_select(items, budget)
        # 密度贪心会先拿 dense(3,31)，剩 7 只能再拿一个 big(5,53) => 84；
        # 精确最优是两个 big => 106。
        self.assertGreaterEqual(sel.total_value, 106)
        self.assertEqual(sel.total_value, brute_force_select(items, budget).total_value)
        self.assertEqual(set(sel.chosen), {"big-a", "big-b"})

    def test_shards_are_not_independent_items(self):
        # 一个样本 3 个分片，大小 1+1+100=102；不能因为前两个分片“便宜又高风险”
        # 就把该样本按代价 2 保留。选择器只接收 whole-sample 代价。
        shard_sizes = [1, 1, 100]
        whole_cost = sum(shard_sizes)
        sample = Item("S-WHOLE", whole_cost, 50)
        cheap_other = Item("S-CHEAP", 40, 40)
        budget = 50
        sel = exact_select([sample, cheap_other], budget)
        # S-WHOLE 真实代价 102 > 50，不可选；只能选 S-CHEAP。
        self.assertEqual(sel.chosen, ("S-CHEAP",))
        self.assertEqual(whole_cost, 102)


if __name__ == "__main__":
    unittest.main(verbosity=2)
