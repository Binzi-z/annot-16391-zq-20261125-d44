import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from retainer.manager import RetentionManager, whole_sample_cost
from retainer.risksel import Item, brute_force_select
from retainer.synthetic import make_sample
from retainer import verifier as disk_verifier


def explicit_samples():
    # (id, 分片大小列表, 风险)；whole cost = 分片大小之和。
    specs = [
        ("A", [100, 100], 50),
        ("B", [150], 90),
        ("C", [60, 60, 60], 70),
        ("D", [300], 200),
        ("E", [80, 80], 60),
        ("F", [40, 40, 40, 40], 75),
    ]
    out = []
    for sid, sizes, risk in specs:
        out.append(make_sample(sid, tenant="t1", risk=risk, shard_sizes=sizes,
                               gen_seed="explicit", batch_id="B1"))
    return out


class BudgetSelectionOnDiskTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="retainer_budget_")
        self.root = Path(self._tmp.name)
        self.mgr = RetentionManager.initialize(self.root, budget_bytes=100_000)
        self.samples = explicit_samples()
        self.mgr.ingest_samples(self.samples, batch_id="B1")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp.name, ignore_errors=True)

    def test_whole_sample_cost_is_sum_of_shards(self):
        for s in self.samples:
            self.assertEqual(whole_sample_cost(s), sum(sh["size"] for sh in s["shards"]))
            self.assertEqual(whole_sample_cost(s), s["size_bytes"])

    def test_shrink_selects_exact_optimum_and_reclaims_others(self):
        budget = 300
        self.mgr.set_budget(budget)
        m = self.mgr.manifest

        items = [Item(s["id"], whole_sample_cost(s), s["risk"]) for s in self.samples]
        expect = brute_force_select(items, budget)

        self.assertEqual(list(m["selection"]["chosen_optional_ids"]), list(expect.chosen))
        self.assertEqual(m["selection"]["chosen_optional_risk"], expect.total_value)
        self.assertEqual(m["selection"]["total_retained_cost"], expect.total_cost)
        self.assertLessEqual(m["selection"]["total_retained_cost"], budget)
        self.assertEqual(set(m["retained"]), set(expect.chosen))

        # 选中的完整样本：全部分片在盘且可读。
        for sid in expect.chosen:
            self.assertTrue(self.mgr.sample_dir(sid).exists())
            self.assertEqual(self.mgr.sample_read_errors(m, sid), [])
        # 未选中的样本：整样本目录已被回收（不存在“保留部分分片”的中间态）。
        for s in self.samples:
            if s["id"] not in expect.chosen:
                self.assertFalse(self.mgr.sample_dir(s["id"]).exists(),
                                 f"未选中样本 {s['id']} 应已整体回收")

        res = disk_verifier.verify_root_consistency(self.root)
        self.assertTrue(res["ok"], "\n".join(res["errors"]))

    def test_grow_budget_rebuilds_reclaimed_samples_and_verifies_hashes(self):
        self.mgr.set_budget(260)
        small_chosen = set(self.mgr.manifest["retained"])
        self.assertLess(len(small_chosen), len(self.samples))

        # 重新放宽预算：曾被回收、现在重新中选的样本按合成种子重建并通过哈希校验。
        self.mgr.set_budget(100_000)
        m = self.mgr.manifest
        self.assertEqual(set(m["retained"]), {s["id"] for s in self.samples})
        self.mgr.verify_readable()
        res = disk_verifier.verify_root_consistency(self.root)
        self.assertTrue(res["ok"], "\n".join(res["errors"]))
        for s in self.samples:
            self.assertTrue(self.mgr.sample_dir(s["id"]).exists())

    def test_mandatory_obligation_outranks_shrunk_budget(self):
        # 对代价 300 的 D 设定保留义务。
        self.mgr.add_hold("D", case_id="CASE-MUST-KEEP")
        self.mgr.set_budget(80)  # 远低于义务样本代价

        sel = self.mgr.manifest["selection"]
        self.assertFalse(sel["budget_feasible"])
        self.assertGreater(sel["deficit_bytes"], 0)
        self.assertEqual(sel["remaining_budget"], 80 - 300)
        # 负剩余预算下不选任何可选项，但义务样本 D 仍被强制保留且可读。
        self.assertEqual(self.mgr.manifest["retained"], ["D"])
        self.assertEqual(sel["chosen_optional_ids"], [])
        self.assertEqual(self.mgr.sample_read_errors(self.mgr.manifest, "D"), [])
        self.assertTrue(self.mgr.sample_dir("D").exists())

        # 独立核验器接受“义务优先、预算有缺口”的状态，且算术/可读性全部自洽。
        res = disk_verifier.verify_root_consistency(self.root)
        self.assertTrue(res["ok"], "\n".join(res["errors"]))
        self.assertFalse(res["facts"]["budget_feasible"])

        # 预算恢复到能覆盖义务 + 最优可选组合后，重新回到可行且最优。
        self.mgr.set_budget(2_000)
        res2 = disk_verifier.verify_root_consistency(self.root)
        self.assertTrue(res2["ok"], "\n".join(res2["errors"]))
        self.assertTrue(self.mgr.manifest["selection"]["budget_feasible"])

    def test_duplicate_ingest_is_idempotent(self):
        before = len(self.mgr.manifest["samples"])
        self.mgr.ingest_samples([self.samples[0]], batch_id="B1")  # 同 ID 同内容
        self.assertEqual(len(self.mgr.manifest["samples"]), before)
        self.assertEqual(self.mgr.manifest["batches"]["B1"].count("A"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
