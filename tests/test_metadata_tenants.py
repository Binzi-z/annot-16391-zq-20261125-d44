import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from retainer.metadata import (
    DEFAULT_ENTRIES,
    DEFAULT_TENANTS,
    MetadataCatalog,
    TenantRollupService,
    generate_metadata_entries,
    oracle_tenant_identity,
)


class FiftyThousandMetadataTenantTests(unittest.TestCase):
    def setUp(self):
        # 每个用例独立的 50k 数据集，避免访问计数跨用例累积。
        self.entries = generate_metadata_entries(DEFAULT_ENTRIES, DEFAULT_TENANTS)
        self.catalog = MetadataCatalog(self.entries)
        self.svc = TenantRollupService(self.catalog)
        self.dao = self.catalog.dao

    def test_scale_and_even_partition(self):
        self.assertEqual(len(self.entries), 50_000)
        self.assertEqual(len(self.dao.tenants), 100)
        for t in self.dao.tenants:
            self.assertEqual(self.dao.tenant_size(t), 500)

    def test_initial_full_recompute_real_access_count(self):
        done = self.svc.recompute_all()
        self.assertEqual(len(done), 100)
        # 真实访问量：全量重算必须恰好逐条读过 50000 条，不能少（也不应重复）。
        self.assertEqual(self.dao.total_reads, 50_000)
        for t in self.dao.tenants:
            self.assertEqual(self.dao.reads_by_tenant[t], 500)
            self.assertEqual(self.svc.rollups[t].recompute_count, 1)

    def test_change_recomputes_only_own_tenant_and_real_access(self):
        self.svc.recompute_all()
        self.assertEqual(self.dao.total_reads, 50_000)

        target = "tenant-007"
        before_identity = {t: ru.identity() for t, ru in self.svc.rollups.items()}
        before_count = {t: ru.recompute_count for t, ru in self.svc.rollups.items()}

        # tenant-007 中 entry_id=8（(id-1)%100==7）。直接读内部表取旧值，
        # 不经过计数 DAO.get，以免污染“真实 scan 访问量”的核对。
        old = self.dao._by_id[8]
        self.assertEqual(old.tenant, target)
        self.catalog.change_risk(8, 999)  # 写入/标脏，不产生 scan 读取计数
        self.assertEqual(self.catalog.dirty, {target})

        reads_before = self.dao.total_reads
        tenant_reads_before = dict(self.dao.reads_by_tenant)
        recomputed = self.svc.recompute_dirty()

        self.assertEqual(recomputed, [target])
        self.assertEqual(self.catalog.dirty, set())

        # 真实访问量增量：恰好重扫目标租户的 500 条，全局也只增加 500。
        self.assertEqual(self.dao.total_reads - reads_before, 500)
        for t in self.dao.tenants:
            delta = self.dao.reads_by_tenant[t] - tenant_reads_before[t]
            self.assertEqual(delta, 500 if t == target else 0,
                             f"租户 {t} 的真实访问增量异常: {delta}")

        # 无关租户：数据身份与重算次数完全不变（不重算）。
        for t in self.dao.tenants:
            if t == target:
                continue
            self.assertEqual(self.svc.rollups[t].identity(), before_identity[t],
                             f"无关租户 {t} 的聚合结果发生了变化（被错误重算）")
            self.assertEqual(self.svc.rollups[t].recompute_count, before_count[t])

        # 目标租户：确实重算一次且结果改变。
        self.assertEqual(self.svc.rollups[target].recompute_count, before_count[target] + 1)
        self.assertNotEqual(self.svc.rollups[target].identity(), before_identity[target])

        # 目标租户结果与独立神谕一致（用 DAO 内更新后的真实条目）。
        current = list(self.dao._by_id.values())
        self.assertEqual(self.svc.rollups[target].identity(),
                         oracle_tenant_identity(current, target))
        self.assertEqual(sum(ru.total_risk for ru in self.svc.rollups.values()),
                         sum(e.risk for e in current))

    def test_second_change_other_tenant_is_isolated(self):
        self.svc.recompute_all()
        # 先改 tenant-007。
        self.catalog.change_risk(8, 999)
        self.svc.recompute_dirty()
        self.assertEqual(self.svc.rollups["tenant-007"].recompute_count, 2)

        # 再改 tenant-042（entry_id=43）。
        target = "tenant-042"
        self.catalog.change_risk(43, 1)
        reads_before = dict(self.dao.reads_by_tenant)
        done = self.svc.recompute_dirty()
        self.assertEqual(done, [target])

        for t in self.dao.tenants:
            delta = self.dao.reads_by_tenant[t] - reads_before[t]
            self.assertEqual(delta, 500 if t == target else 0)

        # 只有 tenant-042 再算一次；tenant-007 与其余 98 个租户都不重算。
        self.assertEqual(self.svc.rollups[target].recompute_count, 2)
        self.assertEqual(self.svc.rollups["tenant-007"].recompute_count, 2)
        recomputed_again = [t for t, ru in self.svc.rollups.items()
                           if ru.recompute_count >= 2]
        self.assertEqual(sorted(recomputed_again), ["tenant-007", target])


if __name__ == "__main__":
    unittest.main(verbosity=2)
