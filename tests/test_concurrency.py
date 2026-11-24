import sys
import threading
import time
import traceback
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from retainer.manager import RetentionManager
from retainer.synthetic import deterministic_samples, make_sample
from retainer import verifier as disk_verifier


class TwoWorkerInterleavingTests(unittest.TestCase):
    """两个工作线程把 撤销保留 / 更改预算 / 样本入库 真实交错；

    主线程在它们运行期间持续从磁盘独立核验“当前已提交状态”的义务与承诺快照
    始终可读（每次核验持有管理器 RLock，从而与回收互斥、读到一致的提交状态）；
    另有一个完全无锁的“永久义务核心”探针，直接哈希永不回收的分片。
    """

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory(prefix="retainer_conc_")
        self.root = Path(self._tmp.name)
        self.mgr = RetentionManager.initialize(self.root, budget_bytes=2600)

        # 永久对外承诺批次（任何线程都不撤销）。
        promised = deterministic_samples(3, prefix="P", seed=101,
                                        tenants=["tenant-legal"], batch_id="B-PROM")
        self.mgr.ingest_samples(promised, batch_id="B-PROM")
        self.mgr.promise_batch_snapshot("B-PROM", snapshot_id="SNAP-PROM")
        self.permanent_ids = [s["id"] for s in promised]
        self.permanent_samples = {s["id"]: s for s in promised}

        # 可被撤销的保留义务池。
        held = deterministic_samples(10, prefix="H", seed=202,
                                    tenants=["tenant-case"], batch_id="B-HELD")
        self.mgr.ingest_samples(held, batch_id="B-HELD")
        for s in held:
            self.mgr.add_hold(s["id"], case_id="CASE-X")
        self.revocable_pool = [s["id"] for s in held]

        self._id_lock = threading.Lock()
        self._seq = 0
        self._revoke_index = 0
        self.worker_errors: list[str] = []

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp.name, ignore_errors=True)

    def _next_id(self):
        with self._id_lock:
            self._seq += 1
            return f"W{self._seq:04d}"

    def _next_revoke(self):
        with self._id_lock:
            if self._revoke_index >= len(self.revocable_pool):
                return None
            sid = self.revocable_pool[self._revoke_index]
            self._revoke_index += 1
            return sid

    def _record(self, where):
        self.worker_errors.append(where + ":\n" + traceback.format_exc())

    def test_two_workers_revoke_budget_ingest_interleaved(self):
        budgets = [350, 700, 1400, 2600, 4200]
        op_counts = {"ingest": 0, "revoke": 0, "budget": 0}
        counts_lock = threading.Lock()

        def worker_a():
            import random
            rng = random.Random(1001)
            try:
                for _ in range(22):
                    sid = self._next_id()
                    sizes = [rng.randint(24, 180) for _ in range(rng.randint(1, 4))]
                    s = make_sample(sid, tenant="tenant-a", risk=rng.randint(40, 100),
                                    shard_sizes=sizes, gen_seed="wa", batch_id="B-WA")
                    self.mgr.ingest_samples([s], batch_id="B-WA")
                    with counts_lock:
                        op_counts["ingest"] += 1
                    # 入库后立刻设定义务再撤销，与另一线程的预算/撤销交错。
                    self.mgr.add_hold(sid, case_id="CASE-TMP")
                    self.mgr.revoke_hold(sid)
                    if rng.random() < 0.5:
                        self.mgr.set_budget(budgets[rng.randrange(len(budgets))])
                        with counts_lock:
                            op_counts["budget"] += 1
                    time.sleep(rng.uniform(0, 0.002))
            except Exception:  # noqa: BLE001
                self._record("worker_a")

        def worker_b():
            import random
            rng = random.Random(2002)
            try:
                for k in range(22):
                    action = k % 3
                    if action == 0:
                        self.mgr.set_budget(budgets[rng.randrange(len(budgets))])
                        with counts_lock:
                            op_counts["budget"] += 1
                    elif action == 1:
                        sid = self._next_revoke()
                        if sid is not None:
                            self.mgr.revoke_hold(sid)
                            with counts_lock:
                                op_counts["revoke"] += 1
                    else:
                        sid = self._next_id()
                        s = make_sample(sid, tenant="tenant-b", risk=rng.randint(50, 99),
                                        shard_sizes=[rng.randint(40, 200)
                                                     for _ in range(rng.randint(1, 3))],
                                        gen_seed="wb", batch_id="B-WB")
                        self.mgr.ingest_samples([s], batch_id="B-WB")
                        with counts_lock:
                            op_counts["ingest"] += 1
                    # 也持续入库高风险样本，保证“新到高风险样本”参与重选。
                    if k % 2 == 0:
                        hid = self._next_id()
                        hot = make_sample(hid, tenant="tenant-hot", risk=rng.randint(85, 100),
                                          shard_sizes=[rng.randint(30, 160)
                                                       for _ in range(rng.randint(1, 3))],
                                          gen_seed="whot", batch_id="B-HOT")
                        self.mgr.ingest_samples([hot], batch_id="B-HOT")
                        with counts_lock:
                            op_counts["ingest"] += 1
                    time.sleep(rng.uniform(0, 0.002))
            except Exception:  # noqa: BLE001
                self._record("worker_b")

        ta = threading.Thread(target=worker_a, name="worker-A", daemon=True)
        tb = threading.Thread(target=worker_b, name="worker-B", daemon=True)
        ta.start()
        tb.start()

        probes = 0
        lockfree_core_probes = 0
        probe_failures: list[str] = []
        # 主线程：只要任一 worker 存活就持续核验。
        while ta.is_alive() or tb.is_alive():
            # 1) 无锁永久核心探针：承诺快照分片永不回收，任何时刻都必须可读。
            for sid in self.permanent_ids:
                errs = disk_verifier._check_sample_shards(
                    self.root, sid, self.permanent_samples[sid])
                if errs:
                    probe_failures.append("lockfree-core " + ";".join(errs))
            lockfree_core_probes += 1

            # 2) 持锁的当前提交状态可读性核验（高频、轻量，与回收互斥）。
            with self.mgr.lock:
                ro = disk_verifier.verify_readability(self.root)
            probes += 1
            if not ro["ok"]:
                probe_failures.extend(ro["errors"][:5])
                break
            # 周期性做一次含预算算术/精确最优性的全量独立核验。
            if probes % 25 == 0:
                with self.mgr.lock:
                    full = disk_verifier.verify_root_consistency(self.root)
                if not full["ok"]:
                    probe_failures.extend(full["errors"][:5])
                    break
            time.sleep(0.001)

        ta.join(timeout=30)
        tb.join(timeout=30)
        self.assertFalse(ta.is_alive(), "worker-A 超时未结束（疑似死锁）")
        self.assertFalse(tb.is_alive(), "worker-B 超时未结束（疑似死锁）")
        self.assertEqual(self.worker_errors, [], "工作线程异常: " + "\n".join(self.worker_errors))
        self.assertEqual(probe_failures, [], "运行期间可读性/一致性被破坏")
        self.assertGreater(probes, 20, f"完整探针次数过少: {probes}")
        self.assertGreater(lockfree_core_probes, 20)

        # 三类操作都必须真实发生并交错。
        self.assertGreater(op_counts["ingest"], 0)
        self.assertGreater(op_counts["revoke"], 0)
        self.assertGreater(op_counts["budget"], 0)

        # 最终状态：管理器内置校验 + 独立磁盘核验都必须通过。
        self.mgr.verify_readable()
        final = disk_verifier.verify_root_consistency(self.root)
        self.assertTrue(final["ok"], "\n".join(final["errors"]))

        # 所有永久承诺样本在最终状态仍可读。
        with self.mgr.lock:
            errs = self.mgr.read_errors(self.mgr.manifest, mandatory_only=True)
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
