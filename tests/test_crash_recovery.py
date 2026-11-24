import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from retainer import EXIT_POWER_LOSS, POINT_AFTER_MANIFEST_BEFORE_POINTER
from retainer.manager import RetentionManager, SimulatedPowerLoss
from retainer.synthetic import deterministic_samples
from retainer import verifier as disk_verifier

VERIFIER_FILE = PROJECT_ROOT / "retainer" / "verifier.py"


def run_subprocess(args, timeout=180):
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + existing if existing else "")
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable] + [str(a) if isinstance(a, Path) else a for a in args],
        cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )


class SimulatedCrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="retainer_crash_")
        self.root = Path(self._tmp.name)
        self.mgr = RetentionManager.initialize(self.root, budget_bytes=8000)
        seed = deterministic_samples(3, prefix="E", seed=11,
                                     tenants=["tenant-legal"], batch_id="B-G")
        self.mgr.ingest_samples(seed, batch_id="B-G")
        self.mgr.add_hold("E0001", case_id="CASE-1")
        self.mgr.promise_batch_snapshot("B-G", snapshot_id="SNAP-G")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp.name, ignore_errors=True)

    def test_injected_after_manifest_before_pointer_then_recover_and_verify(self):
        old_seq = self.mgr.manifest["seq"]
        fires = {"n": 0}

        def hook(point, _m, _ctx):
            if point == POINT_AFTER_MANIFEST_BEFORE_POINTER and fires["n"] == 0:
                fires["n"] += 1
                raise SimulatedPowerLoss("inject power loss")

        self.mgr.fault_hook = hook
        with self.assertRaises(SimulatedPowerLoss):
            self.mgr.set_budget(1234)
        self.assertEqual(fires["n"], 1)

        # 指针仍停在旧提交；新清单已完整落盘（断电窗口的精确刻画）。
        pointer = json.loads((self.root / "pointer.json").read_text(encoding="utf-8"))
        self.assertEqual(pointer["seq"], old_seq)
        staged = self.root / f"manifests/m-{old_seq + 1:06d}.json"
        self.assertTrue(staged.exists(), "注入点之后清单文件必须已经写入")

        # 旧指针状态在“断电后、重启前”就必须可独立核验通过。
        before = disk_verifier.verify_root_consistency(self.root)
        self.assertTrue(before["ok"], "\n".join(before["errors"]))

        # 重启：新对象 recover，前滚前置清单并写报告。
        mgr2, report = RetentionManager.recover(self.root)
        self.assertTrue(report["rolled_forward"])
        self.assertEqual(report["final_state"]["seq"], old_seq + 1)
        self.assertEqual(report["final_state"]["budget_bytes"], 1234)
        report_path = self.root / "restart-report.json"
        mgr2.write_restart_report(report, report_path)

        inproc = disk_verifier.verify_report(self.root, report_path)
        self.assertTrue(inproc["ok"], "\n".join(inproc["errors"]))

        # 关键：用“直接运行单文件 verifier.py 的全新子进程”独立核验报告。
        proc = run_subprocess([
            VERIFIER_FILE, "--root", self.root, "--report", report_path,
        ])
        self.assertEqual(proc.returncode, 0,
                         msg=f"独立核验子进程失败\nSTDOUT={proc.stdout}\nSTDERR={proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])

    def test_report_tampering_is_detected(self):
        mgr2, report = RetentionManager.recover(self.root)
        rp = self.root / "report.json"
        mgr2.write_restart_report(report, rp)
        bad = json.loads(rp.read_text(encoding="utf-8"))
        bad["final_state"]["budget_bytes"] = 999_999_999  # 与磁盘不符
        rp.write_text(json.dumps(bad), encoding="utf-8")
        res = disk_verifier.verify_report(self.root, rp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("report_field[budget_bytes]" in e for e in res["errors"]))


class RealSubprocessPowerLossTests(unittest.TestCase):
    def test_real_os_exit_between_manifest_and_pointer(self):
        with tempfile.TemporaryDirectory(prefix="retainer_realcrash_",
                                         ignore_cleanup_errors=True) as td:
            root = Path(td) / "vault"
            root.mkdir()

            # 1) 子进程建立义务/承诺后，在注入点 os._exit(73) 模拟真实断电。
            child = run_subprocess([
                "-m", "retainer.cli", "crash-child", "--root", root,
                "--exit-code", str(EXIT_POWER_LOSS),
            ])
            self.assertEqual(child.returncode, EXIT_POWER_LOSS,
                             msg=f"child stdout={child.stdout}\nstderr={child.stderr}")

            pointer = json.loads((root / "pointer.json").read_text(encoding="utf-8"))
            self.assertEqual(pointer["seq"], 3, "断电时指针必须仍停在承诺快照提交 seq=3")
            self.assertTrue((root / "manifests/m-000004.json").exists(),
                            "热样本清单必须已写入但未被指针提交")

            # 2) 断电后尚未重启：直接运行独立核验器（无报告）核验最后提交状态。
            pre = run_subprocess([VERIFIER_FILE, "--root", root])
            self.assertEqual(pre.returncode, 0,
                             msg=f"断电后旧状态不可读\n{pre.stdout}\n{pre.stderr}")
            self.assertTrue(json.loads(pre.stdout)["ok"])

            # 3) 全新进程执行重启恢复并生成报告。
            rec = run_subprocess([
                "-m", "retainer.cli", "recover", "--root", root,
                "--report-out", root / "restart-report.json",
            ])
            self.assertEqual(rec.returncode, 0,
                             msg=f"recover 失败\n{rec.stdout}\n{rec.stderr}")
            rec_info = json.loads(rec.stdout)
            self.assertTrue(rec_info["rolled_forward"])

            # 4) 第三个全新进程：单文件标准库核验器独立核验重启报告。
            ver = run_subprocess([
                VERIFIER_FILE, "--root", root,
                "--report", root / "restart-report.json",
            ])
            self.assertEqual(ver.returncode, 0,
                             msg=f"独立报告核验失败\n{ver.stdout}\n{ver.stderr}")
            verdict = json.loads(ver.stdout)
            self.assertTrue(verdict["ok"], msg=json.dumps(verdict["errors"], indent=2))

            # 永久承诺快照三个样本确实仍在最终 mandatory 集合中。
            facts = verdict["facts"]
            for sid in ("E0001", "E0002", "E0003"):
                self.assertIn(sid, facts["mandatory_ids"])


class VerifierTeethTests(unittest.TestCase):
    def _vault(self, budget=20000):
        td = tempfile.TemporaryDirectory(prefix="retainer_teeth_",
                                        ignore_cleanup_errors=True)
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        mgr = RetentionManager.initialize(root, budget_bytes=budget)
        ss = deterministic_samples(3, prefix="T", seed=7, batch_id="B-T")
        mgr.ingest_samples(ss, batch_id="B-T")
        mgr.add_hold("T0001", case_id="C")
        return root, mgr

    def test_detects_corrupted_shard_hash(self):
        root, mgr = self._vault()
        sid = "T0001"
        shard = next((root / "objects" / "samples" / sid).glob("shard-*.bin"))
        data = bytearray(shard.read_bytes())
        data[0] ^= 0xFF
        shard.write_bytes(bytes(data))  # 等长翻转，破坏哈希而非大小
        res = disk_verifier.verify_root_consistency(root)
        self.assertFalse(res["ok"])
        self.assertTrue(any("哈希不符" in e for e in res["errors"]), res["errors"])

    def test_detects_missing_shard(self):
        root, mgr = self._vault()
        sid = "T0001"
        shard = next((root / "objects" / "samples" / sid).glob("shard-*.bin"))
        shard.unlink()
        res = disk_verifier.verify_root_consistency(root)
        self.assertFalse(res["ok"])
        self.assertTrue(any("缺失分片" in e for e in res["errors"]), res["errors"])

    def test_clean_vault_passes(self):
        root, mgr = self._vault()
        res = disk_verifier.verify_root_consistency(root)
        self.assertTrue(res["ok"], "\n".join(res["errors"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
