"""端到端可复现演示：产出 artifacts/ 下的报告与可独立核验结论。

运行：``python -m retainer demo --artifacts artifacts``（通常由 ``python run_all.py`` 调用）。
所有数据均为合成数据。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import EXIT_POWER_LOSS, POINT_AFTER_MANIFEST_BEFORE_POINTER
from .manager import RetentionManager, SimulatedPowerLoss, whole_sample_cost
from .metadata import MetadataCatalog, TenantRollupService, generate_metadata_entries
from .risksel import Item, brute_force_select
from .synthetic import deterministic_samples, make_sample
from .util import setup_utf8_stdio
from . import verifier as disk_verifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_FILE = PROJECT_ROOT / "retainer" / "verifier.py"


def _run(args: list[Any], timeout: int = 180) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable] + [str(a) for a in args],
        cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )


def _budget_story(art: Path, report: dict[str, Any]) -> None:
    vault = art / "demo-vault"
    if vault.exists():
        shutil.rmtree(vault)
    mgr = RetentionManager.initialize(vault, budget_bytes=9000)

    promised = deterministic_samples(3, prefix="P", seed=301, tenants=["legal"],
                                    batch_id="B-EXT")
    held = deterministic_samples(2, prefix="E", seed=302, tenants=["legal"],
                                 batch_id="B-EVID")
    optional = deterministic_samples(8, prefix="R", seed=303, tenants=["tenant-x"],
                                     batch_id="B-RISK")
    hot = deterministic_samples(2, prefix="HOT", seed=304, tenants=["malware"],
                                high_risk=True, batch_id="B-HOT")

    mgr.ingest_samples(promised, batch_id="B-EXT")
    mgr.promise_batch_snapshot("B-EXT", snapshot_id="SNAP-EXTERNALLY-PROMISED")
    mgr.ingest_samples(held, batch_id="B-EVID")
    for s in held:
        mgr.add_hold(s["id"], case_id="CASE-OPEN-EVIDENCE")
    mgr.ingest_samples(optional, batch_id="B-RISK")
    mgr.ingest_samples(hot, batch_id="B-HOT")

    mgr.set_budget(1500)  # 磁盘预算收缩

    m = mgr.manifest
    items = [Item(s["id"], whole_sample_cost(s), s["risk"])
             for s in m["samples"].values()
             if s["id"] not in set(m["selection"]["mandatory_ids"])]
    expect = brute_force_select(items, max(0, m["budget_bytes"]
                                          - m["selection"]["mandatory_cost"]))
    disk_ok = disk_verifier.verify_root_consistency(vault)["ok"]

    report["budget_story"] = {
        "budget_bytes": 1500,
        "mandatory_ids": m["selection"]["mandatory_ids"],
        "mandatory_cost": m["selection"]["mandatory_cost"],
        "remaining_budget": m["selection"]["remaining_budget"],
        "chosen_optional_ids": m["selection"]["chosen_optional_ids"],
        "chosen_optional_risk": m["selection"]["chosen_optional_risk"],
        "independent_bruteforce_risk": expect.total_value,
        "matches_bruteforce": list(m["selection"]["chosen_optional_ids"])
        == list(expect.chosen),
        "total_retained_cost": m["selection"]["total_retained_cost"],
        "disk_verifier_ok": disk_ok,
    }


def _crash_story(art: Path, report: dict[str, Any]) -> None:
    vault = art / "crash-vault"
    if vault.exists():
        shutil.rmtree(vault)
    mgr = RetentionManager.initialize(vault, budget_bytes=8000)
    seed = deterministic_samples(3, prefix="E", seed=11, tenants=["legal"], batch_id="B-G")
    mgr.ingest_samples(seed, batch_id="B-G")
    mgr.add_hold("E0001", case_id="CASE-1")
    mgr.promise_batch_snapshot("B-G", snapshot_id="SNAP-G")

    def hook(point, _m, _ctx):
        if point == POINT_AFTER_MANIFEST_BEFORE_POINTER:
            raise SimulatedPowerLoss("demo injected power loss")

    mgr.fault_hook = hook
    try:
        mgr.set_budget(1234)
        raise RuntimeError("fault hook did not fire")
    except SimulatedPowerLoss:
        pass

    mgr2, rec = RetentionManager.recover(vault)
    rp = art / "demo-restart-report.json"
    mgr2.write_restart_report(rec, rp)

    inproc = disk_verifier.verify_report(vault, rp)

    # 用独立单文件核验器的全新子进程核验。
    proc = _run([VERIFIER_FILE, "--root", vault, "--report", rp])
    verdict = json.loads(proc.stdout) if proc.returncode == 0 else {
        "ok": False, "stdout": proc.stdout, "stderr": proc.stderr}
    (art / "independent-verdict.json").write_text(
        json.dumps(verdict, ensure_ascii=True, indent=2), encoding="utf-8")

    report["crash_story_inproc"] = {
        "rolled_forward": rec["rolled_forward"],
        "final_seq": rec["final_state"]["seq"],
        "inproc_verifier_ok": inproc["ok"],
        "subprocess_verifier_returncode": proc.returncode,
        "subprocess_verifier_ok": bool(verdict.get("ok")),
        "report_path": str(rp),
        "verdict_path": str(art / "independent-verdict.json"),
    }


def _real_subprocess_crash_story(art: Path, report: dict[str, Any]) -> None:
    vault = art / "realcrash-vault"
    if vault.exists():
        shutil.rmtree(vault)
    vault.mkdir(parents=True, exist_ok=True)
    child = _run(["-m", "retainer.cli", "crash-child", "--root", vault,
                  "--exit-code", str(EXIT_POWER_LOSS)])
    info: dict[str, Any] = {"child_returncode": child.returncode,
                           "expected": EXIT_POWER_LOSS}
    if child.returncode != EXIT_POWER_LOSS:
        info["child_stdout"] = child.stdout[-2000:]
        info["child_stderr"] = child.stderr[-2000:]
        report["real_subprocess_crash"] = info
        return

    rec = _run(["-m", "retainer.cli", "recover", "--root", vault,
                "--report-out", art / "realcrash-restart-report.json"])
    info["recover_returncode"] = rec.returncode
    ver = _run([VERIFIER_FILE, "--root", vault,
                "--report", art / "realcrash-restart-report.json"])
    info["verifier_returncode"] = ver.returncode
    try:
        info["verifier_ok"] = bool(json.loads(ver.stdout).get("ok"))
    except Exception:  # noqa: BLE001
        info["verifier_ok"] = False
        info["verifier_stderr"] = ver.stderr[-1000:]
    report["real_subprocess_crash"] = info


def _metadata_story(report: dict[str, Any]) -> None:
    entries = generate_metadata_entries(50_000, 100)
    cat = MetadataCatalog(entries)
    svc = TenantRollupService(cat)
    svc.recompute_all()
    baseline_reads = cat.dao.total_reads

    cat.change_risk(8, 999)  # tenant-007
    before = dict(cat.dao.reads_by_tenant)
    done = svc.recompute_dirty()
    post_reads = cat.dao.total_reads

    unrelated_zero = all(
        cat.dao.reads_by_tenant[t] - before[t] == 0
        for t in cat.dao.tenants if t != "tenant-007"
    )
    report["metadata_50k"] = {
        "entries": len(entries),
        "tenants": len(cat.dao.tenants),
        "initial_real_reads": baseline_reads,
        "after_change_recomputed_tenants": done,
        "post_change_real_reads_delta": post_reads - baseline_reads,
        "changed_tenant_read_delta": cat.dao.reads_by_tenant["tenant-007"]
        - before["tenant-007"],
        "unrelated_tenants_zero_new_reads": unrelated_zero,
    }


def _write_summary(art: Path, report: dict[str, Any]) -> None:
    bs = report["budget_story"]
    cs = report["crash_story_inproc"]
    rs = report["real_subprocess_crash"]
    md = report["metadata_50k"]
    all_green = all([
        bs["matches_bruteforce"], bs["disk_verifier_ok"],
        cs["inproc_verifier_ok"], cs["subprocess_verifier_ok"],
        rs.get("child_returncode") == EXIT_POWER_LOSS,
        rs.get("recover_returncode") == 0, rs.get("verifier_returncode") == 0,
        rs.get("verifier_ok"),
        md["initial_real_reads"] == 50_000,
        md["post_change_real_reads_delta"] == 500,
        md["unrelated_tenants_zero_new_reads"],
    ])
    report["all_green"] = all_green

    lines = [
        "# 保留器端到端演示报告（全部合成数据）",
        "",
        f"总体结论：{'✅ 全部核验通过' if all_green else '❌ 存在失败项'}",
        "",
        "## 1. 预算收缩下的精确总风险组合",
        f"- 预算 {bs['budget_bytes']}；义务+承诺固定样本 {bs['mandatory_ids']}",
        f"- 强制代价 {bs['mandatory_cost']}，剩余预算 {bs['remaining_budget']}",
        f"- 精确最优可选样本 {bs['chosen_optional_ids']}，"
        f"总风险 {bs['chosen_optional_risk']}",
        f"- 独立暴力重算总风险 {bs['independent_bruteforce_risk']}，"
        f"一致：{bs['matches_bruteforce']}",
        f"- 磁盘独立核验：{bs['disk_verifier_ok']}",
        "",
        "## 2. 断电注入（清单已写、指针未切）+ 重启独立核验",
        f"- 进程内注入后前滚：{cs['rolled_forward']}，最终 seq={cs['final_seq']}",
        f"- 进程内核验器：{cs['inproc_verifier_ok']}",
        f"- 全新子进程运行单文件 verifier.py，退出码 "
        f"{cs['subprocess_verifier_returncode']}，ok={cs['subprocess_verifier_ok']}",
        f"- 重启报告：`{cs['report_path']}`",
        "",
        "## 3. 真实 os._exit 子进程断电",
        f"- crash-child 退出码 {rs.get('child_returncode')}（期望 {EXIT_POWER_LOSS}）",
        f"- recover 退出码 {rs.get('recover_returncode')}，"
        f"独立核验退出码 {rs.get('verifier_returncode')}，ok={rs.get('verifier_ok')}",
        "",
        "## 4. 五万元数据条目 / 租户增量 / 真实访问量",
        f"- 条目 {md['entries']}，租户 {md['tenants']}",
        f"- 首次全量真实读取 {md['initial_real_reads']}（恰为 50000）",
        f"- 改 tenant-007 一条后，仅重算 {md['after_change_recomputed_tenants']}",
        f"- 变更后真实读取增量 {md['post_change_real_reads_delta']}（恰为 500）",
        f"- 无关租户新增真实读取为 0：{md['unrelated_tenants_zero_new_reads']}",
        "",
        "> 两工作线程撤销/预算/入库交错与连续可读探针、短序列穷举、容量边界/"
        "等价值/重复样本等证明由 `python run_all.py` 的 unittest 套件执行。",
        "",
    ]
    (art / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def main(artifacts: str = "artifacts") -> int:
    setup_utf8_stdio()
    art = Path(artifacts)
    if not art.is_absolute():
        art = PROJECT_ROOT / art
    art.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {}
    _budget_story(art, report)
    _crash_story(art, report)
    _real_subprocess_crash_story(art, report)
    _metadata_story(report)
    _write_summary(art, report)

    (art / "demo-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[demo] SUMMARY -> {art / 'SUMMARY.md'}")
    print(f"[demo] report  -> {art / 'demo-report.json'}")
    return 0 if report.get("all_green") else 1


if __name__ == "__main__":
    raise SystemExit(main())
