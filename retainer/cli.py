"""``python -m retainer`` 命令行：recover / verify / crash-child / demo。"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path

from . import EXIT_POWER_LOSS, POINT_AFTER_MANIFEST_BEFORE_POINTER
from .manager import RetentionManager
from .synthetic import deterministic_samples
from .util import setup_utf8_stdio
from . import verifier as verifier_mod


def _cmd_recover(args: argparse.Namespace) -> int:
    mgr, report = RetentionManager.recover(args.root)
    out = Path(args.report_out) if args.report_out else None
    path = mgr.write_restart_report(report, out)
    print(json.dumps({
        "ok": True,
        "report": str(path),
        "seq": report["final_state"]["seq"],
        "rolled_forward": report["rolled_forward"],
        "recovery_action": report["recovery_action"],
        "mandatory_ids": report["final_state"]["mandatory_ids"],
    }, ensure_ascii=True, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    if args.report:
        out = verifier_mod.verify_report(args.root, args.report)
    else:
        out = verifier_mod.verify_root_consistency(args.root)
    print(json.dumps(out, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if out["ok"] else 1


def _cmd_crash_child(args: argparse.Namespace) -> int:
    """真实子进程断电演示：在“清单已写、指针未切”处 os._exit。

    父进程用子进程退出码 + 磁盘状态判断断电是否被准确注入。
    """
    root = Path(args.root)
    mgr = RetentionManager.initialize(root, budget_bytes=args.budget)

    # 先建立两类不可推卸义务：未解除 hold + 已对外承诺批次快照。
    genesis = deterministic_samples(3, prefix="E", seed=11,
                                   tenants=["tenant-legal"], batch_id="B-GENESIS")
    mgr.ingest_samples(genesis, batch_id="B-GENESIS")
    mgr.add_hold("E0001", case_id="CASE-EVIDENCE-1", reason="open legal hold")
    mgr.promise_batch_snapshot("B-GENESIS", snapshot_id="SNAP-GENESIS",
                               label="externally-promised-batch")

    def hook(point: str, _mgr: RetentionManager, _ctx: dict) -> None:
        if point == POINT_AFTER_MANIFEST_BEFORE_POINTER:
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            finally:
                # 立即终止，不执行 finally/atexit/缓冲刷新，模拟真实断电。
                os._exit(args.exit_code)

    mgr.fault_hook = hook

    hot = deterministic_samples(1, prefix="HOT", start_index=1, seed=991,
                               tenants=["tenant-malware"], high_risk=True,
                               batch_id="B-HOT")
    # 下面应在提交临界点被 os._exit 终止，不会正常返回。
    mgr.ingest_samples(hot, batch_id="B-HOT")
    # 若执行到这里说明注入失败：
    print("CRASH_INJECTION_DID_NOT_FIRE", file=sys.stderr)
    return 20


def _cmd_demo(args: argparse.Namespace) -> int:
    from . import demo as demo_mod
    return demo_mod.main(args.artifacts)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="retainer", description="隔离样本保留器（标准库）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser("recover", help="重启恢复并写重启报告")
    p_rec.add_argument("--root", required=True)
    p_rec.add_argument("--report-out", default=None)
    p_rec.set_defaults(func=_cmd_recover)

    p_ver = sub.add_parser("verify", help="独立核验保险库/重启报告")
    p_ver.add_argument("--root", required=True)
    p_ver.add_argument("--report", default=None)
    p_ver.set_defaults(func=_cmd_verify)

    p_crash = sub.add_parser("crash-child", help=argparse.SUPPRESS)
    p_crash.add_argument("--root", required=True)
    p_crash.add_argument("--exit-code", type=int, default=EXIT_POWER_LOSS)
    p_crash.add_argument("--budget", type=int, default=20000)
    p_crash.set_defaults(func=_cmd_crash_child)

    p_demo = sub.add_parser("demo", help="运行端到端演示并写 artifacts 报告")
    p_demo.add_argument("--artifacts", default="artifacts")
    p_demo.set_defaults(func=_cmd_demo)
    return ap


def main(argv: list[str] | None = None) -> int:
    setup_utf8_stdio()
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        return int(args.func(args))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        print(json.dumps({"ok": False, "error": repr(exc)}, ensure_ascii=True),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
