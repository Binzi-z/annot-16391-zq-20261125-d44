#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键验证入口（Windows 原生 + Python 3.12 标准库）。

    python run_all.py

依次执行：
  1) unittest 全套：短序列穷举（容量边界/等价值/重复样本）、两工作线程交错 +
     连续可读探针、断电注入 + 真实 os._exit 子进程重启独立核验、
     50,000 元数据条目的租户不重算与真实访问量、磁盘预算/分片原子性/核验器牙齿；
  2) 端到端演示并在 artifacts/ 产出 SUMMARY.md、demo-report.json 与可独立核验的报告。

任一步失败则以非 0 退出。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from retainer.util import setup_utf8_stdio  # noqa: E402


def run_tests() -> bool:
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=str(PROJECT_ROOT / "tests"),
        pattern="test_*.py",
        top_level_dir=str(PROJECT_ROOT),
    )
    runner = unittest.TextTestRunner(verbosity=2, failfast=False)
    result = runner.run(suite)
    return result.wasSuccessful()


def run_demo() -> int:
    from retainer.demo import main as demo_main
    return demo_main(str(PROJECT_ROOT / "artifacts"))


def main() -> int:
    setup_utf8_stdio()
    print("=" * 78)
    print("隔离样本保留器：全套正确性/并发/崩溃恢复/规模核验")
    print(f"Python {sys.version.split()[0]}  @  {sys.executable}")
    print("=" * 78)

    tests_ok = run_tests()
    print("\n" + "=" * 78)
    print(f"单元/集成测试结果：{'PASS' if tests_ok else 'FAIL'}")
    print("=" * 78 + "\n")

    demo_code = run_demo()
    print("\n" + "=" * 78)
    print(f"演示与产物核验：{'PASS' if demo_code == 0 else 'FAIL'}")
    print("=" * 78)

    if tests_ok and demo_code == 0:
        print("\nALL CHECKS PASSED ✅")
        return 0
    print("\nSOME CHECKS FAILED ❌", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
