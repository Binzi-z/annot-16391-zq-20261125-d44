# 隔离样本的受限保留与审计承诺

题面见 [`task/PROMPT.txt`](task/PROMPT.txt)。完整方案、正确性论证与验证指南见
[`SOLUTION.md`](SOLUTION.md)。

## 一键运行（原生 Windows / Python 3.12，仅标准库）

```bat
python run_all.py
```

它会：

1. 运行全部 `unittest`：
   - 短序列**穷举**容量边界 / 等价值 / 重复样本（DP 对暴力神谕，11 万+ 用例）；
   - **两个工作线程**交错执行 撤销保留 / 更改预算 / 样本入库，主线程连续核验“义务样本 + 已承诺快照始终可读”；
   - “写清单后、切指针前”**断电注入**：进程内异常 + 真实 `os._exit(73)` 子进程，随后重启恢复，并用**全新子进程运行独立单文件核验器**核验重启报告；
   - 50,000 条元数据 / 100 租户：证明只重算被变更租户（真实读取增量恰为 500），无关租户零重算、零新增访问；
   - 磁盘预算收缩、精确最优组合、整样本分片原子性、核验器能抓篡改/缺片。
2. 跑端到端演示，在 `artifacts/` 生成 `SUMMARY.md`、`demo-report.json`、
   重启报告与 `independent-verdict.json`（该目录被 `.gitignore` 忽略，运行后生成）。

## 常用命令

```bat
python -m unittest discover -s tests -t . -v
python scratch_selftest.py
python -m retainer demo
python -m retainer recover --root <vault> --report-out <vault>\restart-report.json
python retainer\verifier.py --root <vault> --report <vault>\restart-report.json
```

## 目录

```
retainer/
  risksel.py     # 精确总风险 0/1 选择（暴力神谕 + DP，确定性平局），整样本代价
  synthetic.py   # 确定性合成样本/分片字节
  metadata.py    # 50k 元数据 + 按租户增量重算 + 真实访问计数 DAO
  util.py        # 规范 JSON / 自哈希 / fsync / Windows 友好原子替换
  manager.py     # 保险库、提交协议、断电注入、回收、恢复与重启报告
  verifier.py    # ★独立核验器：仅标准库，可直接作为单文件脚本/子进程运行
  cli.py         # recover / verify / crash-child / demo
  demo.py        # 端到端演示与 artifacts 报告
tests/           # 上述五类 unittest
run_all.py       # 一键测试 + 演示
```

所有数据均为合成数据；无第三方依赖、无网络访问。
