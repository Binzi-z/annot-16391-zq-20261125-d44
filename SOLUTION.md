# 隔离样本保留器 — 方案、正确性论证与验证指南

仅用 **Python 3.12 标准库**、可在 **原生 Windows** 运行的合成实现。一条命令跑完所有证明：

```bat
python run_all.py
```

或分步：

```bat
python -m unittest discover -s tests -t . -v
python -m retainer demo
```

所有样本、分片、风险分、租户元数据均为确定性合成数据，无任何真实样本/网络/第三方依赖。

---

## 1. 题面约束如何落到代码

| 要求 | 实现位置 | 证明/测试 |
| --- | --- | --- |
| 义务样本始终可读 | `manager.py`：义务 = 未解除 hold ∪ 已承诺快照成员，强制 `mandatory ⊆ retained`，提交前先补齐并哈希校验全部分片 | `test_concurrency.py` 两线程交错 + 主线程连续探针；`test_vault_budget.py` |
| 已对外承诺的本批快照始终可读 | `promise_batch_snapshot()` 写外部回执 `receipts/*.json` 并把成员永久并入义务集合 | 同上 + 核验器核对快照根哈希/回执 |
| 剩余预算内**精确总风险优先**组合 | `risksel.py` 精确 0/1 背包（暴力神谕 + DP），**不是**风险密度贪心 | `test_selector_exhaustive.py` 11 万+ 穷举用例、随机交叉、反“密度贪心”例 |
| 不能把分片当作可单独保留的完整样本 | 样本代价 = `sum(全部分片 size)`；选择/保留/回收/核验单位永远是完整 `sample_id` | `test_shards_are_not_independent_items`、核验器 `shard_atomicity_*`、删任一分片即判失败 |
| 两工作线程测试撤销保留/改预算/入库交错 | `tests/test_concurrency.py` 恰好两个 worker 线程执行三类操作，RLock 串行化提交临界区 | 连续可读性探针 + 周期全量核验 + 无锁永久核心探针 |
| 写清单后、切指针前断电可注入 | 常量注入点 `after_manifest_write_before_pointer_switch`；进程内抛 `SimulatedPowerLoss`，子进程 `os._exit(73)` 真断电 | `test_crash_recovery.py` 两种测试 |
| 重启报告可独立核验 | `recover()` 前滚合法前置清单并写报告；`verifier.py` **只用标准库、不 import 包内模块**，可作为单文件/子进程运行 | 测试用全新子进程跑 `python retainer/verifier.py --root … --report …` 并断言退出码 0 |
| 短序列穷举容量边界/等价值/重复样本 | `test_selector_exhaustive.py` | 小字母表 0..5 全长 × `0..total_cost+1` 全容量；显式边界；等价值字典序；重复样本计数 |
| 5 万元数据，变更前后无关租户不重算 + 真实访问量 | `metadata.py` 计数 DAO（每读一条 +1、按租户分账）+ 脏租户增量聚合 | `test_metadata_tenants.py`：首算恰好 50000 次真实读取；改 1 条后仅该租户重扫 500 条，其余 99 租户增量为 0 |

---

## 2. 磁盘布局与提交协议

```
<vault>/
  pointer.json                 # 原子切换的提交指针 -> 当前 manifest（含其自哈希）
  manifests/m-000000.json ...  # 不可变、自哈希、带 parent 链的清单
  objects/samples/<sample_id>/shard-000.bin ...
  receipts/<snapshot_id>.json  # 对外承诺回执（逐样本内容哈希 + 快照根）
  reports/restart-report-latest.json
```

每次变更在同一把 `RLock` 内严格按序执行
（`RetentionManager._finalize_and_commit`）：

1. 深拷贝当前清单，应用领域变更；
2. 重算 **义务集合 → 强制代价 → 剩余预算 → 精确最优可选组合 → retained**；
3. 对新清单全部 retained 样本补齐分片：缺失才按合成种子确定性重建；
   已存在但 SHA-256 不符立即报 `IntegrityError`，**绝不静默覆盖证据**；
4. 写不可变、规范 JSON、自哈希的新清单并 `fsync`；
5. **★注入点★** `after_manifest_write_before_pointer_switch`
   （测试可在此抛异常或 `os._exit`）；
6. `pointer.json.tmp + fsync + os.replace` **原子切换指针**——指针即提交点；
7. 切换成功后才回收“新清单 retained 之外”的**整样本目录**（带 Windows 重试删除）；
8. 再次对新清单做整样本可读性 + 分片哈希校验。

### 为什么“每个时刻义务/承诺样本都可读”

- 规划器保证义务集合是 retained 的子集，且这些分片在第 3 步已落盘并通过哈希校验；
- 回收只可能删除“在**新指针清单**中已不属于 retained”的整样本。只要一个样本在新清单里仍是义务/已承诺，它就仍在 retained 中，第 7 步显式跳过，且 `_reclaim` 内还有一道“仍负义务却要删”的安全闸门；
- 指针原子切换。读者要么看到旧指针/旧清单——此时第 7 步针对新清单的回收尚未发生或只会删新清单的非 retained 样本，旧义务样本的分片仍在；要么看到新指针/新清单——其义务集合与磁盘状态一致；
- 并发测试中的核验探针与提交/回收互斥（取同一把锁），因此探针观察到的每个状态都是上述协议下的一致提交点；另有一个**完全无锁**探针持续哈希“永不撤销的对外承诺批次”的分片，覆盖真实并行读；
- 断电落在第 5 步时：旧指针、旧清单、旧分片完好；新清单是一份完整、自哈希正确、parent 连续且其 retained 对象已齐全的“前置清单”。重启 `recover()` 独立校验后沿 parent 链**前滚**并把指针切到它，再执行回收与复核。无论前滚与否，义务/承诺样本都可读。

> 说明：本实现采用“合法前置清单校验后前滚”。因为清单在注入点之前已完整落盘且对象已校验，前滚不会破坏任何不变量；核验器会独立复核报告中的前滚目标、前置清单哈希与全部可读性/最优性结论。

---

## 3. 精确总风险选择（分片原子性的关键点）

一个样本含若干分片，大小 `s0…sk-1`，其保留代价是

```
cost(sample) = Σ si          # 绝不是某个“高分片”的大小
value(sample) = risk(sample)
```

先预留强制集合代价 `C_mand`，剩余容量 `cap = max(0, budget - C_mand)`，
对全部非强制完整样本求

```
max Σ risk_i  s.t.  Σ cost_i ≤ cap     （精确 0/1 背包）
```

- `risksel.brute_force_select`：枚举 `2^n` 子集的独立神谕；
- `risksel.dp_select`：按“精确代价”建状态的滚动 DP，O(n·cap)；
- `exact_select` 按规模自动选择，二者使用同一确定性平局规则：
  1. 总风险更大；2. 总字节更小；3. ID 升序元组字典序更小。

当义务代价超过预算时：`remaining < 0`、`cap = 0`、记录 `deficit_bytes` 与
`budget_feasible=False`，但**义务样本仍被强制保留且可读**——证据义务优先于预算，
缺口被显式上报而不是偷偷删证据。

核验器 `verifier.py` 内置**另写的一份**容量维 DP（n 小时再用自带暴力交叉验证），
从磁盘清单重算最优总风险，断言落盘选择恰好最优，并复核预算算术与可行性。

---

## 4. 独立核验器与重启报告

`retainer/verifier.py` **只 import 标准库**（argparse/hashlib/json/sys/pathlib/typing），
不依赖包内任何模块，可被单独拷出审计：

```bat
python retainer\verifier.py --root <vault> --report <report.json>
echo %ERRORLEVEL%     & REM 0 = 全部通过，1 = 有不符
python retainer\verifier.py --root <vault>
```

它独立重算并逐项给出检查结论：指针存在/JSON/路径安全、清单自哈希、指针哈希一致、
seq 一致、schema、parent 链、`size_bytes==Σ分片size`、义务⊆retained、
快照根哈希与回执、义务与全部 retained 样本的分片存在性/大小/SHA-256/整样本内容哈希、
预算与缺口、选择可行性、**独立最优性**、整样本原子性，以及报告字段与磁盘重算值、
报告所列“已写未切”清单是否真实存在且哈希正确。

测试用 `subprocess` 运行一个**全新解释器进程**直接执行该文件来核验报告，
以此证明“独立可核验”，而不是自调用同一份代码。

---

## 5. 50,000 条元数据：租户增量与真实访问量

`metadata.py` 的 `CountingMetadataDAO` 是读取唯一收口：生成器 `scan_tenant`
每 `yield` 一条就 `total_reads += 1` 并按租户分账。聚合必须真正消费这些条目，
因此计数无法被“声称缓存命中”绕过。

- 100 租户 × 500 条 = 50,000；
- 首次 `recompute_all()`：真实读取恰好 50,000，每租户 500，重算次数 1；
- 修改 `tenant-007` 的 1 条风险 → 只把该租户标脏 → `recompute_dirty()` 仅重算它，
  真实读取增量恰好 500；其余 99 租户访问增量 0、摘要身份与重算次数不变；
- 被改租户的新摘要与绕过 DAO/缓存的独立神谕 `oracle_tenant_identity` 一致。

---

## 6. Windows 兼容性要点

- 全部路径用 `pathlib`；子进程用 `sys.executable` 并显式设置
  `PYTHONPATH/PYTHONUTF8/PYTHONIOENCODING=utf-8`；
- 原子替换用 `os.replace`，并对 Windows `WinError 5/32/33` 共享冲突做有限退避重试；
- 目录回收对只读位/杀软或索引器短暂占用做去只读 + 重试；
- 控制台入口统一 `reconfigure(encoding="utf-8", errors="replace")`；
- 仅依赖标准库；无需 C 编译器、无需 sqlite。

## 7. 退出码

- `run_all.py`：全部测试与演示核验通过 → 0，否则 1；
- `verifier.py`：核验通过 → 0，发现任何不符 → 1；
- 模拟断电子进程：在注入点 `os._exit(73)`（`retainer.EXIT_POWER_LOSS`）。
