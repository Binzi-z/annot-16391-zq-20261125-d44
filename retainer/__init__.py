"""隔离样本保留器（仅依赖 Python 3.12 标准库）。

模块划分：
- risksel:   全样本原子的精确“总风险优先”组合选择（0/1 背包，精确最优）。
- synthetic: 全部合成数据生成（样本/分片/租户元数据），确定性种子。
- metadata:  50,000 条元数据 + 按租户增量重算 + 真实访问计数 DAO。
- manager:   磁盘保险库、义务/承诺固定、预算重规划、安全回收、断电注入与恢复。
- verifier:  完全独立的只读核验器（只 import 标准库，可作为脚本/子进程运行）。
- cli:       recover / verify / crash-child / demo 命令行入口。
"""

__version__ = "1.0.0"

# 模拟“断电”子进程使用的退出码（避开常见 0/1/2）。
EXIT_POWER_LOSS = 73

# 断电注入点名称：清单已落盘、指针尚未切换。
POINT_AFTER_MANIFEST_BEFORE_POINTER = "after_manifest_write_before_pointer_switch"
