"""磁盘隔离保险库 + 保留管理器。

持久性/提交协议（关键）：

一次变更在同一把 RLock 内按以下顺序进行——
  1. 深拷贝当前已提交清单，应用领域变更（入库/撤销保留/改预算/承诺快照）；
  2. 重新计算 义务集合 → 强制保留代价 → 剩余预算 → 精确总风险最优可选组合；
  3. 对“新清单的全部 retained 样本”补齐分片（缺失才按合成种子重建；
     已存在但哈希不符一律报完整性错误，绝不静默覆盖证据）；
  4. 写不可变、自哈希的新清单 ``manifests/m-NNNNNN.json`` 并 fsync；
  5. ★注入点★ ``after_manifest_write_before_pointer_switch``（可抛异常或 os._exit）；
  6. 原子切换 ``pointer.json``（tmp+fsync+os.replace）——指针即提交点；
  7. 指针切换后才回收“新清单 retained 之外”的样本目录；
  8. 再次对新清单做整样本可读性 + 分片哈希校验。

为什么“每个时刻义务样本与已承诺快照始终可读”：
  - 义务 = 未解除 hold 的样本 ∪ 所有已对外承诺快照内样本；规划器强制
    mandatory ⊆ retained，且它们的分片在第 3 步就已持久、校验通过；
  - 回收（第 7 步）只可能删除“新指针清单里已经不是 retained”的样本。
    一个样本若在新清单中仍是义务/已承诺，就一定在 retained 中，绝不删除；
  - 指针原子切换，外部读者要么看到旧清单（其分片尚未被回收，因为回收发生在
    切换之后且按新清单执行），要么看到新清单（义务集合与磁盘状态一致）；
  - 崩溃在第 5 步：旧指针完好、旧清单与分片完好；新清单是完整且自哈希正确的
    “前置清单”，重启可校验后前滚，或保留旧状态——两种情况下可读性都成立。

分片永远不是可单独保留的单位：Item.cost 取该样本全部分片 size 之和，
retained 只包含完整 sample id；回收/校验都以整样本目录为单位。
"""
from __future__ import annotations

import copy
import json
import re
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import POINT_AFTER_MANIFEST_BEFORE_POINTER
from .risksel import Item, exact_select
from .synthetic import shard_bytes
from .util import (
    SCHEMA_VERSION,
    canonical_bytes,
    durable_atomic_pointer,
    durable_write_new_file,
    hash_manifest,
    setup_utf8_stdio,  # noqa: F401  (re-exported convenience)
    sha256_file,
)

SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

FaultHook = Callable[[str, "RetentionManager", dict[str, Any]], None]


def _rmtree_retry(path: Path, attempts: int = 5) -> None:
    """Windows 健壮删除：去掉只读位并在杀软/索引器短暂占用时重试。"""
    import os
    import stat
    import time

    def make_writable(p: Path) -> None:
        for root, _dirs, files in os.walk(p):
            for name in files:
                try:
                    os.chmod(os.path.join(root, name), stat.S_IWRITE)
                except OSError:
                    pass

    last: Exception | None = None
    for i in range(attempts):
        try:
            if path.exists():
                make_writable(path)
                shutil.rmtree(path, ignore_errors=False)
            return
        except OSError as exc:  # 共享冲突 / 拒绝访问
            last = exc
            time.sleep(0.02 * (i + 1))
    if path.exists():  # 最后兜底：忽略错误删一次，仍存在则抛出。
        shutil.rmtree(path, ignore_errors=True)
    if path.exists() and last is not None:
        raise last


class RetentionError(RuntimeError):
    pass


class IntegrityError(RetentionError):
    pass


class SimulatedPowerLoss(RetentionError):
    """进程内模拟“清单已写、指针未切”的断电（用于确定性测试）。"""


def whole_sample_cost(sample: dict[str, Any]) -> int:
    """以清单内各分片 size 之和为准（不直接信任 size_bytes 字段）。"""
    return int(sum(int(sh["size"]) for sh in sample["shards"]))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RetentionManager:
    def __init__(self, root: Path | str, manifest: dict[str, Any]):
        self.root = Path(root)
        self.manifest = manifest
        self.lock = threading.RLock()
        # 测试可设置：hook(point, mgr, context)；在提交临界区内被调用。
        self.fault_hook: FaultHook | None = None

    # ---------- 路径 ----------
    @property
    def pointer_path(self) -> Path:
        return self.root / "pointer.json"

    @property
    def manifests_dir(self) -> Path:
        return self.root / "manifests"

    @property
    def objects_dir(self) -> Path:
        return self.root / "objects" / "samples"

    @property
    def receipts_dir(self) -> Path:
        return self.root / "receipts"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    def manifest_path(self, file_rel: str) -> Path:
        return self.root / file_rel

    def sample_dir(self, sample_id: str) -> Path:
        if not SAFE_ID_RE.match(sample_id):
            raise RetentionError(f"不安全的 sample id，拒绝用于路径: {sample_id!r}")
        base = self.objects_dir.resolve()
        p = (self.objects_dir / sample_id).resolve()
        if base not in p.parents and p != base:
            raise RetentionError(f"路径越界: {sample_id!r}")
        return p

    # ---------- 初始化 / 打开 ----------
    @classmethod
    def initialize(cls, root: Path | str, budget_bytes: int = 8192) -> "RetentionManager":
        root = Path(root)
        (root / "manifests").mkdir(parents=True, exist_ok=True)
        (root / "objects" / "samples").mkdir(parents=True, exist_ok=True)
        (root / "receipts").mkdir(parents=True, exist_ok=True)
        (root / "reports").mkdir(parents=True, exist_ok=True)
        if (root / "pointer.json").exists():
            raise RetentionError(f"保险库已初始化，pointer.json 已存在: {root}")
        if not isinstance(budget_bytes, int) or budget_bytes < 0:
            raise ValueError("budget_bytes 必须是非负整数")

        genesis: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "seq": 0,
            "parent_sha256": None,
            "created_at_utc": _now_iso(),
            "budget_bytes": int(budget_bytes),
            "samples": {},
            "batches": {},
            "holds": [],
            "snapshots": [],
            "retained": [],
            "selection": None,
        }
        mgr = cls(root, genesis)
        with mgr.lock:
            mgr._finalize_and_commit(genesis, reclaim=False)
        return mgr

    @classmethod
    def open(cls, root: Path | str) -> "RetentionManager":
        root = Path(root)
        pointer = json.loads((root / "pointer.json").read_text(encoding="utf-8"))
        mpath = root / pointer["manifest"]
        manifest = cls._load_manifest_file(mpath, expected_sha=pointer.get("sha256"))
        if manifest["seq"] != pointer.get("seq"):
            raise IntegrityError("pointer.seq 与清单 seq 不一致")
        return cls(root, manifest)

    @staticmethod
    def _load_manifest_file(path: Path, expected_sha: str | None = None) -> dict[str, Any]:
        raw = path.read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
        actual = hash_manifest(manifest)
        if manifest.get("sha256") != actual:
            raise IntegrityError(f"清单自哈希不符: {path}")
        if expected_sha is not None and expected_sha != actual:
            raise IntegrityError(f"指针哈希与清单不符: {path}")
        return manifest

    def read_pointer(self) -> dict[str, Any]:
        return json.loads(self.pointer_path.read_text(encoding="utf-8"))

    # ---------- 规划 ----------
    @staticmethod
    def mandatory_ids_of(manifest: dict[str, Any]) -> list[str]:
        ids: set[str] = set()
        for h in manifest.get("holds", []):
            ids.add(h["sample_id"])
        for sn in manifest.get("snapshots", []):
            ids.update(sn["sample_ids"])
        return sorted(ids)

    def _plan(self, draft: dict[str, Any]) -> None:
        samples: dict[str, Any] = draft["samples"]
        mandatory = self.mandatory_ids_of(draft)
        missing = [sid for sid in mandatory if sid not in samples]
        if missing:
            raise RetentionError(f"义务/快照引用了不存在的样本: {missing}")

        mandatory_cost = sum(whole_sample_cost(samples[sid]) for sid in mandatory)
        mandatory_risk = sum(int(samples[sid]["risk"]) for sid in mandatory)
        budget = int(draft["budget_bytes"])
        remaining = budget - mandatory_cost
        deficit = max(0, -remaining)
        cap = max(0, remaining)

        mandatory_set = frozenset(mandatory)
        items = [
            Item(sid, whole_sample_cost(samples[sid]), int(samples[sid]["risk"]))
            for sid in sorted(samples)
            if sid not in mandatory_set
        ]
        sel = exact_select(items, cap)
        chosen_optional = list(sel.chosen)
        retained = sorted(mandatory_set | frozenset(chosen_optional))

        draft["retained"] = retained
        draft["selection"] = {
            "mandatory_ids": mandatory,
            "mandatory_cost": mandatory_cost,
            "mandatory_risk": mandatory_risk,
            "budget_bytes": budget,
            "remaining_budget": remaining,
            "deficit_bytes": deficit,
            "budget_feasible": mandatory_cost <= budget,
            "optional_candidate_count": len(items),
            "optional_item_whole_sample": True,
            "chosen_optional_ids": chosen_optional,
            "chosen_optional_count": len(chosen_optional),
            "chosen_optional_cost": sel.total_cost,
            "chosen_optional_risk": sel.total_value,
            "total_retained_cost": mandatory_cost + sel.total_cost,
            "optimal_total_risk": mandatory_risk + sel.total_value,
            "algorithm": sel.algorithm,
        }

    # ---------- 分片读写 / 完整性 ----------
    def _write_shard(self, sample: dict[str, Any], shard: dict[str, Any]) -> Path:
        sid = sample["id"]
        d = self.sample_dir(sid)
        d.mkdir(parents=True, exist_ok=True)
        p = d / shard["name"]
        data = shard_bytes(sample.get("gen_seed", "no-seed"), sid,
                           int(shard["index"]), int(shard["size"]))
        if len(data) != int(shard["size"]):
            raise IntegrityError(f"分片长度派生错误: {sid}/{shard['name']}")
        tmp = p.with_name(p.name + ".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            import os
            os.fsync(f.fileno())
        from .util import replace_with_retry
        replace_with_retry(tmp, p)
        return p

    def _ensure_sample_objects(self, sample: dict[str, Any]) -> None:
        """缺失分片才重建；已存在则必须哈希正确，否则报完整性错误。"""
        sid = sample["id"]
        for sh in sample["shards"]:
            p = self.sample_dir(sid) / sh["name"]
            if not p.exists():
                self._write_shard(sample, sh)
            actual = sha256_file(p)
            if actual != sh["sha256"]:
                raise IntegrityError(
                    f"分片哈希不符（疑似篡改/损坏，拒绝静默覆盖）: "
                    f"{sid}/{sh['name']} expected={sh['sha256'][:12]} actual={actual[:12]}"
                )
            if p.stat().st_size != int(sh["size"]):
                raise IntegrityError(f"分片大小不符: {sid}/{sh['name']}")

    def sample_read_errors(self, manifest: dict[str, Any], sample_id: str) -> list[str]:
        """独立、只读地检查一个整样本的全部分片；返回错误描述列表。"""
        errors: list[str] = []
        sample = manifest["samples"].get(sample_id)
        if sample is None:
            return [f"manifest 缺少样本元数据: {sample_id}"]
        try:
            d = self.sample_dir(sample_id)
        except RetentionError as exc:
            return [str(exc)]
        whole = __import__("hashlib").sha256()
        for sh in sample["shards"]:
            p = d / sh["name"]
            if not p.exists():
                errors.append(f"缺失分片: {sample_id}/{sh['name']}")
                continue
            if p.stat().st_size != int(sh["size"]):
                errors.append(f"分片大小不符: {sample_id}/{sh['name']}")
            actual = sha256_file(p)
            if actual != sh["sha256"]:
                errors.append(f"分片哈希不符: {sample_id}/{sh['name']}")
            else:
                with open(p, "rb") as f:
                    while True:
                        buf = f.read(1 << 20)
                        if not buf:
                            break
                        whole.update(buf)
        if not errors:
            if whole.hexdigest() != sample["content_sha256"]:
                errors.append(f"整样本内容哈希不符: {sample_id}")
        return errors

    def read_errors(self, manifest: dict[str, Any] | None = None,
                    sample_id: str | None = None, *,
                    mandatory_only: bool = False) -> list[str]:
        manifest = manifest or self.manifest
        if sample_id is not None:
            return self.sample_read_errors(manifest, sample_id)
        if mandatory_only:
            ids = self.mandatory_ids_of(manifest)
        else:
            ids = list(manifest["retained"])
        errors: list[str] = []
        for sid in ids:
            errors.extend(self.sample_read_errors(manifest, sid))
        return errors

    def verify_readable(self, *, mandatory_only: bool = False) -> None:
        errors = self.read_errors(self.manifest, mandatory_only=mandatory_only)
        if errors:
            raise IntegrityError("可读性校验失败:\n  - " + "\n  - ".join(errors))

    # ---------- 提交流程 ----------
    def _call_fault(self, point: str, ctx: dict[str, Any] | None = None) -> None:
        if self.fault_hook is not None:
            self.fault_hook(point, self, ctx or {})

    def _write_manifest_file(self, manifest: dict[str, Any]) -> Path:
        digest = hash_manifest(manifest)
        manifest["sha256"] = digest
        seq = int(manifest["seq"])
        rel = f"manifests/m-{seq:06d}.json"
        path = self.root / rel
        durable_write_new_file(path, canonical_bytes(manifest))
        return path

    def _write_pointer(self, manifest: dict[str, Any]) -> None:
        rel = f"manifests/m-{int(manifest['seq']):06d}.json"
        pointer = {
            "schema": SCHEMA_VERSION,
            "seq": int(manifest["seq"]),
            "manifest": rel,
            "sha256": manifest["sha256"],
            "switched_at_utc": _now_iso(),
        }
        durable_atomic_pointer(self.pointer_path, canonical_bytes(pointer))

    def _reclaim(self, manifest: dict[str, Any]) -> dict[str, Any]:
        retained = set(manifest["retained"])
        reclaimed: list[str] = []
        freed = 0
        root = self.objects_dir
        if not root.exists():
            return {"reclaimed_sample_ids": reclaimed, "freed_bytes": freed}
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            sid = child.name
            if sid in retained:
                continue
            # 安全闸门：义务集合必须是 retained 子集，否则绝不删除。
            if sid in set(self.mandatory_ids_of(manifest)):
                raise IntegrityError(f"试图回收仍负义务的样本，已阻止: {sid}")
            total = sum(p.stat().st_size for p in child.rglob("*") if p.is_file())
            _rmtree_retry(child)
            reclaimed.append(sid)
            freed += total
        return {"reclaimed_sample_ids": reclaimed, "freed_bytes": freed}

    def _finalize_and_commit(self, draft: dict[str, Any], *, reclaim: bool = True) -> dict[str, Any]:
        """规划 → 补齐对象 → 写清单 → 故障点 → 切指针 → 回收 → 校验。调用方持锁。"""
        if int(draft["seq"]) == 0 and draft.get("parent_sha256") is None and self.manifest is draft:
            pass
        else:
            draft["seq"] = int(self.manifest["seq"]) + 1
            draft["parent_sha256"] = self.manifest.get("sha256")
        draft["created_at_utc"] = _now_iso()

        self._plan(draft)

        # 3. 先补齐并校验所有 retained 对象（义务样本自然包含在内）。
        for sid in draft["retained"]:
            self._ensure_sample_objects(draft["samples"][sid])
        pre_errors = self.read_errors(draft)
        if pre_errors:
            raise IntegrityError("提交前可读性校验失败: " + "; ".join(pre_errors))

        # 4. 写不可变清单。
        mpath = self._write_manifest_file(draft)

        # 5. ★断电注入点（清单已落盘，指针尚未切换）★
        self._call_fault(POINT_AFTER_MANIFEST_BEFORE_POINTER, {"manifest_path": str(mpath)})

        # 6. 原子指针切换（提交点）。
        self._write_pointer(draft)
        self.manifest = draft

        # 7. 切换后回收（结果只作为返回值/重启报告，不回写已哈希清单）。
        reclaim_info = self._reclaim(draft) if reclaim else {"reclaimed_sample_ids": [], "freed_bytes": 0}

        # 8. 提交后不变量校验。
        self.verify_readable()
        return reclaim_info

    def _transact(self, mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        with self.lock:
            draft = copy.deepcopy(self.manifest)
            mutate(draft)
            return self._finalize_and_commit(draft)

    # ---------- 公共操作 ----------
    def ingest_samples(self, samples: list[dict[str, Any]],
                       batch_id: str | None = None) -> dict[str, Any]:
        if not samples:
            raise ValueError("samples 不能为空")

        def mutate(d: dict[str, Any]) -> None:
            bid = batch_id or samples[0].get("batch_id") or f"batch-{int(d['seq']) + 1}"
            ids: list[str] = []
            for s in samples:
                sid = s["id"]
                if not SAFE_ID_RE.match(sid):
                    raise RetentionError(f"不安全的 sample id: {sid!r}")
                if sid in d["samples"]:
                    if canonical_bytes(d["samples"][sid]) == canonical_bytes(s):
                        ids.append(sid)
                        continue
                    raise RetentionError(f"样本 ID 冲突且内容不同: {sid}")
                copied = copy.deepcopy(s)
                copied["batch_id"] = bid
                d["samples"][sid] = copied
                ids.append(sid)
            d["batches"].setdefault(bid, [])
            for sid in ids:
                if sid not in d["batches"][bid]:
                    d["batches"][bid].append(sid)

        with self.lock:
            info = self._transact(mutate)
            return {"seq": self.manifest["seq"], **(info or {})}

    def add_hold(self, sample_id: str, case_id: str, reason: str = "evidence-retention") -> dict[str, Any]:
        def mutate(d: dict[str, Any]) -> None:
            if sample_id not in d["samples"]:
                raise RetentionError(f"不能对未入库样本设定义务: {sample_id}")
            if any(h["sample_id"] == sample_id for h in d["holds"]):
                return
            d["holds"].append({
                "sample_id": sample_id,
                "case_id": case_id,
                "reason": reason,
                "since_seq": int(d["seq"]) + 1,
                "at_utc": _now_iso(),
            })

        with self.lock:
            self._transact(mutate)
            return {"seq": self.manifest["seq"]}

    def revoke_hold(self, sample_id: str) -> dict[str, Any]:
        """撤销保留义务。幂等：本来就没有 hold 时不产生新版本。"""
        with self.lock:
            active = [h for h in self.manifest["holds"] if h["sample_id"] == sample_id]
            if not active:
                return {"seq": self.manifest["seq"], "revoked": False}

            def mutate(d: dict[str, Any]) -> None:
                d["holds"] = [h for h in d["holds"] if h["sample_id"] != sample_id]
                d.setdefault("revocations", []).append({
                    "sample_id": sample_id, "at_utc": _now_iso(),
                    "from_seq": int(d["seq"]),
                })

            self._transact(mutate)
            return {"seq": self.manifest["seq"], "revoked": True}

    def set_budget(self, budget_bytes: int) -> dict[str, Any]:
        if not isinstance(budget_bytes, int) or budget_bytes < 0:
            raise ValueError("budget_bytes 必须是非负整数")

        def mutate(d: dict[str, Any]) -> None:
            d["budget_bytes"] = int(budget_bytes)

        with self.lock:
            self._transact(mutate)
            return {"seq": self.manifest["seq"], "budget_bytes": budget_bytes}

    def promise_batch_snapshot(self, batch_id: str, snapshot_id: str | None = None,
                               label: str = "promised-batch") -> dict[str, Any]:
        """把一个入库批次固化为“已对外承诺快照”，写外部回执并永久固定其样本。"""
        with self.lock:
            if batch_id not in self.manifest["batches"]:
                raise RetentionError(f"未知批次: {batch_id}")
            sample_ids = list(self.manifest["batches"][batch_id])
            snapshot_id = snapshot_id or f"snap-{batch_id}"

            # 回执内容：逐样本内容哈希 + 快照根哈希。
            entries = []
            root_h = __import__("hashlib").sha256()
            for sid in sample_ids:
                s = self.manifest["samples"][sid]
                entries.append({"sample_id": sid, "content_sha256": s["content_sha256"],
                                "size_bytes": s["size_bytes"]})
                root_h.update(canonical_bytes([sid, s["content_sha256"]]))
            root = root_h.hexdigest()
            receipt = {
                "receipt_type": "external-promise",
                "snapshot_id": snapshot_id,
                "batch_id": batch_id,
                "label": label,
                "promised_at_utc": _now_iso(),
                "sample_ids": sample_ids,
                "entries": entries,
                "snapshot_root_sha256": root,
            }
            self.receipts_dir.mkdir(parents=True, exist_ok=True)
            receipt_rel = f"receipts/{snapshot_id}.json"
            durable_write_new_file(self.root / receipt_rel, canonical_bytes(receipt))

            def mutate(d: dict[str, Any]) -> None:
                if any(sn["snapshot_id"] == snapshot_id for sn in d["snapshots"]):
                    raise RetentionError(f"快照 ID 已存在: {snapshot_id}")
                d["snapshots"].append({
                    "snapshot_id": snapshot_id,
                    "batch_id": batch_id,
                    "label": label,
                    "sample_ids": sample_ids,
                    "snapshot_root_sha256": root,
                    "receipt_file": receipt_rel,
                    "promised": True,
                    "created_seq": int(d["seq"]) + 1,
                })

            self._transact(mutate)
            return {"seq": self.manifest["seq"], "snapshot_id": snapshot_id,
                    "snapshot_root_sha256": root, "sample_ids": sample_ids}

    # ---------- 崩溃恢复 ----------
    @classmethod
    def recover(cls, root: Path | str) -> tuple["RetentionManager", dict[str, Any]]:
        """重启恢复：读指针 → 校验 → 把完整且链接连续的前置清单前滚 → 回收 → 报告。"""
        root = Path(root)
        notes: list[str] = []
        pointer_info: dict[str, Any] | None = None
        head: dict[str, Any] | None = None
        head_file: Path | None = None
        pre_crash_seq: int | None = None
        action = "no_staged_manifest"

        pointer_path = root / "pointer.json"
        if pointer_path.exists():
            pointer_info = json.loads(pointer_path.read_text(encoding="utf-8"))
            pre_crash_seq = pointer_info.get("seq")
            head_file = root / pointer_info["manifest"]
            head = cls._load_manifest_file(head_file, pointer_info.get("sha256"))
        else:
            notes.append("pointer.json 缺失，尝试从 manifests 中选择最高有效清单")

        # 扫描全部清单，收集自哈希有效信息。
        staged_found: list[dict[str, Any]] = []
        all_manifests: dict[int, tuple[Path, dict[str, Any]]] = {}
        for mp in sorted((root / "manifests").glob("m-*.json")):
            info: dict[str, Any] = {"file": f"manifests/{mp.name}"}
            try:
                m = cls._load_manifest_file(mp)
                info.update({"seq": m["seq"], "sha256": m["sha256"], "valid": True,
                             "parent_sha256": m.get("parent_sha256")})
                all_manifests[int(m["seq"])] = (mp, m)
            except Exception as exc:  # noqa: BLE001
                info.update({"valid": False, "error": str(exc)})
            staged_found.append(info)

        if head is None:
            # 指针缺失的兜底：选 seq 最大的有效清单。
            if not all_manifests:
                raise IntegrityError("没有任何可用清单，无法恢复")
            seq = max(all_manifests)
            head_file, head = all_manifests[seq]
            action = "pointer_rebuilt_from_manifest"
            notes.append(f"从磁盘选择 seq={seq} 作为头部")

        assert head is not None and head_file is not None
        mgr = cls(root, head)
        if not pointer_path.exists():
            # 指针缺失兜底：把指针重建到所选头部，否则独立核验会因无 pointer 失败。
            mgr._write_pointer(head)
            notes.append(f"已重建缺失的 pointer.json -> seq={head['seq']}")

        # 沿 parent 链前滚所有“连续、完整、对象可读”的后继清单。
        advanced: list[int] = []
        cur = head
        while True:
            nxt = all_manifests.get(int(cur["seq"]) + 1)
            if nxt is None:
                break
            nxt_path, nxt_m = nxt
            parent_ok = nxt_m.get("parent_sha256") == cur["sha256"]
            errs = mgr.read_errors(nxt_m) if parent_ok else ["parent 链不连续"]
            entry = next((e for e in staged_found if e.get("seq") == nxt_m["seq"]), None)
            if entry is not None:
                entry["parent_ok"] = parent_ok
                entry["readable"] = not errs
                if errs:
                    entry["read_errors"] = errs
            if not parent_ok or errs:
                notes.append(f"前置清单 seq={nxt_m['seq']} 不可前滚: {errs[:2]}")
                break
            # 前滚：切换指针到该清单。
            mgr.manifest = nxt_m
            mgr._write_pointer(nxt_m)
            advanced.append(int(nxt_m["seq"]))
            cur = nxt_m
            action = "rolled_forward_staged_manifest"

        mgr.manifest = cur
        reclaim_info = mgr._reclaim(cur)
        mgr.verify_readable()

        sel = cur["selection"] or {}
        report = {
            "report_type": "retainer-restart-report",
            "schema": 1,
            "generated_at_utc": _now_iso(),
            "root": str(root),
            "power_loss_injection_point": POINT_AFTER_MANIFEST_BEFORE_POINTER,
            "pointer": pointer_info,
            "pre_crash_pointer_seq": pre_crash_seq,
            "staged_manifests_found": staged_found,
            "recovery_action": action if not advanced else "rolled_forward_staged_manifest",
            "rolled_forward": bool(advanced),
            "rolled_forward_to_seq": int(cur["seq"]) if advanced else None,
            "advanced_seq_chain": advanced,
            "final_state": {
                "seq": int(cur["seq"]),
                "manifest_file": f"manifests/m-{int(cur['seq']):06d}.json",
                "manifest_sha256": cur["sha256"],
                "budget_bytes": cur["budget_bytes"],
                "hold_ids": [h["sample_id"] for h in cur["holds"]],
                "promised_snapshot_ids": [s["snapshot_id"] for s in cur["snapshots"]],
                "mandatory_ids": mgr.mandatory_ids_of(cur),
                "retained_ids": list(cur["retained"]),
                "mandatory_cost": sel.get("mandatory_cost"),
                "remaining_budget": sel.get("remaining_budget"),
                "deficit_bytes": sel.get("deficit_bytes"),
                "budget_feasible": sel.get("budget_feasible"),
                "chosen_optional_ids": sel.get("chosen_optional_ids"),
                "chosen_optional_risk": sel.get("chosen_optional_risk"),
                "optimal_total_risk": sel.get("optimal_total_risk"),
                "total_retained_cost": sel.get("total_retained_cost"),
                "readability_ok": True,
                "obligations_readable": True,
            },
            "reclamation_after_restart": reclaim_info,
            "notes": notes,
        }
        return mgr, report

    def write_restart_report(self, report: dict[str, Any], out_path: Path | str | None = None) -> Path:
        out = Path(out_path) if out_path else self.reports_dir / "restart-report-latest.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        durable_write_new_file(out, canonical_bytes(report) + b"\n")
        # 同时在保险库 reports/ 留一份 latest（若 out 不在该处）。
        latest = self.reports_dir / "restart-report-latest.json"
        if out.resolve() != latest.resolve():
            durable_write_new_file(latest, canonical_bytes(report) + b"\n")
        return out
