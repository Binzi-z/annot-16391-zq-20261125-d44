#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""独立核验器（**只依赖 Python 标准库**，不 import retainer 包内任何模块）。

设计目的：重启报告不能“自说自话”。第三方只需拿到 保险库目录 + 重启报告 JSON，
用同一个解释器直接运行本文件即可独立核验：

    python retainer/verifier.py --root <vault> --report <report.json>
    echo %ERRORLEVEL%     # 0 = 全部核验通过；1 = 存在不符

它独立地从磁盘重新读取 pointer -> manifest -> 分片字节，重新计算：
  * 指针/清单哈希与 parent 链；
  * 每个义务样本、每个已对外承诺快照内样本的“整样本全部分片”存在性、大小、
    SHA-256，以及整样本内容哈希；
  * 预算算术、剩余预算、缺口；
  * 用核验器**自带的另一份 0/1 背包 DP**重算“精确最大总风险”，证明清单选择
    确实最优（而不是风险密度贪心），并校验可行性；
  * 分片原子性：retained 单位只能是完整 sample id；保留样本的所有分片必须全部可读；
  * 重启报告中的关键字段是否与磁盘重算结果逐项一致；
  * 报告列出的断电时“已写未切”前置清单是否真实存在且哈希正确。

本文件刻意不依赖 manager.py / risksel.py，以便被单独拷出审计或在隔离环境运行。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "retainer-manifest-v1"
INJECTION_POINT = "after_manifest_write_before_pointer_switch"


# --------------------------------------------------------------------------- #
# 独立哈希 / JSON 例程（与 retainer.util 中规范保持一致，但此处独立实现）
# --------------------------------------------------------------------------- #
def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_manifest(m: dict[str, Any]) -> str:
    return _sha_bytes(_canonical({k: v for k, v in m.items() if k != "sha256"}))


def _whole_cost(sample: dict[str, Any]) -> int:
    return sum(int(sh["size"]) for sh in sample.get("shards", []))


def _independent_optimal_risk(items: list[tuple[str, int, int]], cap: int) -> int:
    """核验器自带的精确 0/1 背包（容量维 DP），独立于 retainer.risksel。

    items: [(id, whole_sample_cost, risk), ...]；cap 必须 >= 0。
    返回容量 cap 下可获得的最大总风险。代价为整数、规模在测试范围内可控。
    """
    if cap < 0:
        raise ValueError("cap 必须非负")
    dp = [0] * (cap + 1)
    for _id, cost, risk in items:
        if cost < 0:
            raise ValueError("cost 不能为负")
        if cost > cap:
            continue
        for w in range(cap, cost - 1, -1):
            cand = dp[w - cost] + risk
            if cand > dp[w]:
                dp[w] = cand
    return dp[cap]


def _independent_brute_risk(items: list[tuple[str, int, int]], cap: int) -> int:
    """n 很小时的第二意见：枚举全部子集。"""
    n = len(items)
    best = 0
    for mask in range(1 << n):
        c = v = 0
        for i in range(n):
            if (mask >> i) & 1:
                c += items[i][1]
                v += items[i][2]
        if c <= cap and v > best:
            best = v
    return best


class _Recorder:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.errors: list[str] = []

    def check(self, name: str, cond: bool, detail: Any = "") -> bool:
        ok = bool(cond)
        self.checks.append({"name": name, "ok": ok, "detail": detail})
        if not ok:
            self.errors.append(f"{name}: {detail}")
        return ok


def _safe_within(root: Path, rel: str) -> Path | None:
    """把清单/指针中的相对路径安全地限制在 root 内。"""
    if not isinstance(rel, str) or not rel:
        return None
    p = (root / rel).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError:
        return None
    return p


def _check_sample_shards(root: Path, sid: str, sample: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not isinstance(sid, str) or "/" in sid or "\\" in sid or sid in ("", ".", ".."):
        return [f"非法 sample id: {sid!r}"]
    sdir = (root / "objects" / "samples" / sid)
    whole = hashlib.sha256()
    for sh in sample.get("shards", []):
        name = sh.get("name", "")
        if "/" in name or "\\" in name or name in ("", ".", ".."):
            errs.append(f"非法分片名: {sid}/{name!r}")
            continue
        p = sdir / name
        if not p.is_file():
            errs.append(f"缺失分片: {sid}/{name}")
            continue
        if p.stat().st_size != int(sh["size"]):
            errs.append(f"分片大小不符: {sid}/{name}")
        actual = _sha_file(p)
        if actual != sh["sha256"]:
            errs.append(f"分片哈希不符: {sid}/{name}")
            continue
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                whole.update(chunk)
    if not errs and whole.hexdigest() != sample.get("content_sha256"):
        errs.append(f"整样本内容哈希不符: {sid}")
    return errs


# --------------------------------------------------------------------------- #
# 仅针对保险库当前磁盘状态的一致性核验（不需要报告）
# --------------------------------------------------------------------------- #
def verify_root_consistency(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    rec = _Recorder()
    facts: dict[str, Any] = {"root": str(root)}

    pointer_path = root / "pointer.json"
    if not rec.check("pointer_exists", pointer_path.is_file(), str(pointer_path)):
        return {"ok": False, "errors": rec.errors, "checks": rec.checks, "facts": facts}

    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        rec.check("pointer_json", False, repr(exc))
        return {"ok": False, "errors": rec.errors, "checks": rec.checks, "facts": facts}
    rec.check("pointer_json", True)

    mpath = _safe_within(root, pointer.get("manifest", ""))
    rec.check("pointer_manifest_path_safe", mpath is not None and mpath.is_file(),
              pointer.get("manifest"))
    if mpath is None or not mpath.is_file():
        return {"ok": False, "errors": rec.errors, "checks": rec.checks, "facts": facts}

    # 指针承诺的是“清单自哈希”（剔除 sha256 字段后的规范哈希），与 manager 口径一致。
    # 这里记录文件原始字节哈希作为附加事实，但不把它误当作自哈希比较。
    try:
        raw_manifest = mpath.read_bytes()
    except OSError as exc:
        rec.check("manifest_readable", False, repr(exc))
        return {"ok": False, "errors": rec.errors, "checks": rec.checks, "facts": facts}
    facts["manifest_file_raw_sha256"] = _sha_bytes(raw_manifest)

    try:
        m = json.loads(raw_manifest.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        rec.check("manifest_json", False, repr(exc))
        return {"ok": False, "errors": rec.errors, "checks": rec.checks, "facts": facts}
    rec.check("manifest_json", True)

    mhash = _hash_manifest(m)
    rec.check("manifest_self_hash", m.get("sha256") == mhash,
              {"claimed": m.get("sha256"), "recomputed": mhash})
    rec.check("manifest_hash_equals_pointer", mhash == pointer.get("sha256"),
              {"pointer": pointer.get("sha256"), "manifest_self_hash": mhash})
    rec.check("manifest_seq_equals_pointer", m.get("seq") == pointer.get("seq"),
              {"manifest": m.get("seq"), "pointer": pointer.get("seq")})
    rec.check("manifest_schema", m.get("schema") == SCHEMA, m.get("schema"))

    # parent 链：优先 O(1) 定位 m-(seq-1).json，找不到再全量扫描匹配自哈希。
    if int(m.get("seq", -1)) > 0 and m.get("parent_sha256"):
        parent_hash = m["parent_sha256"]
        found_parent = None
        seq = int(m["seq"])
        direct = _safe_within(root, f"manifests/m-{seq - 1:06d}.json")
        candidates = [direct] if direct is not None else []
        mdir = root / "manifests"
        if mdir.is_dir():
            candidates.extend(sorted(mdir.glob("m-*.json")))
        seen = set()
        for cand in candidates:
            if cand is None or cand in seen or not cand.is_file():
                continue
            seen.add(cand)
            try:
                cm = json.loads(cand.read_text(encoding="utf-8"))
                if _hash_manifest(cm) == parent_hash and cm.get("sha256") == parent_hash:
                    found_parent = cand.name
                    break
            except Exception:  # noqa: BLE001
                continue
        rec.check("parent_manifest_chain", found_parent is not None, parent_hash[:16])
        facts["parent_manifest"] = found_parent

    samples: dict[str, Any] = m.get("samples", {})
    holds = m.get("holds", [])
    snapshots = m.get("snapshots", [])
    retained = list(m.get("retained", []))
    sel = m.get("selection") or {}

    # 元数据内部一致性：size_bytes == 分片 size 之和。
    for sid, s in samples.items():
        rec.check(f"sample_size_sum[{sid}]",
                  int(s.get("size_bytes", -1)) == _whole_cost(s),
                  {"size_bytes": s.get("size_bytes"), "sum_shards": _whole_cost(s)})

    hold_ids = sorted({h["sample_id"] for h in holds})
    snap_ids: set[str] = set()
    for sn in snapshots:
        snap_ids.update(sn.get("sample_ids", []))
    mandatory = sorted(set(hold_ids) | snap_ids)

    facts.update({
        "seq": m.get("seq"),
        "manifest_sha256": mhash,
        "budget_bytes": m.get("budget_bytes"),
        "hold_ids": hold_ids,
        "promised_snapshot_ids": [s.get("snapshot_id") for s in snapshots],
        "snapshot_sample_ids": sorted(snap_ids),
        "mandatory_ids": mandatory,
        "retained_ids": retained,
    })

    unknown_mandatory = [sid for sid in mandatory if sid not in samples]
    rec.check("mandatory_samples_known", not unknown_mandatory, unknown_mandatory)
    unknown_retained = [sid for sid in retained if sid not in samples]
    rec.check("retained_samples_known", not unknown_retained, unknown_retained)

    mandatory_set = set(mandatory)
    retained_set = set(retained)
    rec.check("mandatory_subset_retained", mandatory_set <= retained_set,
              {"missing": sorted(mandatory_set - retained_set)})
    rec.check("retained_entries_are_whole_sample_ids",
              all(isinstance(x, str) and "/" not in x and "\\" not in x for x in retained))

    # 已对外承诺快照：回执文件 + 根哈希 + 成员一致。
    for sn in snapshots:
        sid_sn = sn.get("snapshot_id", "?")
        ids = sn.get("sample_ids", [])
        calc_root_h = hashlib.sha256()
        for x in ids:
            s = samples.get(x)
            if s is None:
                continue
            calc_root_h.update(_canonical([x, s.get("content_sha256")]))
        rec.check(f"snapshot_root[{sid_sn}]",
                  calc_root_h.hexdigest() == sn.get("snapshot_root_sha256"),
                  {"claimed": sn.get("snapshot_root_sha256"),
                   "calc": calc_root_h.hexdigest()})
        rf = sn.get("receipt_file")
        if rf:
            rp = _safe_within(root, rf)
            rec.check(f"snapshot_receipt_file[{sid_sn}]", rp is not None and rp.is_file(), rf)
            if rp and rp.is_file():
                try:
                    receipt = json.loads(rp.read_text(encoding="utf-8"))
                    rec.check(f"snapshot_receipt_root_match[{sid_sn}]",
                              receipt.get("snapshot_root_sha256") == sn.get("snapshot_root_sha256"))
                except Exception as exc:  # noqa: BLE001
                    rec.check(f"snapshot_receipt_json[{sid_sn}]", False, repr(exc))

    # 可读性：义务样本（标题性不变量）与全部 retained 样本（分片原子性）。
    mandatory_errors: list[str] = []
    for sid in mandatory:
        if sid in samples:
            mandatory_errors.extend(_check_sample_shards(root, sid, samples[sid]))
    rec.check("obligations_and_promised_snapshots_readable", not mandatory_errors,
              mandatory_errors[:5])
    facts["mandatory_read_errors"] = mandatory_errors

    retained_errors: list[str] = []
    for sid in retained:
        if sid in samples:
            retained_errors.extend(_check_sample_shards(root, sid, samples[sid]))
    rec.check("all_retained_whole_samples_readable", not retained_errors, retained_errors[:5])
    rec.check("shard_atomicity_no_partial_retained_sample", not retained_errors,
              "任一保留样本缺/坏任一分片都会在此失败")
    facts["retained_read_errors"] = retained_errors

    # ---------------- 预算与精确最优性（核验器独立重算） ---------------- #
    budget = int(m.get("budget_bytes", -1))
    mandatory_cost = sum(_whole_cost(samples[sid]) for sid in mandatory if sid in samples)
    mandatory_risk = sum(int(samples[sid].get("risk", 0)) for sid in mandatory if sid in samples)
    remaining = budget - mandatory_cost
    deficit = max(0, -remaining)
    cap = max(0, remaining)

    rec.check("plan_mandatory_cost", sel.get("mandatory_cost") == mandatory_cost,
              {"claimed": sel.get("mandatory_cost"), "recomputed": mandatory_cost})
    rec.check("plan_remaining_budget", sel.get("remaining_budget") == remaining,
              {"claimed": sel.get("remaining_budget"), "recomputed": remaining})
    rec.check("plan_deficit", sel.get("deficit_bytes") == deficit,
              {"claimed": sel.get("deficit_bytes"), "recomputed": deficit})
    rec.check("plan_budget_feasible_flag",
              bool(sel.get("budget_feasible")) == (mandatory_cost <= budget))

    chosen = sorted(retained_set - mandatory_set)
    claimed_chosen = sorted(sel.get("chosen_optional_ids", []) or [])
    rec.check("chosen_optional_matches_retained_minus_mandatory", chosen == claimed_chosen,
              {"from_retained": chosen, "selection": claimed_chosen})

    chosen_cost = sum(_whole_cost(samples[sid]) for sid in chosen if sid in samples)
    chosen_risk = sum(int(samples[sid].get("risk", 0)) for sid in chosen if sid in samples)
    retained_cost = sum(_whole_cost(samples[sid]) for sid in retained if sid in samples)
    rec.check("chosen_within_remaining_budget", chosen_cost <= cap,
              {"chosen_cost": chosen_cost, "capacity": cap, "remaining": remaining})
    rec.check("plan_chosen_cost", sel.get("chosen_optional_cost") == chosen_cost)
    rec.check("plan_chosen_risk", sel.get("chosen_optional_risk") == chosen_risk)
    rec.check("plan_total_retained_cost",
              sel.get("total_retained_cost") == retained_cost == mandatory_cost + chosen_cost,
              {"claimed": sel.get("total_retained_cost"), "retained_sum": retained_cost})

    optional_items = [
        (sid, _whole_cost(s), int(s.get("risk", 0)))
        for sid, s in sorted(samples.items()) if sid not in mandatory_set
    ]
    if len(optional_items) <= 18:
        opt_risk = _independent_brute_risk(optional_items, cap)
        rec.check("independent_bruteforce_optimum", True, {"brute": opt_risk})
        # 小容量时再用自带 DP 交叉验证；大容量下 n 很小，暴力本身已是独立神谕。
        if cap <= 200_000:
            dp_risk = _independent_optimal_risk(optional_items, cap)
            rec.check("independent_dp_matches_bruteforce", dp_risk == opt_risk,
                      {"dp": dp_risk, "brute": opt_risk})
    else:
        opt_risk = _independent_optimal_risk(optional_items, cap)
    rec.check("selection_is_exact_total_risk_optimum", chosen_risk == opt_risk,
              {"chosen_risk": chosen_risk, "independent_optimum": opt_risk,
               "candidates": len(optional_items), "capacity": cap})
    rec.check("plan_optimal_total_risk",
              sel.get("optimal_total_risk") == mandatory_risk + opt_risk)
    rec.check("whole_sample_cost_used",
              sel.get("optional_item_whole_sample") is True,
              "选择器必须以全分片之和为代价，禁止单片保留")

    facts.update({
        "mandatory_cost": mandatory_cost,
        "mandatory_risk": mandatory_risk,
        "remaining_budget": remaining,
        "deficit_bytes": deficit,
        "capacity_used_for_optimization": cap,
        "chosen_optional_ids": chosen,
        "chosen_optional_cost": chosen_cost,
        "chosen_optional_risk": chosen_risk,
        "independent_optimal_optional_risk": opt_risk,
        "optimal_total_risk": mandatory_risk + opt_risk,
        "retained_cost": retained_cost,
        "budget_bytes": budget,
        "budget_feasible": mandatory_cost <= budget,
    })

    ok = not rec.errors
    return {"ok": ok, "errors": rec.errors, "checks": rec.checks, "facts": facts}


# --------------------------------------------------------------------------- #
# 轻量可读性核验：并发探针高频调用（只读 pointer/manifest + 哈希分片，不做 DP）
# --------------------------------------------------------------------------- #
def verify_readability(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    errors: list[str] = []
    pointer_path = root / "pointer.json"
    if not pointer_path.is_file():
        return {"ok": False, "errors": ["pointer.json 缺失"]}
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        mpath = _safe_within(root, pointer.get("manifest", ""))
        if mpath is None or not mpath.is_file():
            return {"ok": False, "errors": ["指针指向的清单不存在或越界"]}
        m = json.loads(mpath.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "errors": [f"读取指针/清单失败: {exc!r}"]}

    samples = m.get("samples", {})
    hold_ids = {h["sample_id"] for h in m.get("holds", [])}
    snap_ids: set[str] = set()
    for sn in m.get("snapshots", []):
        snap_ids.update(sn.get("sample_ids", []))
    mandatory = sorted(hold_ids | snap_ids)

    for sid in mandatory:
        if sid not in samples:
            errors.append(f"义务样本元数据缺失: {sid}")
            continue
        errors.extend(_check_sample_shards(root, sid, samples[sid]))

    retained_errors: list[str] = []
    for sid in m.get("retained", []):
        if sid in samples:
            retained_errors.extend(_check_sample_shards(root, sid, samples[sid]))

    return {
        "ok": not errors and not retained_errors,
        "errors": errors + retained_errors,
        "mandatory_ids": mandatory,
        "seq": m.get("seq"),
    }


# --------------------------------------------------------------------------- #
# 重启报告的独立核验：先核验磁盘一致性，再逐项比对报告声明
# --------------------------------------------------------------------------- #
def verify_report(root: str | Path, report_path: str | Path) -> dict[str, Any]:
    root = Path(root)
    report_path = Path(report_path)
    result = verify_root_consistency(root)
    rec = _Recorder()
    rec.check("report_file_exists", report_path.is_file(), str(report_path))
    report: dict[str, Any] | None = None
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            rec.check("report_json", True)
        except Exception as exc:  # noqa: BLE001
            rec.check("report_json", False, repr(exc))

    if report is not None:
        rec.check("report_type", report.get("report_type") == "retainer-restart-report")
        rec.check("report_injection_point",
                  report.get("power_loss_injection_point") == INJECTION_POINT)

        # 报告中列出的“已写未切”清单必须真实存在且自哈希正确（可独立复核断电窗口）。
        for entry in report.get("staged_manifests_found", []):
            rel = entry.get("file", "")
            p = _safe_within(root, rel)
            if entry.get("valid"):
                exists = p is not None and p.is_file()
                rec.check(f"staged_manifest_exists[{rel}]", exists, rel)
                if exists and p is not None:
                    try:
                        sm = json.loads(p.read_text(encoding="utf-8"))
                        self_h = _hash_manifest(sm)
                    except Exception as exc:  # noqa: BLE001
                        self_h = f"__load_error__:{exc!r}"
                    rec.check(f"staged_manifest_hash[{rel}]", self_h == entry.get("sha256"),
                              {"report": entry.get("sha256"), "recomputed_self_hash": self_h})

        fs = report.get("final_state", {})
        facts = result.get("facts", {})
        m = None
        try:
            pointer = json.loads((root / "pointer.json").read_text(encoding="utf-8"))
            m = json.loads((root / pointer["manifest"]).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            m = None

        if m is not None:
            rec.check("report_final_seq", fs.get("seq") == m.get("seq"),
                      {"report": fs.get("seq"), "disk": m.get("seq")})
            rec.check("report_final_manifest_sha",
                      fs.get("manifest_sha256") == m.get("sha256"))
            rec.check("report_budget", fs.get("budget_bytes") == m.get("budget_bytes"))
            rec.check("report_hold_ids", sorted(fs.get("hold_ids", [])) == facts.get("hold_ids"))
            rec.check("report_mandatory_ids",
                      sorted(fs.get("mandatory_ids", [])) == facts.get("mandatory_ids"))
            rec.check("report_retained_ids",
                      sorted(fs.get("retained_ids", []))
                      == sorted(facts.get("retained_ids", [])))
            rec.check("report_chosen_optional_ids",
                      sorted(fs.get("chosen_optional_ids", []) or [])
                      == facts.get("chosen_optional_ids"))
            for key in ("budget_bytes", "mandatory_cost", "remaining_budget",
                        "deficit_bytes", "chosen_optional_risk", "optimal_total_risk"):
                rec.check(f"report_field[{key}]", fs.get(key) == facts.get(key),
                          {"report": fs.get(key), "recomputed": facts.get(key)})
            rec.check("report_readability_flag", fs.get("readability_ok") is True)
            rec.check("report_obligations_readable_flag",
                      fs.get("obligations_readable") is True)

        if report.get("rolled_forward"):
            try:
                pointer = json.loads((root / "pointer.json").read_text(encoding="utf-8"))
                rec.check("report_rollforward_seq_matches_pointer",
                          pointer.get("seq") == report.get("rolled_forward_to_seq"),
                          {"pointer": pointer.get("seq"),
                           "to": report.get("rolled_forward_to_seq")})
            except Exception as exc:  # noqa: BLE001
                rec.check("read_pointer_after_rollforward", False, repr(exc))

    all_errors = list(result.get("errors", [])) + rec.errors
    ok = not all_errors
    return {
        "ok": ok,
        "errors": all_errors,
        "disk_checks": result.get("checks", []),
        "report_checks": rec.checks,
        "facts": result.get("facts", {}),
    }


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="保留器重启报告/保险库独立核验器（仅标准库）")
    ap.add_argument("--root", required=True, help="保险库根目录")
    ap.add_argument("--report", default=None, help="重启报告 JSON；省略则只核验磁盘一致性")
    args = ap.parse_args(argv)

    if args.report:
        out = verify_report(args.root, args.report)
    else:
        out = verify_root_consistency(args.root)
    json.dump(out, sys.stdout, ensure_ascii=True, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
