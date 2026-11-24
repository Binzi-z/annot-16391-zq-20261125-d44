"""全部数据均为合成数据；确定性生成，跨进程/重启可复现。

样本由若干分片组成。分片字节由 (gen_seed, sample_id, index) 确定性派生，因此
回收删除可选样本后，若预算重新放宽而再次选中，可用相同种子把字节“重建”出来
（真实系统中对应从归档/源端重新取回），并逐片哈希校验，身份不变。
"""
from __future__ import annotations

import hashlib
from typing import Any, Sequence

from .util import sha256_bytes

MALWARE_FAMILIES = ("Trojan", "Ransom", "Spyware", "Rootkit", "Worm", "Loader", "Stealer")
EVIDENCE_KINDS = ("pcap", "memory-image", "disk-triage", "email-export", "log-bundle")


def shard_bytes(gen_seed: str, sample_id: str, index: int, size: int) -> bytes:
    if size < 0:
        raise ValueError("shard size 不能为负")
    if size == 0:
        return b""
    domain = f"retainer-synth-v1|{gen_seed}|{sample_id}|{index}".encode("utf-8")
    # SHAKE256 可直接派生长度任意的确定性字节流。
    return hashlib.shake_256(domain).digest(size)


def content_digest(gen_seed: str, sample_id: str, shard_sizes: Sequence[int]) -> tuple[str, list[dict[str, Any]]]:
    shards: list[dict[str, Any]] = []
    whole = hashlib.sha256()
    for i, size in enumerate(shard_sizes):
        data = shard_bytes(gen_seed, sample_id, i, int(size))
        digest = sha256_bytes(data)
        whole.update(data)
        shards.append({
            "index": i,
            "name": f"shard-{i:03d}.bin",
            "size": int(size),
            "sha256": digest,
        })
    return whole.hexdigest(), shards


def make_sample(
    sample_id: str,
    *,
    tenant: str,
    risk: int,
    shard_sizes: Sequence[int],
    gen_seed: str = "seed-0",
    batch_id: str | None = None,
    kind: str = "synthetic-binary",
    tags: Sequence[str] = (),
) -> dict[str, Any]:
    if not shard_sizes or any(s <= 0 for s in shard_sizes):
        # 至少一个正大小分片：保证 whole-sample cost > 0，且“空样本”不产生歧义。
        raise ValueError("每个样本必须至少含一个正大小分片")
    if risk < 0:
        raise ValueError("risk 必须非负")
    content_sha, shards = content_digest(gen_seed, sample_id, shard_sizes)
    return {
        "id": sample_id,
        "tenant": tenant,
        "batch_id": batch_id,
        "kind": kind,
        "risk": int(risk),
        "tags": sorted(set(tags)),
        "synthetic": True,
        "gen_seed": gen_seed,
        "size_bytes": int(sum(shard_sizes)),
        "content_sha256": content_sha,
        "shards": shards,
    }


def deterministic_samples(count: int, *, prefix: str = "S", start_index: int = 1,
                          tenants: Sequence[str] = ("tenant-a",),
                          seed: int = 16391, batch_id: str | None = None,
                          high_risk: bool = False) -> list[dict[str, Any]]:
    """生成一组稳定的多样分片样本（仅用标准库确定性 PRNG）。"""
    import random

    rng = random.Random(seed)
    out: list[dict[str, Any]] = []
    for k in range(count):
        idx = start_index + k
        sid = f"{prefix}{idx:04d}"
        tenant = tenants[rng.randrange(len(tenants))]
        n_shards = rng.randint(1, 4)
        # 小体积分片，保证穷举/DP 与磁盘测试都很快。
        sizes = [rng.randint(24, 220) for _ in range(n_shards)]
        if high_risk:
            risk = rng.randint(70, 100)
        else:
            risk = rng.randint(1, 95)
        kind = MALWARE_FAMILIES[rng.randrange(len(MALWARE_FAMILIES))]
        out.append(make_sample(
            sid, tenant=tenant, risk=risk, shard_sizes=sizes,
            gen_seed=f"g{seed}", batch_id=batch_id, kind=kind,
            tags=[f"fam:{kind.lower()}"],
        ))
    return out
