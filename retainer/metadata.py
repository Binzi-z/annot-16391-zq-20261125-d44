"""五万元数据条目：按租户增量重算 + 不可绕过的真实访问计数。

核验思路（对应题面“变更前后无关租户不重算和真实访问量”）：

- 所有对条目的真实读取都必须经过 :class:`CountingMetadataDAO` 的扫描迭代器，
  每 yield 一条就 +1，并按租户分账。计数发生在数据访问的唯一收口，无法被
  “声称命中缓存”绕过。
- 某租户的一条元数据变更，只把该租户标脏；``recompute_dirty`` 只重算脏租户。
- 测试用“变更前快照 / 变更后计数增量”证明：无关租户的摘要、版本、重算次数、
  真实访问量全部不变；被变更租户的真实访问量恰为其分区条目数。
"""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from .util import canonical_bytes

DEFAULT_TENANTS = 100
DEFAULT_ENTRIES = 50_000


@dataclass(frozen=True)
class MetadataEntry:
    entry_id: int
    sample_id: str
    tenant: str
    risk: int
    size_bytes: int
    version: int = 1


def generate_metadata_entries(total: int = DEFAULT_ENTRIES,
                              tenants: int = DEFAULT_TENANTS,
                              seed: int = 20261125) -> list[MetadataEntry]:
    """确定性生成 total 条元数据，尽量均匀分布到 tenants 个租户。"""
    import random

    rng = random.Random(seed)
    out: list[MetadataEntry] = []
    for i in range(total):
        tenant_idx = i % tenants  # 严格均匀：50000 / 100 = 500/租户
        out.append(MetadataEntry(
            entry_id=i + 1,
            sample_id=f"M{i + 1:06d}",
            tenant=f"tenant-{tenant_idx:03d}",
            risk=rng.randint(1, 100),
            size_bytes=rng.randint(24, 4096),
            version=1,
        ))
    return out


class CountingMetadataDAO:
    """唯一的数据读取收口；记录真实发生的条目访问量。"""

    def __init__(self, entries: Iterable[MetadataEntry]):
        self._by_tenant: dict[str, list[MetadataEntry]] = {}
        self._by_id: dict[int, MetadataEntry] = {}
        for e in entries:
            self._by_tenant.setdefault(e.tenant, []).append(e)
            self._by_id[e.entry_id] = e
        self.total_reads = 0
        self.reads_by_tenant: Counter[str] = Counter()
        self.scan_calls_by_tenant: Counter[str] = Counter()

    @property
    def tenants(self) -> list[str]:
        return sorted(self._by_tenant)

    def tenant_size(self, tenant: str) -> int:
        return len(self._by_tenant.get(tenant, ()))

    def get(self, entry_id: int) -> MetadataEntry:
        # 单点真实读取也计数（本演示主要用 scan_tenant）。
        self.total_reads += 1
        e = self._by_id[entry_id]
        self.reads_by_tenant[e.tenant] += 1
        return e

    def scan_tenant(self, tenant: str) -> Iterable[MetadataEntry]:
        self.scan_calls_by_tenant[tenant] += 1
        for e in self._by_tenant.get(tenant, ()):  # noqa: UP028 - 生成器内需逐条计数
            self.total_reads += 1
            self.reads_by_tenant[tenant] += 1
            yield e

    def update_risk(self, entry_id: int, new_risk: int) -> str:
        old = self._by_id[entry_id]
        new = MetadataEntry(old.entry_id, old.sample_id, old.tenant,
                            int(new_risk), old.size_bytes, old.version + 1)
        self._by_id[entry_id] = new
        bucket = self._by_tenant[old.tenant]
        for i, e in enumerate(bucket):
            if e.entry_id == entry_id:
                bucket[i] = new
                break
        return old.tenant


@dataclass(frozen=True)
class TenantRollup:
    tenant: str
    entries: int
    total_risk: int
    total_bytes: int
    max_risk: int
    digest: str
    recompute_count: int

    def identity(self) -> tuple:
        """与重算次数无关的数据身份，用于变更前后比较无关租户是否变化。"""
        return (self.entries, self.total_risk, self.total_bytes, self.max_risk, self.digest)


def aggregate(tenant: str, entries: Iterable[MetadataEntry]) -> tuple[int, int, int, int, str]:
    """纯聚合；消费迭代器。传入计数 DAO 的生成器时，每一条都是一次真实访问。"""
    n = 0
    total_risk = 0
    total_bytes = 0
    max_risk = 0
    h = hashlib.sha256()
    for e in entries:
        n += 1
        total_risk += e.risk
        total_bytes += e.size_bytes
        max_risk = max(max_risk, e.risk)
        h.update(canonical_bytes([e.entry_id, e.risk, e.size_bytes, e.version]))
    return n, total_risk, total_bytes, max_risk, h.hexdigest()


class MetadataCatalog:
    """包装 DAO，维护脏租户集合。"""

    def __init__(self, entries: Iterable[MetadataEntry]):
        self.dao = CountingMetadataDAO(entries)
        self.dirty: set[str] = set()

    def change_risk(self, entry_id: int, new_risk: int) -> str:
        tenant = self.dao.update_risk(entry_id, new_risk)
        self.dirty.add(tenant)  # 只标脏该条目所属租户
        return tenant


class TenantRollupService:
    def __init__(self, catalog: MetadataCatalog):
        self.catalog = catalog
        self.dao = catalog.dao
        self.rollups: dict[str, TenantRollup] = {}
        self.recompute_events: list[str] = []

    def recompute_tenant(self, tenant: str) -> TenantRollup:
        n, tr, tb, mx, digest = aggregate(tenant, self.dao.scan_tenant(tenant))
        count = self.rollups[tenant].recompute_count + 1 if tenant in self.rollups else 1
        ru = TenantRollup(tenant, n, tr, tb, mx, digest, count)
        self.rollups[tenant] = ru
        self.recompute_events.append(tenant)
        return ru

    def recompute_all(self) -> list[str]:
        done = []
        for t in self.dao.tenants:
            self.recompute_tenant(t)
            done.append(t)
        return done

    def recompute_dirty(self) -> list[str]:
        done = []
        for t in sorted(self.catalog.dirty):
            self.recompute_tenant(t)
            done.append(t)
        self.catalog.dirty.clear()
        return done


def oracle_tenant_identity(entries: list[MetadataEntry], tenant: str) -> tuple:
    """独立神谕：直接在原始条目列表上全量聚合，不经过计数 DAO / 服务缓存。"""
    n, tr, tb, mx, digest = aggregate(
        tenant, [e for e in entries if e.tenant == tenant]
    )
    return (n, tr, tb, mx, digest)
