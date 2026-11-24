"""通用工具：规范 JSON、哈希、Windows 友好的原子替换与 fsync。"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "retainer-manifest-v1"


def setup_utf8_stdio() -> None:
    """让 Windows 控制台/重定向也能稳定输出 UTF-8（幂等）。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def canonical_dumps(obj: Any) -> str:
    """跨进程稳定的规范 JSON 文本（排序键、无多余空白、ASCII 转义）。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(obj: Any) -> bytes:
    return canonical_dumps(obj).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike[str] | str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def hash_manifest(manifest: dict[str, Any]) -> str:
    """清单自哈希：剔除自身的 sha256 字段后对规范 JSON 求哈希。"""
    payload = {k: v for k, v in manifest.items() if k != "sha256"}
    return sha256_bytes(canonical_bytes(payload))


def fsync_file(f) -> None:
    try:
        f.flush()
        os.fsync(f.fileno())
    except (OSError, AttributeError):
        # 某些受限/内存文件系统不支持 fsync；合成环境下不影响正确性逻辑。
        pass


def fsync_dir_best_effort(path: Path) -> None:
    """Linux 下需要 fsync 目录以保证 rename 持久；Windows 上尽力而为。"""
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def replace_with_retry(src: Path, dst: Path, attempts: int = 8, delay: float = 0.01) -> None:
    """os.replace 在 Windows 上偶发与并发读取产生共享冲突，做有限重试。"""
    last: OSError | None = None
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:  # WinError 5/32
            last = exc
            time.sleep(delay * (i + 1))
        except OSError as exc:
            # 仅对 Windows 共享/锁定类错误重试
            winerror = getattr(exc, "winerror", None)
            if winerror in (5, 32, 33):
                last = exc
                time.sleep(delay * (i + 1))
            else:
                raise
    assert last is not None
    raise last


def durable_write_new_file(final_path: Path, data: bytes) -> None:
    """写临时文件 -> fsync -> 原子发布为 final_path -> fsync 目录。

    final_path 必须是“不可变的新文件名”（如带序号的清单），调用方保证不覆盖。
    """
    final_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = final_path.with_name(f".{final_path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            fsync_file(f)
        replace_with_retry(tmp, final_path)
        fsync_dir_best_effort(final_path.parent)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def durable_atomic_pointer(pointer_path: Path, data: bytes) -> None:
    """指针切换：写 pointer.json.tmp + fsync，再 os.replace 原子覆盖指针。"""
    pointer_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = pointer_path.with_name("pointer.json.tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        fsync_file(f)
    replace_with_retry(tmp, pointer_path)
    fsync_dir_best_effort(pointer_path.parent)
