"""快照目录加载。

快照目录约定(根目录即目标机的 ``/`` 视角):

.. code-block:: text

    host-a/
      snapshot.json            # 可选:主机元数据 + 文件权限
      etc/ssh/sshd_config
      etc/ssh/sshd_config.d/...
      etc/sudoers, etc/sudoers.d/...
      etc/pam.d/...
      etc/sysctl.conf, etc/sysctl.d/...
      etc/login.defs
      etc/crontab, etc/cron.d/...
      var/spool/cron/... , var/spool/cron/crontabs/...
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from ..models import HostInfo
from ..utils import norm_rel, read_snapshot_file


@dataclass
class Snapshot:
    root: str
    host: HostInfo
    # rel_path -> 原始物理行(保留换行符)
    files: dict[str, list[str]] = field(default_factory=dict)
    # rel_path -> {"mode": "0600", "owner": "root", ...}
    file_meta: dict[str, dict] = field(default_factory=dict)
    missing: set[str] = field(default_factory=set)

    def read(self, rel_path: str) -> Optional[list[str]]:
        rel_path = norm_rel(rel_path)
        if rel_path in self.files:
            return self.files[rel_path]
        return None

    def exists(self, rel_path: str) -> bool:
        return norm_rel(rel_path) in self.files

    def meta(self, rel_path: str) -> Optional[dict]:
        return self.file_meta.get(norm_rel(rel_path))


def load_snapshot(root: str) -> Snapshot:
    """扫描快照目录,载入全部文本文件与 snapshot.json 元数据。"""
    root = os.path.abspath(root)
    host_id = os.path.basename(root.rstrip(os.sep))
    host = HostInfo(host_id=host_id)
    file_meta: dict[str, dict] = {}

    manifest_path = os.path.join(root, "snapshot.json")
    if os.path.isfile(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        host = HostInfo(
            host_id=str(manifest.get("host_id") or host_id),
            distro=manifest.get("distro"),
            release=manifest.get("release"),
            hostname=manifest.get("hostname"),
            extra={k: v for k, v in manifest.items()
                   if k not in ("host_id", "distro", "release", "hostname", "files")},
        )
        for rel, meta in (manifest.get("files") or {}).items():
            if isinstance(meta, dict):
                file_meta[norm_rel(rel)] = meta

    files: dict[str, list[str]] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            abs_path = os.path.join(dirpath, name)
            if os.path.abspath(abs_path) == os.path.abspath(manifest_path):
                continue
            rel = norm_rel(os.path.relpath(abs_path, root))
            try:
                files[rel] = read_snapshot_file(abs_path)
            except (OSError, UnicodeError):
                # 二进制或不可读文件跳过,但在 missing/元数据层面不影响其他检查
                continue

    # manifest 里声明了权限元数据、但快照未采集实体内容的文件
    # (如只收集 stat 的 /etc/shadow):登记为空文件,使 file.exists/stat 可用
    for rel in file_meta:
        files.setdefault(rel, [])

    return Snapshot(root=root, host=host, files=files, file_meta=file_meta)
