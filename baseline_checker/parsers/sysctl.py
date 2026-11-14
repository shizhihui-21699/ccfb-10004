"""sysctl 配置解析。

读取 ``/etc/sysctl.conf`` 与 ``/etc/sysctl.d/*.conf``(以及
``/run/sysctl.d``、``/usr/lib/sysctl.d`` 若快照里有)。
内核参数后写覆盖先写,即**最后出现生效**,解析层保留全部行并标记生效行,
被遮蔽的行同样保留证据,便于人工复核。
分隔符支持 ``=`` 与 ``:``;``-`` 前缀文件指令忽略;支持反斜杠续行。
"""
from __future__ import annotations

import os
from typing import Any

from ..models import Entry
from ..utils import logical_join, make_evidence
from .snapshot import Snapshot

LOAD_DIRS = (
    "etc/sysctl.d",
    "run/sysctl.d",
    "usr/lib/sysctl.d",
    "usr/local/lib/sysctl.d",
)
MAIN_FILE = "etc/sysctl.conf"


def _ordered_files(snap: Snapshot) -> list[str]:
    files: list[str] = []
    for d in LOAD_DIRS:
        names = sorted(r for r in snap.files if r.startswith(d.rstrip("/") + "/")
                       and r.endswith(".conf"))
        files.extend(names)
    if snap.exists(MAIN_FILE):
        files.append(MAIN_FILE)
    return files


def parse(snapshot: Snapshot) -> dict[str, Any]:
    entries: list[Entry] = []
    winning: dict[str, Entry] = {}

    for rel_path in _ordered_files(snapshot):
        lines = snapshot.read(rel_path) or []
        physical = [(i, raw.rstrip("\r\n")) for i, raw in enumerate(lines, start=1)]
        for start_line, logical, _members in logical_join(physical):
            text = logical.strip()
            if not text or text.startswith("#") or text.startswith(";"):
                continue
            if text.startswith("-"):
                text = text[1:].strip()
            sep_idx = -1
            for sep in ("=", ":"):
                sep_idx = text.find(sep)
                if sep_idx != -1:
                    break
            if sep_idx == -1:
                continue
            key = text[:sep_idx].strip().lower()
            value = text[sep_idx + 1 :].strip()
            if not key:
                continue
            entry = Entry(
                key=key,
                value=value,
                raw_value=value,
                evidence=make_evidence(rel_path, start_line, logical),
            )
            entries.append(entry)
            winning[key] = entry  # 后者覆盖前者

    # 标记被遮蔽的行
    for e in entries:
        e.extra["effective"] = winning.get(e.key) is e
        e.extra["shadowed_lines"] = [
            x.evidence.line for x in entries if x.key == e.key and x is not winning[e.key]
        ] if winning.get(e.key) is e else []

    return {"entries": entries}
