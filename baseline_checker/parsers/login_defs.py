"""/etc/login.defs 解析。

格式为 ``KEY  value``(空白分隔),整行 ``#`` 注释。
同名键以最后一次出现为准(man login.defs 的规定),
保留全部重复行,生效行通过 extra.effective 标记。
"""
from __future__ import annotations

from ..models import Entry
from ..utils import make_evidence
from .snapshot import Snapshot


def parse(snapshot: Snapshot) -> dict[str, Any]:
    rel_path = "etc/login.defs"
    entries: list[Entry] = []
    lines = snapshot.read(rel_path)
    if not lines:
        return {"entries": entries}

    winning: dict[str, Entry] = {}
    for lineno, raw in enumerate(lines, start=1):
        text = raw.rstrip("\r\n").strip()
        if not text or text.startswith("#"):
            continue
        parts = text.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].upper(), parts[1].strip()
        entry = Entry(
            key=key,
            value=value,
            raw_value=value,
            evidence=make_evidence(rel_path, lineno, raw),
        )
        entries.append(entry)
        winning[key] = entry

    for e in entries:
        e.extra["effective"] = winning.get(e.key) is e
    return {"entries": entries}
