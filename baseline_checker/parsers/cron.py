"""cron 相关快照解析。

覆盖:

- ``/etc/crontab`` 与 ``/etc/cron.d/*``:五时间字段 + 用户名 + 命令;
- ``/var/spool/cron/``、``/var/spool/cron/crontabs/``:用户 crontab,
  五时间字段后直接是命令(无用户名列);
- ``NAME=value`` 环境变量行、``#`` 注释、空行;
- ``/etc/cron.allow``、``/etc/cron.deny``、``/etc/at.allow``、``/etc/at.deny``
  按行解析为名单事实;
- 标记危险命令特征(curl|wget 管道 shell、写系统目录、chmod 777 等)。
"""
from __future__ import annotations

import os
import re
from typing import Any

from ..models import Entry
from ..utils import make_evidence
from .snapshot import Snapshot

SYSTEM_DIRS = ("etc/cron.d",)
SPOOL_DIRS = ("var/spool/cron", "var/spool/cron/crontabs")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
RISKY_PATTERNS = (
    re.compile(r"curl\b[^|]*\|\s*(ba|z|da)?sh\b"),
    re.compile(r"wget\b[^|]*\|\s*(ba|z|da)?sh\b"),
    re.compile(r"chmod\s+-R?\s*777\b"),
    re.compile(r"/dev/(tcp|udp)/"),
    re.compile(r"\b(ba|z|da)?sh\b.*\b(http|ftp)://"),
    re.compile(r"\bnc\b.*-e\b"),
    re.compile(r"base64\s+-d"),
)
SHORT = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly",
         "@daily", "@midnight", "@hourly"}


def _is_risky(command: str) -> list[str]:
    return [p.pattern for p in RISKY_PATTERNS if p.search(command)]


def _parse_crontab(rel_path: str, lines: list[str], has_user: bool,
                   owner: str, entries: list[Entry]) -> None:
    for lineno, raw in enumerate(lines, start=1):
        text = raw.rstrip("\r\n").strip()
        if not text or text.startswith("#"):
            continue
        if ENV_RE.match(text):
            k, _, v = text.partition("=")
            entries.append(
                Entry(key="env", value=k.strip(), raw_value=v.strip(),
                      evidence=make_evidence(rel_path, lineno, raw),
                      context={"path": rel_path, "owner": owner}))
            continue
        parts = text.split()
        schedule_kind = "shortcut" if parts[0] in SHORT else "five-field"
        if schedule_kind == "shortcut":
            # @reboot [user] command
            if len(parts) < 2:
                continue
            schedule = parts[0]
            rest = parts[1:]
            if has_user and len(rest) >= 2:
                user, command = rest[0], " ".join(rest[1:])
            else:
                user, command = owner, " ".join(rest)
        else:
            if len(parts) < 6:
                continue
            schedule = " ".join(parts[:5])
            rest = parts[5:]
            if has_user:
                if len(rest) < 2:
                    # 系统 crontab 缺用户名列,容错按 owner 处理
                    user, command = owner, " ".join(rest)
                else:
                    user, command = rest[0], " ".join(rest[1:])
            else:
                user, command = owner, " ".join(rest)
        entries.append(
            Entry(
                key="job",
                value=command,
                raw_value=text,
                evidence=make_evidence(rel_path, lineno, raw),
                context={"path": rel_path, "user": user, "owner": owner},
                extra={
                    "schedule": schedule,
                    "schedule_kind": schedule_kind,
                    "risky": _is_risky(command),
                },
            )
        )


def _parse_list_file(rel_path: str, lines: list[str]) -> list[Entry]:
    out: list[Entry] = []
    for lineno, raw in enumerate(lines, start=1):
        name = raw.strip()
        if not name or name.startswith("#"):
            continue
        out.append(
            Entry(key="list", value=name, raw_value=name,
                  evidence=make_evidence(rel_path, lineno, raw),
                  context={"path": rel_path}))
    return out


def parse(snapshot: Snapshot) -> dict[str, Any]:
    entries: list[Entry] = []

    if snapshot.exists("etc/crontab"):
        _parse_crontab("etc/crontab", snapshot.read("etc/crontab") or [],
                       has_user=True, owner="root", entries=entries)

    for d in SYSTEM_DIRS:
        for rel in sorted(r for r in snapshot.files if r.startswith(d.rstrip("/") + "/")):
            if os.path.basename(rel).startswith(".") or rel.endswith("~"):
                continue
            _parse_crontab(rel, snapshot.read(rel) or [],
                           has_user=True, owner="root", entries=entries)

    spool_seen: set[str] = set()
    for d in SPOOL_DIRS:
        for rel in sorted(r for r in snapshot.files if r.startswith(d.rstrip("/") + "/")):
            # 两个 spool 根目录存在嵌套(var/spool/cron 与其下 crontabs),
            # 同一文件只按最深匹配处理一次
            if rel in spool_seen:
                continue
            spool_seen.add(rel)
            owner = os.path.basename(rel)
            _parse_crontab(rel, snapshot.read(rel) or [],
                           has_user=False, owner=owner, entries=entries)

    for rel in ("etc/cron.allow", "etc/cron.deny", "etc/at.allow", "etc/at.deny"):
        if snapshot.exists(rel):
            entries.extend(_parse_list_file(rel, snapshot.read(rel) or []))

    return {"entries": entries}
