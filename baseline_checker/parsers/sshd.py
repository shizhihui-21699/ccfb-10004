"""sshd_config 解析。

覆盖等保快照里常见的复杂写法:

- ``#`` 注释、行内注释(sshd 仅支持整行注释,行内 ``#`` 属于参数,
  因此这里不做行内注释剥离);
- ``Include`` / ``include`` 指令,支持绝对/相对路径与 glob 通配,
  按 sshd 的出现顺序递归处理,带深度与循环包含保护;
- ``Match`` 块,块内配置带上下文(条件列表),块在遇到下一个 Match 或
  文件结束时终止;
- 重复键:sshd 对同一上下文采用**首次出现生效**,解析层保留全部行,
  由事实层挑选生效值并把被遮蔽的行一并留证;
- 参数大小写不敏感(键归一为小写),参数值保留原样。
"""
from __future__ import annotations

import glob
import os
from typing import Any, Optional

from ..models import Entry
from ..utils import make_evidence, strip_newline
from .snapshot import Snapshot

MAX_INCLUDE_DEPTH = 12
DEFAULT_INCLUDE_BASE = "etc/ssh"


class SshdParseError(ValueError):
    pass


def _tokenize(line: str) -> list[str]:
    # sshd 不支持引号续行,简单按空白分词即可
    return line.split()


class SshdParser:
    def __init__(self, snapshot: Snapshot) -> None:
        self.snap = snapshot
        self.entries: list[Entry] = []
        self.match_blocks: list[dict[str, Any]] = []
        self._seen: set[str] = set()

    def parse(self) -> dict[str, Any]:
        main = "etc/ssh/sshd_config"
        self._parse_file(main, depth=0)
        return {"entries": self.entries, "match_blocks": self.match_blocks}

    def _resolve_include(self, pattern: str) -> list[str]:
        """把 Include 模式解析为快照内已存在的文件相对路径(有序)。"""
        if pattern.startswith("/"):
            rel_pattern = pattern.lstrip("/")
            base_dir = ""
        elif pattern.startswith("~"):
            # ~ 在快照里无法还原家目录,按 /etc/ssh 下处理并去掉前缀
            rel_pattern = os.path.join(DEFAULT_INCLUDE_BASE, pattern.lstrip("~/")).replace(os.sep, "/")
            base_dir = ""
        else:
            rel_pattern = os.path.join(DEFAULT_INCLUDE_BASE, pattern).replace(os.sep, "/")
            base_dir = ""
        abs_pattern = os.path.join(self.snap.root, rel_pattern)
        matches = sorted(glob.glob(abs_pattern))
        result = []
        for abs_path in matches:
            if not os.path.isfile(abs_path):
                continue
            rel = os.path.relpath(abs_path, self.snap.root).replace(os.sep, "/")
            if rel in self.snap.files:
                result.append(rel)
        return result

    def _parse_file(self, rel_path: str, depth: int) -> None:
        if depth > MAX_INCLUDE_DEPTH:
            raise SshdParseError(f"Include 嵌套超过 {MAX_INCLUDE_DEPTH} 层: {rel_path}")
        key = f"d{depth}:{rel_path}"
        if key in self._seen:
            # 循环包含:sshd 行为未定义,这里直接忽略并保留可追踪性
            return
        self._seen.add(key)

        lines = self.snap.read(rel_path)
        if lines is None:
            return

        current_match: Optional[dict[str, Any]] = None
        for lineno, raw in enumerate(lines, start=1):
            text = strip_newline(raw).strip()
            if not text or text.startswith("#"):
                continue
            tokens = _tokenize(text)
            if not tokens:
                continue
            directive = tokens[0].lower()
            args = tokens[1:]

            if directive == "include":
                for pattern in args:
                    for included in self._resolve_include(pattern):
                        self._parse_file(included, depth + 1)
                continue

            if directive == "match":
                criteria = self._parse_match_args(args, rel_path, lineno)
                current_match = {
                    "criteria": criteria,
                    "raw": " ".join(args),
                    "path": rel_path,
                    "line": lineno,
                }
                self.match_blocks.append(current_match)
                continue

            if not args:
                continue
            value = " ".join(args)
            context: dict[str, Any] = {
                "scope": "match" if current_match else "global",
                "path": rel_path,
            }
            if current_match:
                context["match"] = current_match["criteria"]
                context["match_raw"] = current_match["raw"]
                context["match_line"] = current_match["line"]
                context["match_path"] = current_match["path"]
            self.entries.append(
                Entry(
                    key=directive,
                    value=value,
                    raw_value=value,
                    evidence=make_evidence(rel_path, lineno, raw),
                    context=context,
                )
            )

    @staticmethod
    def _parse_match_args(args: list[str], path: str, lineno: int) -> list[dict[str, str]]:
        """Match user root,host *.example.com addr 10.0.0.* -> 结构化条件。"""
        criteria: list[dict[str, str]] = []
        known = {
            "all", "canonical", "final", "exec", "host", "originalhost",
            "user", "group", "localuser", "localgroup", "addr", "address",
        }
        current: Optional[dict[str, str]] = None
        for tok in args:
            head = tok.lower()
            if head in known:
                # Address 是 Addr 的同义词,统一归一为 addr
                norm = "addr" if head == "address" else head
                current = {"criterion": norm, "pattern": ""}
                criteria.append(current)
            elif current is None:
                raise SshdParseError(f"Match 条件无法解析: {tok} ({path}:{lineno})")
            else:
                # 模式内部折叠空白,便于规则匹配
                current["pattern"] = " ".join((current["pattern"] + " " + tok).split())
        return criteria


def parse(snapshot: Snapshot) -> dict[str, Any]:
    return SshdParser(snapshot).parse()
