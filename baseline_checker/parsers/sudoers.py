"""/etc/sudoers 及 /etc/sudoers.d/ 解析。

要点:

- 支持 ``#include``、``#includedir``(sudoers 的 include 指令以 ``#``
  开头,这是语法不是注释)、``@include``、``@includedir``;
- 支持反斜杠续行(visudo 允许);
- User_Alias / Runas_Alias / Host_Alias / Cmnd_Alias 四类别名;
- Defaults 条目,含 ``Defaults@host``、``Defaults:user``、``Defaults!cmnd``
  限定符,以及 ``key=value``、``key``、``!key``、``-key``、``+key``;
- 用户规则 ``user host=(runas) spec cmnds``,提取命令标签
  (NOPASSWD/SETENV/NOEXEC ...),``ALL=(ALL) ALL`` 这类过宽授权单独留事实。
"""
from __future__ import annotations

import os
from typing import Any, Optional

from ..models import Entry
from ..utils import logical_join, make_evidence, split_tokens
from .snapshot import Snapshot

ALIAS_TYPES = ("User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias")


class SudoersParser:
    def __init__(self, snapshot: Snapshot) -> None:
        self.snap = snapshot
        self.entries: list[Entry] = []
        self.aliases: dict[str, dict[str, Any]] = {}
        self._visited: set[str] = set()

    def parse(self) -> dict[str, Any]:
        self._parse_file("etc/sudoers")
        return {"entries": self.entries, "aliases": self.aliases}

    def _gather_dir(self, dir_rel: str) -> list[str]:
        prefix = dir_rel.rstrip("/") + "/"
        names = [r for r in self.snap.files
                 if r.startswith(prefix) and not os.path.basename(r).endswith("~")
                 and not os.path.basename(r).startswith(".")]
        # sudoers 按文件名排序读取(忽略 ~ 结尾和 . 开头)
        return sorted(names)

    def _parse_file(self, rel_path: str) -> None:
        if rel_path in self._visited:
            return
        self._visited.add(rel_path)
        lines = self.snap.read(rel_path)
        if lines is None:
            return

        physical = [(i, self._rstrip(raw)) for i, raw in enumerate(lines, start=1)]
        for start_line, logical, members in logical_join(physical):
            text = logical.strip()
            if not text or text.startswith("#"):
                continue
            tokens = split_tokens(text)
            if not tokens:
                continue
            head = tokens[0]
            evidence = make_evidence(rel_path, start_line, logical)
            if members != [start_line]:
                evidence.text = logical

            if head in ("#include", "@include"):
                target = self._normalize_target(tokens[1])
                self._parse_file(target)
                continue
            if head in ("#includedir", "@includedir"):
                target = self._normalize_target(tokens[1], is_dir=True)
                for inc in self._gather_dir(target):
                    self._parse_file(inc)
                continue

            if head in ALIAS_TYPES:
                self._parse_alias(head, tokens, evidence, rel_path)
                continue

            if head == "Defaults" or head.startswith("Defaults"):
                self._parse_defaults(head, tokens, evidence)
                continue

            if head in ("User specification",):
                continue
            self._parse_rule(tokens, evidence, rel_path)

    @staticmethod
    def _rstrip(raw: str) -> str:
        return raw.rstrip("\r\n")

    def _normalize_target(self, token: str, is_dir: bool = False) -> str:
        if token.startswith("/"):
            return token.lstrip("/")
        return ("etc/" + token).replace("//", "/")

    def _parse_alias(self, head: str, tokens: list[str], evidence, rel_path: str) -> None:
        # User_Alias NAME = item1, item2
        try:
            eq = tokens.index("=")
        except ValueError:
            return
        name = tokens[1] if eq >= 2 else None
        if not name:
            return
        members_ = [m.strip() for m in " ".join(tokens[eq + 1 :]).split(",") if m.strip()]
        kind = head.lower()
        self.aliases[name] = {
            "kind": kind,
            "members": members_,
            "path": rel_path,
            "line": evidence.line,
        }
        self.entries.append(
            Entry(
                key=f"alias:{kind}",
                value=name,
                raw_value=",".join(members_),
                evidence=evidence,
                extra={"name": name, "members": members_},
            )
        )

    def _parse_defaults(self, head: str, tokens: list[str], evidence) -> None:
        qualifier = ""
        if head != "Defaults":
            qualifier = head[len("Defaults"):]  # @host / :user / !cmnd
        for raw_tok in tokens[1:]:
            negated = raw_tok[0] in "!-+"
            flag = raw_tok[0] if negated else ""
            tok = raw_tok[1:] if negated else raw_tok
            tok = tok.rstrip(",")  # Defaults 条目之间以逗号分隔
            if "=" in tok:
                k, v = tok.split("=", 1)
            else:
                k, v = tok, ""
            self.entries.append(
                Entry(
                    key="defaults:" + k.lower(),
                    value=v,
                    raw_value=raw_tok,
                    evidence=evidence,
                    extra={"qualifier": qualifier, "flag": flag},
                )
            )

    def _parse_rule(self, tokens: list[str], evidence, rel_path: str) -> None:
        # user host=(runas[:group]) [tags] cmnd, cmnd
        if len(tokens) < 2:
            return
        user = tokens[0]
        host = tokens[1]
        idx = 2
        runas = ""
        if idx < len(tokens) and tokens[idx].startswith("("):
            runas = tokens[idx]
            idx += 1
        tags: list[str] = []
        known_tags = {
            "NOPASSWD", "PASSWD", "SETENV", "NOSETENV", "EXEC", "NOEXEC",
            "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL",
            "NOMAIL", "FOLLOW", "NOFOLLOW", "INTERCEPT", "NOINTERCEPT",
        }
        while idx < len(tokens) and tokens[idx].rstrip(":").upper() in known_tags:
            tags.append(tokens[idx].rstrip(":").upper())
            idx += 1
        commands = " ".join(tokens[idx:]) if idx < len(tokens) else ""
        cmd_list = [c.strip() for c in commands.split(",") if c.strip()]
        self.entries.append(
            Entry(
                key="rule",
                value=user,
                raw_value=" ".join(tokens),
                evidence=evidence,
                context={"path": rel_path},
                extra={
                    "user": user,
                    "host": host,
                    "runas": runas,
                    "tags": tags,
                    "commands": cmd_list,
                },
            )
        )


def parse(snapshot: Snapshot) -> dict[str, Any]:
    return SudoersParser(snapshot).parse()
