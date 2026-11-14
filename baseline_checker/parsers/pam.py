"""/etc/pam.d/ 解析。

PAM 行格式::

    type  control  module-path  module-arguments...

控制字段可能是关键字(sufficient/required/...),也可能是方括号动作列表
``[success=2 default=ignore]``,本解析器两种都保留。``include`` /
``substack`` 递归到对应服务文件。以 ``-`` 开头的模块路径表示"模块缺失不报错",
解析时去掉前缀并留痕。
"""
from __future__ import annotations

import os
from typing import Any, Optional

from ..models import Entry
from ..utils import logical_join, make_evidence, split_tokens
from .snapshot import Snapshot

TYPES = ("account", "auth", "password", "session")
SIMPLE_CONTROLS = {
    "required", "requisite", "sufficient", "optional", "include", "substack", "exclude",
}


class PamParser:
    def __init__(self, snapshot: Snapshot) -> None:
        self.snap = snapshot
        self.entries: list[Entry] = []
        self._visited: set[str] = set()

    def parse(self) -> dict[str, Any]:
        for service in self._pam_files():
            self._parse_service(service)
        return {"entries": self.entries}

    def _pam_files(self) -> list[str]:
        names = [r for r in self.snap.files if r.startswith("etc/pam.d/")]
        # common-auth/system-auth 等基础文件优先,保证 include 顺序稳定
        return sorted(names)

    def _parse_service(self, rel_path: str, depth: int = 0) -> None:
        if rel_path in self._visited or depth > 8:
            return
        self._visited.add(rel_path)
        lines = self.snap.read(rel_path)
        if lines is None:
            return
        service = os.path.basename(rel_path)
        physical = [(i, raw.rstrip("\r\n")) for i, raw in enumerate(lines, start=1)]
        for start_line, logical, members in logical_join(physical):
            text = logical.strip()
            if not text or text.startswith("#"):
                continue
            tokens = split_tokens(text)
            if len(tokens) < 2:
                continue
            evidence = make_evidence(rel_path, start_line, logical)
            ptype_raw = tokens[0].lower()
            optional_type = ptype_raw.startswith("-")
            ptype = ptype_raw.lstrip("-")

            if tokens[1].lower() in ("include", "substack"):
                target = "etc/pam.d/" + tokens[2]
                self.entries.append(
                    Entry(
                        key=f"include:{ptype}",
                        value=tokens[2],
                        raw_value=text,
                        evidence=evidence,
                        context={"service": service, "path": rel_path},
                        extra={"kind": tokens[1].lower()},
                    )
                )
                self._parse_service(target, depth + 1)
                continue

            if ptype not in TYPES:
                continue
            control = tokens[1]
            control_actions: dict[str, str] = {}
            if control.startswith("[") and control.endswith("]"):
                for action in control[1:-1].split():
                    if "=" in action:
                        a, b = action.split("=", 1)
                        control_actions[a] = b
            module_raw = tokens[2] if len(tokens) > 2 else ""
            # 模块缺失容错标记 "-" 只作用于模块路径;类型上的 "-" 已在上面剥离
            optional_missing = module_raw.startswith("-")
            module = module_raw.lstrip("-")
            args = tokens[3:]
            self.entries.append(
                Entry(
                    key=ptype,
                    value=module,
                    raw_value=text,
                    evidence=evidence,
                    context={"service": service, "path": rel_path},
                    extra={
                        "control": control,
                        "control_actions": control_actions,
                        "args": args,
                        "optional_missing": optional_missing or optional_type,
                        "optional_type": optional_type,
                    },
                )
            )


def parse(snapshot: Snapshot) -> dict[str, Any]:
    return PamParser(snapshot).parse()
