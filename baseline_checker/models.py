"""核查器通用数据模型。

所有解析结果都保留原始行号与原始文本,作为核查结论的证据。
行号统一采用 1 起始,与 ``cat -n`` / 编辑器显示一致。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Evidence:
    """一条证据:快照内相对路径 + 行号 + 原始行文本。"""

    path: str
    line: int
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "text": self.text}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        return cls(path=d["path"], line=d["line"], text=d["text"])

    def __str__(self) -> str:  # pragma: no cover - 仅用于调试
        return f"{self.path}:{self.line}: {self.text}"


@dataclass
class Entry:
    """解析后的一条配置。

    ``key``/``value`` 为归一化后的键值(小写键、去引号值);
    ``raw_value`` 保留原值(含引号、原始大小写),用于证据与精细判断;
    ``context`` 携带上下文,例如 sshd 的 Match 块、pam 的文件路径。
    """

    key: str
    value: str
    raw_value: str
    evidence: Evidence
    context: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "raw_value": self.raw_value,
            "evidence": self.evidence.to_dict(),
            "context": self.context,
            "extra": self.extra,
        }


@dataclass
class HostInfo:
    """来自 snapshot.json 的主机元数据(没有则字段为 None)。"""

    host_id: str
    distro: Optional[str] = None
    release: Optional[str] = None
    hostname: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "distro": self.distro,
            "release": self.release,
            "hostname": self.hostname,
            "extra": self.extra,
        }
