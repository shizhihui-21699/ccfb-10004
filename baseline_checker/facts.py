"""事实层:把解析结果组织成规则可查询的事实。

规则 YAML 不直接接触解析器,而是通过 ``fact: 组件.事实名`` 调用这里注册的
事实函数。每个事实返回若干 :class:`FactItem`,统一携带值与证据,
规则引擎只负责"事实 + 算子 + 期望值"的判定。
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .models import Evidence
from .parsers import cron as cron_parser
from .parsers import login_defs as login_parser
from .parsers import pam as pam_parser
from .parsers import sshd as sshd_parser
from .parsers import sudoers as sudoers_parser
from .parsers import sysctl as sysctl_parser
from .parsers.snapshot import Snapshot


@dataclass
class FactItem:
    value: Any
    evidence: list[Evidence] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "meta": self.meta,
        }


FactFn = Callable[[Snapshot, dict[str, Any], dict[str, Any]], list[FactItem]]
_REGISTRY: dict[str, FactFn] = {}


def fact(component: str, name: str):
    key = f"{component}.{name}"

    def deco(fn: FactFn) -> FactFn:
        _REGISTRY[key] = fn
        return fn

    return deco


def get_fact_fn(key: str) -> Optional[FactFn]:
    return _REGISTRY.get(key)


def registered_facts() -> list[str]:
    return sorted(_REGISTRY)


# ---------------------------------------------------------------------------
# 通用辅助
# ---------------------------------------------------------------------------
def _match_selector(entry_ctx_match: Optional[list[dict[str, str]]],
                    selector: dict[str, Any]) -> bool:
    """判断 sshd Match 条件是否满足规则里的 match 选择器。

    Match 模式列表同时支持逗号与空格分隔(``User dba,admin``)。
    """
    if not selector:
        return entry_ctx_match is None
    if entry_ctx_match is None:
        return False
    want_crit = {k.lower(): str(v).lower() for k, v in selector.items()}
    got = {c["criterion"].lower(): c["pattern"].lower() for c in entry_ctx_match}
    for crit, pattern in want_crit.items():
        if crit not in got:
            return False
        got_patterns = [p.strip() for p in got[crit].replace(",", " ").split()]
        if not any(fnmatch.fnmatchcase(got_p, pattern) for got_p in got_patterns):
            return False
    return True


# ---------------------------------------------------------------------------
# sshd
# ---------------------------------------------------------------------------
@fact("sshd", "setting")
def sshd_setting(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("sshd", sshd_parser.parse(snap))
    key = str(args["key"]).lower()
    selector = args.get("match") or {}
    want_global = not selector
    items: list[FactItem] = []
    for e in data["entries"]:
        if e.key != key:
            continue
        is_global = e.context.get("scope") == "global"
        if want_global:
            if not is_global:
                continue
        else:
            if is_global or not _match_selector(e.context.get("match"), selector):
                continue
        shadowed = [
            x.evidence for x in data["entries"]
            if x.key == key and x.context.get("scope") == e.context.get("scope")
            and x is not e
        ]
        items.append(
            FactItem(
                value=e.value,
                evidence=[e.evidence] + shadowed,
                meta={
                    "scope": e.context.get("scope"),
                    "effective": True,
                    "match": e.context.get("match_raw"),
                    "note": "sshd 同名指令首次出现生效" if shadowed else "",
                },
            )
        )
    return items[:1] if items else []


@fact("sshd", "match_blocks")
def sshd_match_blocks(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("sshd", sshd_parser.parse(snap))
    return [
        FactItem(
            value=blk["raw"],
            evidence=[Evidence(blk["path"], blk["line"], f"Match {blk['raw']}")],
            meta={"criteria": blk["criteria"]},
        )
        for blk in data["match_blocks"]
    ]


# ---------------------------------------------------------------------------
# sysctl
# ---------------------------------------------------------------------------
@fact("sysctl", "param")
def sysctl_param(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("sysctl", sysctl_parser.parse(snap))
    key = str(args["key"]).lower()
    out = []
    for e in data["entries"]:
        if e.key != key:
            continue
        out.append(
            FactItem(
                value=e.value,
                evidence=[e.evidence],
                meta={"effective": e.extra.get("effective", False),
                      "shadowed_lines": e.extra.get("shadowed_lines", [])},
            )
        )
    # 只回生效值,但证据里附上被遮蔽行
    effective = [x for x in out if x.meta["effective"]]
    return effective or out[:1]


# ---------------------------------------------------------------------------
# login.defs
# ---------------------------------------------------------------------------
@fact("login_defs", "setting")
def login_setting(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("login_defs", login_parser.parse(snap))
    key = str(args["key"]).upper()
    matched = [e for e in data["entries"] if e.key == key]
    if not matched:
        return []
    winner = next((e for e in matched if e.extra.get("effective")), matched[-1])
    return [
        FactItem(
            value=winner.value,
            evidence=[e.evidence for e in matched],
            meta={"effective_line": winner.evidence.line},
        )
    ]


# ---------------------------------------------------------------------------
# sudoers
# ---------------------------------------------------------------------------
@fact("sudoers", "defaults")
def sudoers_defaults(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("sudoers", sudoers_parser.parse(snap))
    key = "defaults:" + str(args["key"]).lower()
    out = []
    for e in data["entries"]:
        if e.key != key:
            continue
        out.append(
            FactItem(
                value=e.value,
                evidence=[e.evidence],
                meta={"flag": e.extra.get("flag", ""),
                      "qualifier": e.extra.get("qualifier", "")},
            )
        )
    return out


@fact("sudoers", "rules")
def sudoers_rules(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("sudoers", sudoers_parser.parse(snap))
    tag_filter = [t.upper() for t in (args.get("tags") or [])]
    user_pattern = args.get("user")
    cmd_pattern = args.get("command")
    out: list[FactItem] = []
    for e in data["entries"]:
        if e.key != "rule":
            continue
        ex = e.extra
        if tag_filter and not all(t in ex["tags"] for t in tag_filter):
            continue
        if user_pattern and not fnmatch.fnmatchcase(ex["user"], user_pattern):
            continue
        if cmd_pattern and not any(fnmatch.fnmatchcase(c, cmd_pattern) for c in ex["commands"]):
            continue
        out.append(
            FactItem(
                value=ex["user"],
                evidence=[e.evidence],
                meta={
                    "host": ex["host"],
                    "runas": ex["runas"],
                    "tags": ex["tags"],
                    "commands": ex["commands"],
                    "raw": e.raw_value,
                },
            )
        )
    return out


@fact("sudoers", "aliases")
def sudoers_aliases(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("sudoers", sudoers_parser.parse(snap))
    kind = (args.get("kind") or "").lower()
    name_pattern = args.get("name")
    out = []
    for alias_name, info in data["aliases"].items():
        if kind and not info["kind"].endswith(kind):
            continue
        if name_pattern and not fnmatch.fnmatchcase(alias_name, name_pattern):
            continue
        out.append(
            FactItem(
                value=alias_name,
                evidence=[Evidence("etc/sudoers", info["line"],
                                   f"{info['kind']} {alias_name} = {','.join(info['members'])}")],
                meta=info,
            )
        )
    return out


# ---------------------------------------------------------------------------
# pam
# ---------------------------------------------------------------------------
@fact("pam", "lines")
def pam_lines(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("pam", pam_parser.parse(snap))
    type_ = (args.get("type") or "").lower()
    service_pattern = args.get("service")
    module_pattern = args.get("module")
    control = (args.get("control") or "").lower()
    out = []
    for e in data["entries"]:
        if e.key.startswith("include:"):
            continue
        if type_ and e.key != type_:
            continue
        if service_pattern and not fnmatch.fnmatchcase(e.context["service"], service_pattern):
            continue
        if module_pattern and not fnmatch.fnmatchcase(e.value, module_pattern):
            continue
        if control and e.extra["control"].lower() != control:
            continue
        out.append(
            FactItem(
                value=e.value,
                evidence=[e.evidence],
                meta={
                    "service": e.context["service"],
                    "type": e.key,
                    "control": e.extra["control"],
                    "args": e.extra["args"],
                },
            )
        )
    return out


# ---------------------------------------------------------------------------
# cron
# ---------------------------------------------------------------------------
@fact("cron", "jobs")
def cron_jobs(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("cron", cron_parser.parse(snap))
    risky_only = bool(args.get("risky_only"))
    user_pattern = args.get("user")
    out = []
    for e in data["entries"]:
        if e.key != "job":
            continue
        if risky_only and not e.extra.get("risky"):
            continue
        if user_pattern and not fnmatch.fnmatchcase(e.context.get("user", ""), user_pattern):
            continue
        out.append(
            FactItem(
                value=e.value,
                evidence=[e.evidence],
                meta={"user": e.context.get("user"),
                      "schedule": e.extra["schedule"],
                      "risky": e.extra["risky"],
                      "path": e.context.get("path")},
            )
        )
    return out


@fact("cron", "access_list")
def cron_access(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    data = parsed_cache.setdefault("cron", cron_parser.parse(snap))
    want_path = "etc/" + str(args["file"])
    out = []
    for e in data["entries"]:
        if e.key == "list" and e.context.get("path") == want_path:
            out.append(FactItem(value=e.value, evidence=[e.evidence]))
    return out


# ---------------------------------------------------------------------------
# 文件级事实(权限/存在性,证据来自 snapshot.json)
# ---------------------------------------------------------------------------
@fact("file", "stat")
def file_stat(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    rel = str(args["path"]).lstrip("/")
    if not snap.exists(rel):
        return []
    meta = snap.meta(rel) or {}
    mode = meta.get("mode", "")
    return [FactItem(value=mode,
                     evidence=[Evidence(rel, 0, f"元数据: {meta or '未采集权限'}")],
                     meta={"path": rel, **meta})]


@fact("file", "exists")
def file_exists(snap: Snapshot, args: dict, parsed_cache: dict) -> list[FactItem]:
    rel = str(args["path"]).lstrip("/")
    return [FactItem(value=snap.exists(rel),
                     evidence=[Evidence(rel, 0, "文件存在" if snap.exists(rel) else "文件缺失")])]
