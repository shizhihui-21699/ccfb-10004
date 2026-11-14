"""规则引擎:加载 YAML 规则,对事实做判定,输出带证据的结论。

规则结构见 rules/ 目录。判定模型::

    fact + args  ->  list[FactItem]
    FactItem.value + operator + expected  ->  每条事实 true/false
    match_policy(any/all/none) + on_empty  ->  规则级 PASS/FAIL

结论中的每条证据都带快照相对路径、行号与原始行文本。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import yaml_lite
from .facts import FactItem, get_fact_fn
from .parsers.snapshot import Snapshot

SEVERITIES = ("high", "medium", "low", "info")
STATUSES = ("PASS", "FAIL", "ERROR")


class RuleError(ValueError):
    pass


@dataclass
class Finding:
    rule_id: str
    title: str
    component: str
    severity: str
    status: str  # PASS / FAIL / ERROR
    expected: Any
    operator: str
    actual: Any
    evidence: list[dict] = field(default_factory=list)
    rationale: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    message: str = ""
    on_empty: str = "fail"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "component": self.component,
            "severity": self.severity,
            "status": self.status,
            "expected": self.expected,
            "operator": self.operator,
            "actual": self.actual,
            "evidence": self.evidence,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "message": self.message,
            "on_empty": self.on_empty,
        }


# ---------------------------------------------------------------------------
# 规则加载(支持 include)
# ---------------------------------------------------------------------------
def _resolve_include(base_file: str, target: str) -> str:
    if os.path.isabs(target):
        return target
    return os.path.normpath(os.path.join(os.path.dirname(base_file), target))


def load_rules(path: str, _seen: Optional[set[str]] = None) -> list[dict]:
    """加载规则文件,递归合并 include 的规则。

    include 支持文件与目录(目录下取 *.yml/*.yaml,按文件名排序)。
    """
    _seen = _seen or set()
    path = os.path.abspath(path)
    if path in _seen:
        return []
    _seen.add(path)

    if os.path.isdir(path):
        names = sorted(n for n in os.listdir(path)
                       if n.endswith((".yml", ".yaml")))
        merged: list[dict] = []
        for name in names:
            merged.extend(load_rules(os.path.join(path, name), _seen))
        return merged

    doc = yaml_lite.load_file(path)
    if not doc:
        return []
    rules = list(doc.get("rules") or [])
    for inc in doc.get("include") or []:
        rules.extend(load_rules(_resolve_include(path, inc), _seen))
    return rules


# ---------------------------------------------------------------------------
# 算子
# ---------------------------------------------------------------------------
def _as_number(value: Any) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    m = re.match(r"^-?\d+", str(value).strip())
    if not m:
        raise ValueError(f"无法按数字比较: {value!r}")
    return float(m.group(0))


def _eval_one(operator: str, expected: Any, value: Any) -> bool:
    op = operator.lower()
    if op == "exists":
        return value is not None
    if op == "not_exists":
        return value is None
    if op in ("eq", "=="):
        return str(value).lower() == str(expected).lower()
    if op in ("ne", "!="):
        return str(value).lower() != str(expected).lower()
    if op == "contains":
        return str(expected) in str(value)
    if op == "not_contains":
        return str(expected) not in str(value)
    if op == "regex":
        return re.search(str(expected), str(value)) is not None
    if op == "in":
        allowed = [str(x).lower() for x in expected]
        return str(value).lower() in allowed
    if op == "not_in":
        forbidden = [str(x).lower() for x in expected]
        return str(value).lower() not in forbidden
    if op in ("ge", ">="):
        return _as_number(value) >= _as_number(expected)
    if op in ("le", "<="):
        return _as_number(value) <= _as_number(expected)
    if op in ("gt", ">"):
        return _as_number(value) > _as_number(expected)
    if op in ("lt", "<"):
        return _as_number(value) < _as_number(expected)
    if op == "file_mode_at_most":
        # 期望如 "0600":实际权限不得更宽松(任一权限位不得多出)
        actual = int(str(value), 8)
        want = int(str(expected), 8)
        return (actual & ~want) == 0
    if op == "list_contains":
        items = value if isinstance(value, list) else [value]
        return any(str(x).lower() == str(expected).lower() for x in items)
    if op == "list_not_contains":
        items = value if isinstance(value, list) else [value]
        return all(str(x).lower() != str(expected).lower() for x in items)
    raise RuleError(f"未知算子: {operator}")


def _pass_when_check(spec: dict, item: FactItem) -> bool:
    """规则自带的 pass_when 复合判定(用于 sudoers 等半结构化事实)。"""
    value = item.value
    meta = item.meta
    kind = spec.get("kind")
    if kind == "no_nopasswd_all":
        tags = meta.get("tags") or []
        commands = meta.get("commands") or []
        if "NOPASSWD" not in tags:
            return True
        return all(c.strip().upper() != "ALL" for c in commands)
    if kind == "runas_not_all":
        runas = (meta.get("runas") or "").upper()
        return "ALL" not in runas
    if kind == "no_wildcard_command":
        return all("*" not in c and "?" not in c for c in (meta.get("commands") or []))
    if kind == "no_risky_cron":
        return not meta.get("risky")
    if kind == "args_not_contains":
        needle = str(spec.get("arg", ""))
        return all(needle not in a for a in (meta.get("args") or []))
    if kind == "args_contains":
        needle = str(spec.get("arg", ""))
        return any(needle in a for a in (meta.get("args") or []))
    if kind == "meta_contains_arg":
        args = meta.get("args") or []
        needle = str(spec.get("arg", ""))
        return any(needle in a for a in args)
    if kind == "arg_at_most":
        # 提取模块参数中的数值上限,如 faillock 的 deny=5
        prefix = str(spec.get("arg", ""))
        limit = float(spec.get("limit"))
        values: list[float] = []
        for a in meta.get("args") or []:
            if a.startswith(prefix + "="):
                try:
                    values.append(float(a.split("=", 1)[1]))
                except ValueError:
                    continue
        if not values:
            return False
        return all(v <= limit for v in values)
    raise RuleError(f"未知 pass_when 类型: {kind}")


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------
class Engine:
    def __init__(self, rules: list[dict]) -> None:
        self.rules = rules
        self._validate()

    def _validate(self) -> None:
        seen: set[str] = set()
        for r in self.rules:
            rid = r.get("id")
            if not rid:
                raise RuleError(f"规则缺少 id: {r}")
            if rid in seen:
                raise RuleError(f"规则 id 重复: {rid}")
            seen.add(rid)
            if r.get("severity", "medium") not in SEVERITIES:
                raise RuleError(f"{rid}: 非法 severity {r.get('severity')}")
            if "fact" in r and not get_fact_fn(r["fact"]):
                raise RuleError(f"{rid}: 未注册的事实 {r['fact']}")

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        parsed_cache: dict[str, Any] = {}
        findings: list[Finding] = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            findings.append(self._eval_rule(rule, snapshot, parsed_cache))
        return findings

    def _eval_rule(self, rule: dict, snap: Snapshot, cache: dict) -> Finding:
        base = Finding(
            rule_id=rule["id"],
            title=rule.get("title", rule["id"]),
            component=rule.get("component", ""),
            severity=rule.get("severity", "medium"),
            status="ERROR",
            expected=rule.get("expected"),
            operator=rule.get("operator", ""),
            actual=None,
            rationale=rule.get("rationale", ""),
            remediation=rule.get("remediation", ""),
            references=list(rule.get("references") or []),
            tags=list(rule.get("tags") or []),
            on_empty=rule.get("on_empty", "fail"),
        )
        try:
            fn = get_fact_fn(rule["fact"])
            items = fn(snap, rule.get("args") or {}, cache) if fn else []
            base.evidence = [ev for it in items for ev in it.to_dict()["evidence"]]
            base.actual = [it.value for it in items] if len(items) != 1 else items[0].value

            if not items:
                base.status = "PASS" if base.on_empty == "pass" else "FAIL"
                base.message = rule.get("empty_message") or "未找到匹配的配置项"
                return base

            if "pass_when" in rule:
                results = [_pass_when_check(rule["pass_when"], it) for it in items]
            else:
                results = [_eval_one(base.operator, base.expected, it.value) for it in items]

            policy = rule.get("match_policy", "all")
            if policy == "all":
                ok = all(results)
            elif policy == "any":
                ok = any(results)
            elif policy == "none":
                ok = not any(results)
            else:
                raise RuleError(f"{base.rule_id}: 非法 match_policy {policy}")
            base.status = "PASS" if ok else "FAIL"
            base.message = "" if ok else (rule.get("fail_message") or self._default_fail(rule, items))
            return base
        except RuleError as exc:
            base.message = f"规则错误: {exc}"
            return base
        except (KeyError, ValueError, TypeError) as exc:
            base.message = f"判定异常: {type(exc).__name__}: {exc}"
            return base

    @staticmethod
    def _default_fail(rule: dict, items: list[FactItem]) -> str:
        actual = [it.value for it in items] if len(items) != 1 else items[0].value
        return f"实际值 {actual!r},期望 {rule.get('operator')} {rule.get('expected')!r}"
