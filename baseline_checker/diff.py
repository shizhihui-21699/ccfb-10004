"""两次核查结果对比。

输入两次 audit 产生的 JSON 结果(或直接给快照目录现场核查),
按 rule_id 对齐结论,输出:

- improved:FAIL -> PASS(变好),或同 FAIL 但实际值向基线方向收敛
- regressed:PASS -> FAIL(变差),或同 FAIL 但实际值偏离基线更远
- new_failed / fixed / still_failing / still_passing
- evidence_changed:状态未变但证据/实际值变化
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .engine import Engine, Finding
from .parsers.snapshot import Snapshot, load_snapshot


@dataclass
class DiffItem:
    rule_id: str
    title: str
    severity: str
    before_status: str
    after_status: str
    before_actual: Any
    after_actual: Any
    before_evidence: list[dict] = field(default_factory=list)
    after_evidence: list[dict] = field(default_factory=list)
    kind: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "kind": self.kind,
            "before": {"status": self.before_status, "actual": self.before_actual,
                       "evidence": self.before_evidence},
            "after": {"status": self.after_status, "actual": self.after_actual,
                      "evidence": self.after_evidence},
        }


def _index(findings: list[Finding]) -> dict[str, Finding]:
    return {f.rule_id: f for f in findings}


def diff_results(before: list[Finding], after: list[Finding]) -> dict[str, Any]:
    b, a = _index(before), _index(after)
    items: list[DiffItem] = []

    for rid in sorted(set(b) | set(a)):
        old, new = b.get(rid), a.get(rid)
        if old and not new:
            items.append(DiffItem(rid, old.title, old.severity, old.status, "REMOVED",
                                  old.actual, None, old.evidence, [], kind="rule_removed"))
            continue
        if new and not old:
            items.append(DiffItem(rid, new.title, new.severity, "ABSENT", new.status,
                                  None, new.actual, [], new.evidence, kind="rule_added"))
            continue
        assert old and new
        kind = _classify(old.status, new.status, old.actual, new.actual,
                         new.operator, new.expected)
        items.append(DiffItem(rid, new.title, new.severity, old.status, new.status,
                              old.actual, new.actual, old.evidence, new.evidence, kind=kind))

    buckets: dict[str, list[dict]] = {}
    for it in items:
        buckets.setdefault(it.kind, []).append(it.to_dict())

    summary = {
        "total_rules": len(items),
        "improved": len(buckets.get("improved", [])),
        "regressed": len(buckets.get("regressed", [])),
        "still_failing": len(buckets.get("still_failing", [])),
        "still_passing": len(buckets.get("still_passing", [])),
        "evidence_changed": len(buckets.get("evidence_changed", [])),
        "rule_added": len(buckets.get("rule_added", [])),
        "rule_removed": len(buckets.get("rule_removed", [])),
    }
    return {"summary": summary, "items": [i.to_dict() for i in items], "buckets": buckets}


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    m = re.match(r"^-?\d+", str(value).strip())
    return float(m.group(0)) if m else None


def _numeric_drift(rule_operator: str, expected: Any,
                   old: Any, new: Any) -> Optional[str]:
    """同 FAIL 状态下,按数值实际值相对基线的距离判断漂移方向。

    距离基线更近 -> improved;更远 -> regressed;不可比 -> None。
    """
    o, n, e = _as_number(old), _as_number(new), _as_number(expected)
    if o is None or n is None or e is None or o == n:
        return None
    op = (rule_operator or "").lower()
    # 上界类规则(le/lt):值越小越安全
    if op in ("le", "<=", "lt", "<"):
        if n < o:
            return "improved"
        if n > o:
            return "regressed"
    # 下界类规则(ge/gt):值越大越安全
    if op in ("ge", ">=", "gt", ">"):
        if n > o:
            return "improved"
        if n < o:
            return "regressed"
    # 等价值类:数值不同视为证据变化,不贴好坏标签
    return None


def _classify(old_status: str, new_status: str, old_actual: Any, new_actual: Any,
              rule_operator: str = "", expected: Any = None) -> str:
    if old_status == "FAIL" and new_status == "PASS":
        return "improved"
    if old_status == "PASS" and new_status == "FAIL":
        return "regressed"
    if old_status == "FAIL" and new_status == "FAIL":
        drift = _numeric_drift(rule_operator, expected, old_actual, new_actual)
        if drift:
            return drift
        return "still_failing"
    if old_status == "PASS" and new_status == "PASS":
        return "evidence_changed" if old_actual != new_actual else "still_passing"
    # ERROR 参与的变化按字面归类
    if old_status != new_status:
        return "regressed" if new_status == "FAIL" else "improved"
    return "still_passing"


def diff_snapshots(before_dir: str, after_dir: str, engine: Engine) -> dict[str, Any]:
    before_snap = load_snapshot(before_dir)
    after_snap = load_snapshot(after_dir)
    before_findings = engine.evaluate(before_snap)
    after_findings = engine.evaluate(after_snap)
    result = diff_results(before_findings, after_findings)
    result["hosts"] = {
        "before": before_snap.host.to_dict(),
        "after": after_snap.host.to_dict(),
    }
    return result
