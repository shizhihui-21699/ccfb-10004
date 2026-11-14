"""命令行入口。

用法:
    python3 -I baseline_audit.py audit  <快照目录> [--rules 规则路径] [--outdir 输出目录]
    python3 -I baseline_audit.py diff   <旧快照> <新快照> [--rules ...] [--outdir ...]
    python3 -I baseline_audit.py selftest
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import unittest

from .diff import diff_results, diff_snapshots
from .engine import Engine, load_rules
from .parsers.snapshot import load_snapshot
from .report import build_html, build_json, build_remediation_md

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def _default_outdir(snapshot_dir: str) -> str:
    return os.path.join(os.getcwd(), "audit_output", os.path.basename(os.path.abspath(snapshot_dir)))


def cmd_audit(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    engine = Engine(rules)
    snap = load_snapshot(args.snapshot)
    findings = engine.evaluate(snap)

    diff = None
    if args.baseline:
        # 与历史 JSON 结果对比
        with open(args.baseline, "r", encoding="utf-8") as fh:
            old_doc = json.load(fh)
        from .engine import Finding as F
        old_findings = [_finding_from_dict(d) for d in old_doc.get("findings", [])]
        diff = diff_results(old_findings, findings)

    outdir = args.outdir or _default_outdir(args.snapshot)
    os.makedirs(outdir, exist_ok=True)
    host = snap.host.to_dict()

    json_path = os.path.join(outdir, "result.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(build_json(host, findings, diff), fh, ensure_ascii=False, indent=2)

    html_path = os.path.join(outdir, "report.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(build_html(host, findings, diff))

    md_path = os.path.join(outdir, "remediation.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(build_remediation_md(findings, host["host_id"]))

    fails = sum(1 for f in findings if f.status == "FAIL")
    errors = sum(1 for f in findings if f.status == "ERROR")
    print(f"主机 {host['host_id']} ({host.get('distro') or '未知发行版'}): "
          f"共 {len(findings)} 项,不符合 {fails},错误 {errors}")
    print(f"报告: {html_path}\n结果: {json_path}\n整改: {md_path}")
    return 1 if fails or errors else 0


def cmd_diff(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    engine = Engine(rules)
    result = diff_snapshots(args.before, args.after, engine)

    outdir = args.outdir or os.path.join(
        os.getcwd(), "audit_output",
        "diff_" + os.path.basename(os.path.abspath(args.before))
        + "_vs_" + os.path.basename(os.path.abspath(args.after)))
    os.makedirs(outdir, exist_ok=True)
    json_path = os.path.join(outdir, "diff.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)

    # 同时产出带 diff 区块的完整 HTML(以新快照核查结果为主体)
    snap_after = load_snapshot(args.after)
    findings = engine.evaluate(snap_after)
    html_path = os.path.join(outdir, "report.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(build_html(snap_after.host.to_dict(), findings, result))

    s = result["summary"]
    print(f"对比 {args.before} -> {args.after}: "
          f"变好 {s['improved']},变差 {s['regressed']}, "
          f"仍不符合 {s['still_failing']},值变化 {s['evidence_changed']}")
    print(f"报告: {html_path}\n数据: {json_path}")
    return 1 if s["regressed"] else 0


def _finding_from_dict(d: dict):
    from .engine import Finding
    return Finding(
        rule_id=d["rule_id"], title=d["title"], component=d["component"],
        severity=d["severity"], status=d["status"], expected=d.get("expected"),
        operator=d.get("operator", ""), actual=d.get("actual"),
        evidence=d.get("evidence", []), rationale=d.get("rationale", ""),
        remediation=d.get("remediation", ""), references=d.get("references", []),
        tags=d.get("tags", []), message=d.get("message", ""),
        on_empty=d.get("on_empty", "fail"),
    )


def cmd_selftest(_args: argparse.Namespace) -> int:
    loader = unittest.TestLoader()
    start = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
    suite = loader.discover(start, pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baseline_audit",
        description="等保主机基线核查器(只读配置快照,零第三方依赖)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_audit = sub.add_parser("audit", help="对单个快照执行核查")
    p_audit.add_argument("snapshot", help="快照目录")
    p_audit.add_argument("--rules", default=DEFAULT_RULES, help="规则文件或目录")
    p_audit.add_argument("--outdir", default="", help="输出目录")
    p_audit.add_argument("--baseline", default="",
                         help="历史 result.json,存在时附带复测对比")
    p_audit.set_defaults(func=cmd_audit)

    p_diff = sub.add_parser("diff", help="对比同一机器两次快照")
    p_diff.add_argument("before")
    p_diff.add_argument("after")
    p_diff.add_argument("--rules", default=DEFAULT_RULES)
    p_diff.add_argument("--outdir", default="")
    p_diff.set_defaults(func=cmd_diff)

    p_test = sub.add_parser("selftest", help="运行内置单元测试")
    p_test.set_defaults(func=cmd_selftest)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
