"""报告生成:单文件 HTML、机器可读 JSON、整改清单 Markdown。

HTML 全部 CSS/JS 内联,不引用任何外部资源,可直接在内网浏览器打开。
"""
from __future__ import annotations

import html
import json
from typing import Any, Optional

from .engine import Finding

SEV_LABEL = {"high": "高危", "medium": "中危", "low": "低危", "info": "提示"}
STATUS_LABEL = {"PASS": "符合", "FAIL": "不符合", "ERROR": "错误",
                "REMOVED": "规则删除", "ABSENT": "新增规则"}


def build_json(host: dict, findings: list[Finding], diff: Optional[dict] = None) -> dict:
    return {
        "schema_version": 1,
        "host": host,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
        "diff": diff,
    }


def summarize(findings: list[Finding]) -> dict[str, Any]:
    out = {"total": len(findings), "PASS": 0, "FAIL": 0, "ERROR": 0,
           "by_severity_fail": {k: 0 for k in SEV_LABEL}}
    for f in findings:
        out[f.status] = out.get(f.status, 0) + 1
        if f.status == "FAIL":
            out["by_severity_fail"][f.severity] = out["by_severity_fail"].get(f.severity, 0) + 1
    out["pass_rate"] = round(100 * out["PASS"] / max(1, len(findings)), 1)
    return out


def _esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _evidence_html(evidence: list[dict]) -> str:
    if not evidence:
        return '<div class="no-ev">未采集到对应配置(文件缺失或规则无匹配项)</div>'
    rows = []
    for ev in evidence:
        rows.append(
            f'<li><span class="path">{_esc(ev.get("path"))}</span>'
            f'<span class="line">:{_esc(ev.get("line"))}</span>'
            f'<code>{_esc(ev.get("text"))}</code></li>'
        )
    return '<ul class="ev">' + "".join(rows) + "</ul>"


def _finding_card(f: dict) -> str:
    cls = "card " + f["status"].lower()
    sev = SEV_LABEL.get(f["severity"], f["severity"])
    st = STATUS_LABEL.get(f["status"], f["status"])
    refs = "".join(f"<li>{_esc(r)}</li>" for r in f.get("references", []))
    tags = "".join(f'<span class="tag">{_esc(t)}</span>' for t in f.get("tags", []))
    actual = json.dumps(f.get("actual"), ensure_ascii=False)
    return f"""
    <details class="{cls}" {'open' if f['status'] == 'FAIL' else ''}>
      <summary>
        <span class="rid">{_esc(f['rule_id'])}</span>
        <span class="title">{_esc(f['title'])}</span>
        <span class="badge sev-{_esc(f['severity'])}">{sev}</span>
        <span class="badge st-{_esc(f['status']).lower()}">{st}</span>
        {tags}
      </summary>
      <div class="body">
        <p class="rationale">{_esc(f.get('rationale', ''))}</p>
        <table class="kv">
          <tr><th>期望</th><td><code>{_esc(f.get('operator'))} {_esc(json.dumps(f.get('expected'), ensure_ascii=False))}</code></td></tr>
          <tr><th>实际</th><td><code>{_esc(actual)}</code></td></tr>
          {f'<tr><th>说明</th><td>{_esc(f.get("message"))}</td></tr>' if f.get('message') else ''}
        </table>
        <h4>证据</h4>
        {_evidence_html(f.get('evidence', []))}
        {f'<h4>整改建议</h4><pre class="fix">{_esc(f.get("remediation"))}</pre>' if f.get('remediation') else ''}
        {f'<h4>参考依据</h4><ul class="refs">{refs}</ul>' if refs else ''}
      </div>
    </details>"""


def _diff_html(diff: dict) -> str:
    s = diff["summary"]
    cards = [
        ("improved", "变好(FAIL→PASS)", s["improved"]),
        ("regressed", "变差(PASS→FAIL)", s["regressed"]),
        ("still_failing", "仍不符合", s["still_failing"]),
        ("evidence_changed", "值有变化但仍符合", s["evidence_changed"]),
        ("still_passing", "持续符合", s["still_passing"]),
    ]
    chips = "".join(
        f'<div class="diff-chip {k}"><b>{n}</b><span>{_esc(label)}</span></div>'
        for k, label, n in cards
    )
    rows = []
    label_map = {"improved": "变好", "regressed": "变差", "still_failing": "仍不符合",
                 "still_passing": "持续符合", "evidence_changed": "值变化",
                 "rule_added": "新增规则", "rule_removed": "规则移除"}
    for it in diff["items"]:
        if it["kind"] in ("still_passing",):
            continue
        b_ev = "".join(
            f'{_esc(e["path"])}:{_esc(e["line"])}' for e in it["before"].get("evidence", [])[:2])
        a_ev = "".join(
            f'{_esc(e["path"])}:{_esc(e["line"])}' for e in it["after"].get("evidence", [])[:2])
        rows.append(
            f'<tr class="diff-row {it["kind"]}">'
            f'<td>{_esc(label_map.get(it["kind"], it["kind"]))}</td>'
            f'<td>{_esc(it["rule_id"])}</td>'
            f'<td>{_esc(it["title"])}</td>'
            f'<td>{_esc(it["before"]["status"])}<div class="ev-mini">{_esc(b_ev)}</div></td>'
            f'<td>{_esc(it["after"]["status"])}<div class="ev-mini">{_esc(a_ev)}</div></td>'
            f"</tr>"
        )
    return f"""
    <section class="diff-section">
      <h2>复测对比(两次快照)</h2>
      <div class="diff-chips">{chips}</div>
      <table class="diff-table">
        <thead><tr><th>变化</th><th>规则</th><th>检查项</th><th>上次</th><th>本次</th></tr></thead>
        <tbody>{''.join(rows) or '<tr><td colspan=5>无对比数据</td></tr>'}</tbody>
      </table>
    </section>"""


def build_html(host: dict, findings: list[Finding],
               diff: Optional[dict] = None) -> str:
    data = build_json(host, findings, diff)
    summary = data["summary"]
    fail_cards = [f.to_dict() for f in findings if f.status == "FAIL"]
    pass_cards = [f.to_dict() for f in findings if f.status == "PASS"]
    err_cards = [f.to_dict() for f in findings if f.status == "ERROR"]
    host_lines = " ".join(
        f"{k}={_esc(v)}" for k, v in host.items() if v)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>主机基线核查报告 - {_esc(host.get('host_id'))}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
  margin: 0; background: #f4f6f9; color: #1f2933; }}
header {{ background: #102a43; color: #fff; padding: 24px 32px; }}
header h1 {{ margin: 0 0 8px; font-size: 22px; }}
header .meta {{ color: #bcccdc; font-size: 13px; }}
main {{ max-width: 1080px; margin: 0 auto; padding: 24px; }}
.summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
.stat {{ background: #fff; border-radius: 10px; padding: 16px 22px; min-width: 120px;
  box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
.stat b {{ font-size: 26px; display: block; }}
.stat.fail b {{ color: #c62828; }} .stat.pass b {{ color: #2e7d32; }}
.stat.err b {{ color: #ef6c00; }} .stat.rate b {{ color: #1565c0; }}
h2 {{ border-left: 4px solid #1565c0; padding-left: 10px; margin-top: 32px; }}
details.card {{ background: #fff; border-radius: 8px; margin-bottom: 10px;
  box-shadow: 0 1px 2px rgba(0,0,0,.06); border-left: 4px solid #cbd2d9; }}
details.card.fail {{ border-left-color: #c62828; }}
details.card.pass {{ border-left-color: #2e7d32; }}
details.card.error {{ border-left-color: #ef6c00; }}
summary {{ padding: 12px 16px; cursor: pointer; display: flex; gap: 10px;
  align-items: center; flex-wrap: wrap; }}
.rid {{ font-family: ui-monospace, monospace; color: #486581; font-size: 13px;
  min-width: 130px; }}
.title {{ flex: 1; font-weight: 600; }}
.badge {{ font-size: 12px; padding: 2px 9px; border-radius: 10px; color: #fff; }}
.sev-high {{ background: #c62828; }} .sev-medium {{ background: #ef6c00; }}
.sev-low {{ background: #f9a825; }} .sev-info {{ background: #607d8b; }}
.st-pass {{ background: #2e7d32; }} .st-fail {{ background: #c62828; }}
.st-error {{ background: #ef6c00; }}
.tag {{ background: #e4e7eb; color: #334e68; font-size: 11px; padding: 2px 8px;
  border-radius: 8px; }}
.body {{ padding: 4px 18px 16px; border-top: 1px solid #e4e7eb; }}
.ev {{ list-style: none; padding: 0; margin: 6px 0; }}
.ev li {{ font-family: ui-monospace, monospace; font-size: 12.5px; padding: 3px 0;
  border-bottom: 1px dashed #e4e7eb; }}
.ev .path {{ color: #1565c0; }} .ev .line {{ color: #c62828; font-weight: 700; }}
.ev code {{ margin-left: 10px; color: #243b53; white-space: pre-wrap; }}
.no-ev {{ color: #829ab1; font-size: 13px; padding: 6px 0; }}
table.kv {{ border-collapse: collapse; width: 100%; margin: 8px 0; }}
table.kv th {{ width: 70px; text-align: left; color: #627d98; font-size: 13px;
  padding: 4px 8px; vertical-align: top; }}
table.kv td {{ padding: 4px 8px; font-size: 13px; }}
pre.fix {{ background: #f0f4f8; padding: 10px; border-radius: 6px; font-size: 12.5px;
  white-space: pre-wrap; }}
.diff-chips {{ display: flex; gap: 14px; flex-wrap: wrap; margin: 12px 0; }}
.diff-chip {{ background: #fff; border-radius: 8px; padding: 12px 18px; min-width: 130px;
  text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
.diff-chip b {{ font-size: 24px; display: block; }}
.diff-chip.improved b {{ color: #2e7d32; }} .diff-chip.regressed b {{ color: #c62828; }}
.diff-table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px;
  overflow: hidden; }}
.diff-table th, .diff-table td {{ padding: 9px 12px; font-size: 13px; text-align: left;
  border-bottom: 1px solid #e4e7eb; }}
.diff-row.improved {{ background: #e8f5e9; }}
.diff-row.regressed {{ background: #ffebee; }}
.diff-row.still_failing {{ background: #fff8e1; }}
.ev-mini {{ font-size: 11px; color: #627d98; font-family: monospace; }}
.filterbar {{ margin: 8px 0 16px; }}
.filterbar button {{ border: 1px solid #cbd2d9; background: #fff; border-radius: 6px;
  padding: 6px 14px; margin-right: 8px; cursor: pointer; font-size: 13px; }}
.filterbar button.active {{ background: #1565c0; color: #fff; border-color: #1565c0; }}
</style>
</head>
<body>
<header>
  <h1>主机配置基线核查报告</h1>
  <div class="meta">{_esc(host_lines)} | 规则数 {summary['total']} |
  符合 {summary['PASS']} / 不符合 {summary['FAIL']} / 错误 {summary['ERROR']} |
  符合率 {summary['pass_rate']}%</div>
</header>
<main>
  <div class="summary">
    <div class="stat pass"><b>{summary['PASS']}</b><span>符合</span></div>
    <div class="stat fail"><b>{summary['FAIL']}</b><span>不符合</span></div>
    <div class="stat err"><b>{summary['ERROR']}</b><span>判定错误</span></div>
    <div class="stat rate"><b>{summary['pass_rate']}%</b><span>符合率</span></div>
    <div class="stat"><b>{summary['by_severity_fail']['high']}</b><span>高危不符合</span></div>
    <div class="stat"><b>{summary['by_severity_fail']['medium']}</b><span>中危不符合</span></div>
  </div>

  {_diff_html(diff) if diff else ''}

  <h2>不符合项与整改清单({len(fail_cards)})</h2>
  <div class="filterbar">
    <button class="active" onclick="showGroup('all',this)">全部</button>
    <button onclick="showGroup('fail',this)">仅不符合</button>
    <button onclick="showGroup('pass',this)">仅符合</button>
    <button onclick="showGroup('error',this)">仅错误</button>
  </div>
  <div id="cards">
    {''.join(_finding_card(f) for f in fail_cards)}
    {''.join(_finding_card(f) for f in err_cards)}
    {''.join(_finding_card(f) for f in pass_cards)}
  </div>
</main>
<script>
function showGroup(group, btn) {{
  document.querySelectorAll('.filterbar button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('details.card').forEach(c => {{
    c.style.display = (group === 'all' || c.classList.contains(group)) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


def build_remediation_md(findings: list[Finding], host_id: str) -> str:
    fails = [f for f in findings if f.status == "FAIL"]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    fails.sort(key=lambda f: order.get(f.severity, 9))
    lines = [f"# 整改清单 - {host_id}", "",
             f"共 {len(fails)} 项不符合,按风险等级排序。", ""]
    for i, f in enumerate(fails, 1):
        lines += [
            f"## {i}. [{SEV_LABEL.get(f.severity, f.severity)}] {f.rule_id} {f.title}",
            "",
            f"- 现状值:`{json.dumps(f.actual, ensure_ascii=False)}`",
            f"- 期望:`{f.operator} {json.dumps(f.expected, ensure_ascii=False)}`",
        ]
        if f.evidence:
            ev = f.evidence[0]
            lines.append(f"- 证据位置:`{ev['path']}:{ev['line']}` → `{ev['text']}`")
        if f.remediation:
            lines += ["", "```", f.remediation, "```"]
        if f.references:
            lines.append("- 参考:" + "、".join(f.references))
        lines.append("")
    return "\n".join(lines)
