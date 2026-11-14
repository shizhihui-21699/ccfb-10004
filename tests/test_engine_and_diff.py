import json
import os
import tempfile
import unittest

from baseline_checker.diff import diff_results, diff_snapshots
from baseline_checker.engine import Engine, Finding, load_rules
from baseline_checker.parsers.snapshot import load_snapshot
from baseline_checker.report import build_html, build_remediation_md, summarize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules", "rules.yml")


def _engine():
    return Engine(load_rules(RULES))


class TestEngineOnSnapshots(unittest.TestCase):
    def test_messy_host_expected_failures(self):
        findings = _engine().evaluate(load_snapshot(
            os.path.join(ROOT, "snapshots", "host-rhel8-messy")))
        idx = {f.rule_id: f for f in findings}

        # sshd 首值生效:主文件第一行 PermitRootLogin yes -> FAIL
        self.assertEqual(idx["SSHD-002"].status, "FAIL")
        # 空密码 yes -> FAIL
        self.assertEqual(idx["SSHD-003"].status, "FAIL")
        # Match vendor 块里给 root 放开 -> 上下文规则 FAIL
        self.assertEqual(idx["SSHD-101"].status, "FAIL")
        # 0.0.0.0/0 Match -> FAIL
        self.assertEqual(idx["SSHD-103"].status, "FAIL")
        # CBC 算法 -> FAIL
        self.assertEqual(idx["SSHD-008"].status, "FAIL")
        # NOPASSWD ALL -> FAIL
        self.assertEqual(idx["SUDO-001"].status, "FAIL")
        # 通配符命令 -> FAIL
        self.assertEqual(idx["SUDO-003"].status, "FAIL")
        # faillock deny=10 > 5 -> FAIL
        self.assertEqual(idx["PAM-002"].status, "FAIL")
        # md5 哈希 -> FAIL
        self.assertEqual(idx["PAM-004"].status, "FAIL")
        # nullok -> FAIL
        self.assertEqual(idx["PAM-005"].status, "FAIL")
        # 转发最终生效值 1 -> FAIL
        self.assertEqual(idx["SYSCTL-001"].status, "FAIL")
        # syncookies 在 sysctl.d 被覆盖为 0 -> FAIL
        self.assertEqual(idx["SYSCTL-006"].status, "FAIL")
        # 危险 cron -> FAIL
        self.assertEqual(idx["CRON-003"].status, "FAIL")
        # shadow 0666 -> FAIL
        self.assertEqual(idx["FILE-001"].status, "FAIL")

    def test_evidence_has_line_numbers(self):
        findings = _engine().evaluate(load_snapshot(
            os.path.join(ROOT, "snapshots", "host-rhel8-messy")))
        for f in findings:
            if f.status == "FAIL" and f.evidence:
                ev = f.evidence[0]
                self.assertTrue(ev["path"])
                self.assertIsInstance(ev["line"], int)
                self.assertIn("text", ev)

    def test_rhel8_compliant_host_mostly_pass(self):
        findings = _engine().evaluate(load_snapshot(
            os.path.join(ROOT, "snapshots", "host-rhel8")))
        idx = {f.rule_id: f for f in findings}
        self.assertEqual(idx["SSHD-002"].status, "PASS")
        self.assertEqual(idx["SSHD-005"].status, "PASS")
        self.assertEqual(idx["PAM-001"].status, "PASS")
        self.assertEqual(idx["SYSCTL-006"].status, "PASS")
        self.assertEqual(idx["FILE-001"].status, "PASS")
        # RHEL8 没配 AllowGroups 之外的缺失项检查: AllowGroups 已配置 -> PASS
        self.assertEqual(idx["SSHD-015"].status, "PASS")

    def test_missing_files_on_empty_host(self):
        findings = _engine().evaluate(load_snapshot(
            os.path.join(ROOT, "snapshots", "host-debian11")))
        idx = {f.rule_id: f for f in findings}
        # on_empty: fail 的规则在文件缺失时必须 FAIL 而不是报错
        self.assertEqual(idx["SSHD-002"].status, "FAIL")
        # on_empty: pass 的规则缺省应 PASS(如 SSHD-001)
        self.assertEqual(idx["SSHD-001"].status, "PASS")
        # 不应出现未捕获异常导致的 ERROR(规则本身写错除外)
        errors = [f.rule_id for f in findings if f.status == "ERROR"]
        self.assertEqual(errors, [])

    def test_match_block_isolation(self):
        findings = _engine().evaluate(load_snapshot(
            os.path.join(ROOT, "snapshots", "host-rhel8")))
        idx = {f.rule_id: f for f in findings}
        # RHEL8 没有针对 root 的 Match,SSHD-101 on_empty=pass
        self.assertEqual(idx["SSHD-101"].status, "PASS")


class TestDiff(unittest.TestCase):
    def test_diff_improved_and_regressed(self):
        engine = _engine()
        result = diff_snapshots(
            os.path.join(ROOT, "snapshots", "host-ubuntu2204"),
            os.path.join(ROOT, "snapshots", "host-ubuntu2204-fixed"),
            engine,
        )
        buckets = result["buckets"]
        improved_ids = {i["rule_id"] for i in buckets.get("improved", [])}
        regressed_ids = {i["rule_id"] for i in buckets.get("regressed", [])}

        self.assertIn("SSHD-002", improved_ids)       # root 登录 yes -> no
        self.assertIn("SUDO-001", improved_ids)       # NOPASSWD ALL 取消
        self.assertIn("CRON-003", improved_ids)       # 恶意 cron 删除
        self.assertIn("FILE-001", improved_ids)       # shadow 644 -> 600
        # 故意埋的变差项
        self.assertIn("SUDO-007", regressed_ids)
        self.assertGreaterEqual(result["summary"]["improved"], 10)

    def test_diff_carries_evidence(self):
        engine = _engine()
        result = diff_snapshots(
            os.path.join(ROOT, "snapshots", "host-ubuntu2204"),
            os.path.join(ROOT, "snapshots", "host-ubuntu2204-fixed"),
            engine,
        )
        item = next(i for i in result["items"] if i["rule_id"] == "SSHD-002")
        self.assertTrue(item["before"]["evidence"])
        self.assertTrue(item["after"]["evidence"])
        self.assertEqual(item["before"]["evidence"][0]["line"], 6)


class TestReport(unittest.TestCase):
    def test_html_and_markdown_render(self):
        engine = _engine()
        snap = load_snapshot(os.path.join(ROOT, "snapshots", "host-rhel8-messy"))
        findings = engine.evaluate(snap)
        html_text = build_html(snap.host.to_dict(), findings)
        self.assertIn("主机配置基线核查报告", html_text)
        self.assertIn("host-rhel8-messy", html_text)
        # 每条 FAIL 都进了 HTML
        for f in findings:
            if f.status == "FAIL":
                self.assertIn(f.rule_id, html_text)
        md = build_remediation_md(findings, "host-rhel8-messy")
        self.assertIn("# 整改清单", md)
        # 高危排在前面
        first_high = md.find("高危")
        first_med = md.find("中危")
        if first_high != -1 and first_med != -1:
            self.assertLess(first_high, first_med)

    def test_json_roundtrip(self):
        engine = _engine()
        snap = load_snapshot(os.path.join(ROOT, "snapshots", "host-rhel8"))
        findings = engine.evaluate(snap)
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "r.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump([f.to_dict() for f in findings], fh, ensure_ascii=False)
            with open(p, encoding="utf-8") as fh:
                loaded = json.load(fh)
        self.assertEqual(len(loaded), len(findings))
        self.assertTrue(all("evidence" in f for f in loaded))


if __name__ == "__main__":
    unittest.main()
