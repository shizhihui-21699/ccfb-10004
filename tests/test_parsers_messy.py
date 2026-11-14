import os
import unittest

from baseline_checker.parsers.snapshot import load_snapshot
from baseline_checker.parsers import sshd as sshd_parser
from baseline_checker.parsers import sudoers as sudoers_parser
from baseline_checker.parsers import pam as pam_parser
from baseline_checker.parsers import sysctl as sysctl_parser
from baseline_checker.parsers import login_defs as login_parser
from baseline_checker.parsers import cron as cron_parser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(ROOT, "snapshots", "host-rhel8-messy")


class TestSshdMessy(unittest.TestCase):
    def setUp(self):
        self.snap = load_snapshot(SNAP)
        self.data = sshd_parser.parse(self.snap)
        self.entries = self.data["entries"]

    def _global_values(self, key):
        return [(e.value, e.evidence.line, e.context.get("path"))
                for e in self.entries
                if e.key == key and e.context["scope"] == "global"]

    def test_include_glob_loaded_both_files(self):
        paths = {e.context.get("path") for e in self.entries}
        self.assertIn("etc/ssh/sshd_config.d/00-first.conf", paths)
        self.assertIn("etc/ssh/sshd_config.d/99-second.conf", paths)

    def test_duplicate_key_first_wins_with_shadow_evidence(self):
        vals = self._global_values("permitrootlogin")
        # 主文件首值 yes 是"生效值"(同文件内首次出现)
        self.assertEqual(vals[0][0], "yes")
        self.assertEqual(vals[0][1], 8)
        # 三行同键都被保留
        self.assertEqual(len([v for v in vals if v[2] == "etc/ssh/sshd_config"]), 3)

    def test_comments_not_parsed(self):
        # 被注释的 #PermitEmptyPasswords no 不算;主文件内生效的只有 yes
        main = [(e.value, e.evidence.line) for e in self.entries
                if e.key == "permitemptypasswords"
                and e.context["scope"] == "global"
                and e.context.get("path") == "etc/ssh/sshd_config"]
        self.assertEqual(len(main), 1)
        self.assertEqual(main[0], ("yes", 15))

    def test_match_block_context(self):
        vendor = [e for e in self.entries
                  if e.context.get("scope") == "match"
                  and e.context.get("match_raw", "").startswith("User vendor")]
        self.assertTrue(vendor)
        root_in_vendor = [e for e in vendor if e.key == "permitrootlogin"]
        self.assertEqual(root_in_vendor[0].value, "yes")
        self.assertEqual(root_in_vendor[0].context["match"][0]["criterion"], "user")
        self.assertIn("root", root_in_vendor[0].context["match"][0]["pattern"])

    def test_match_multi_criteria(self):
        blk = next(b for b in self.data["match_blocks"]
                   if b["raw"].startswith("Address 192.168.10"))
        criteria = {c["criterion"]: c["pattern"] for c in blk["criteria"]}
        self.assertEqual(criteria["addr"], "192.168.10.0/24")
        self.assertEqual(criteria["user"].replace(" ", ""), "dba,admin")

    def test_match_from_included_file(self):
        wild = [b for b in self.data["match_blocks"] if "0.0.0.0/0" in b["raw"]]
        self.assertEqual(len(wild), 1)
        self.assertEqual(wild[0]["path"], "etc/ssh/sshd_config.d/99-second.conf")

    def test_weak_cipher_preserved(self):
        ciphers = self._global_values("ciphers")
        self.assertIn("aes128-cbc", ciphers[0][0])


class TestSudoersMessy(unittest.TestCase):
    def setUp(self):
        self.data = sudoers_parser.parse(load_snapshot(SNAP))

    def test_continuation_alias(self):
        self.assertIn("OPS", self.data["aliases"])
        self.assertEqual(self.data["aliases"]["OPS"]["members"], ["alice", "bob", "carol"])
        self.assertIn("SHUTDOWN_CMDS", self.data["aliases"])
        self.assertEqual(len(self.data["aliases"]["SHUTDOWN_CMDS"]["members"]), 3)

    def test_tilde_backup_skipped(self):
        rules = [e for e in self.data["entries"] if e.key == "rule"]
        users = [e.extra["user"] for e in rules]
        self.assertNotIn("oldadmin", users)
        # @include 引入的 extra 文件要生效
        self.assertIn("intern", users)

    def test_nopasswd_all_detected(self):
        rules = [e for e in self.data["entries"] if e.key == "rule"]
        vendor = next(e for e in rules if e.extra["user"] == "vendor")
        self.assertIn("NOPASSWD", vendor.extra["tags"])
        self.assertIn("ALL", vendor.extra["commands"])

    def test_defaults_qualifier_and_continuation(self):
        defaults = {e.key: e for e in self.data["entries"] if e.key.startswith("defaults:")}
        self.assertEqual(defaults["defaults:logfile"].value, '"/var/log/sudo.log"'.strip('"'))
        self.assertIn("defaults:log_input", defaults)
        self.assertIn("defaults:visiblepw", defaults)
        self.assertEqual(defaults["defaults:requiretty"].extra["qualifier"], ":vendor")

    def test_wildcard_command(self):
        rules = [e for e in self.data["entries"] if e.key == "rule"]
        bob = next(e for e in rules if e.extra["user"] == "bob")
        self.assertTrue(any("*" in c for c in bob.extra["commands"]))


class TestPamMessy(unittest.TestCase):
    def setUp(self):
        self.data = pam_parser.parse(load_snapshot(SNAP))
        self.entries = self.data["entries"]

    def test_bracket_control_actions(self):
        deny = next(e for e in self.entries
                    if e.value == "pam_deny.so" and e.extra["control"].startswith("["))
        self.assertEqual(deny.extra["control_actions"]["success"], "1")

    def test_continuation_line_joined(self):
        fail = [e for e in self.entries if e.value == "pam_faillock.so"]
        self.assertTrue(fail)
        # deny=10 在续行拼进同一逻辑行
        self.assertTrue(any("deny=10" in a for e in fail for a in e.extra["args"]))
        # 起始行号是物理第一行(续行块起点)
        self.assertIn(fail[0].evidence.line, (9, 11))

    def test_optional_module_prefix(self):
        systemd = next(e for e in self.entries if e.value == "pam_systemd.so")
        self.assertTrue(systemd.extra["optional_missing"])

    def test_md5_hash_flagged_in_args(self):
        unix = [e for e in self.entries if e.value == "pam_unix.so"]
        self.assertTrue(any("md5" in a for e in unix for a in e.extra["args"]))

    def test_nullok_visible(self):
        unix = [e for e in self.entries if e.value == "pam_unix.so"]
        self.assertTrue(any("nullok" in a for e in unix for a in e.extra["args"]))


class TestSysctlMessy(unittest.TestCase):
    def setUp(self):
        self.data = sysctl_parser.parse(load_snapshot(SNAP))

    def test_last_wins_and_shadow_marks(self):
        fwd = [e for e in self.data["entries"] if e.key == "net.ipv4.ip_forward"]
        winner = next(e for e in fwd if e.extra["effective"])
        # 最后一次出现生效
        self.assertEqual(winner.value, "1")
        self.assertTrue(len(fwd) >= 3)
        losers = [e for e in fwd if not e.extra["effective"]]
        self.assertTrue(losers)
        # 生效行证据携带被遮蔽行号
        self.assertTrue(winner.extra["shadowed_lines"])

    def test_colon_separator(self):
        sr = [e for e in self.data["entries"]
              if e.key == "net.ipv4.conf.all.accept_source_route"]
        self.assertEqual(sr[0].value, "1")

    def test_semicolon_comment_ignored(self):
        self.assertFalse(any(e.key == "kernel.randomize_va_space"
                             and e.value == "0"
                             for e in self.data["entries"]))

    def test_continuation_sysctl(self):
        v6 = [e for e in self.data["entries"]
              if e.key == "net.ipv6.conf.all.accept_redirects"]
        self.assertEqual(v6[0].value, "1")


class TestLoginDefsMessy(unittest.TestCase):
    def test_duplicate_last_wins(self):
        data = login_parser.parse(load_snapshot(SNAP))
        pmax = [e for e in data["entries"] if e.key == "PASS_MAX_DAYS"]
        winner = next(e for e in pmax if e.extra["effective"])
        self.assertEqual(winner.value, "120")
        self.assertEqual(winner.evidence.line, 7)
        # 4 行全部保留为证据
        self.assertEqual(len(pmax), 4)

    def test_late_duplicate_min_len(self):
        data = login_parser.parse(load_snapshot(SNAP))
        plen = [e for e in data["entries"] if e.key == "PASS_MIN_LEN"]
        winner = next(e for e in plen if e.extra["effective"])
        self.assertEqual(winner.value, "6")


class TestCronMessy(unittest.TestCase):
    def setUp(self):
        self.data = cron_parser.parse(load_snapshot(SNAP))

    def test_system_and_user_crontab(self):
        jobs = [e for e in self.data["entries"] if e.key == "job"]
        # 系统 crontab 3 条 + cron.d 2 条 + 用户 spool 2 条
        self.assertEqual(len(jobs), 7)
        user_jobs = [e for e in jobs if e.context["owner"] == "oracle"]
        self.assertEqual(len(user_jobs), 2)
        self.assertTrue(all(e.context["user"] == "oracle" for e in user_jobs))

    def test_risky_detection(self):
        jobs = [e for e in self.data["entries"] if e.key == "job"]
        risky = [e for e in jobs if e.extra["risky"]]
        commands = " ".join(e.value for e in risky)
        self.assertIn("base64", commands)
        self.assertIn("/dev/tcp", commands)
        self.assertIn("777", commands)

    def test_shortcut_schedule(self):
        jobs = [e for e in self.data["entries"] if e.key == "job"]
        reboot = next(e for e in jobs if e.extra["schedule"] == "@reboot")
        self.assertIn("base64", reboot.value)

    def test_env_lines_and_deny_list(self):
        envs = [e for e in self.data["entries"] if e.key == "env"]
        self.assertTrue(any(e.value == "RANDOM_DELAY" for e in envs))
        deny = [e for e in self.data["entries"]
                if e.key == "list" and e.context["path"] == "etc/cron.deny"]
        self.assertEqual(deny[0].value, "ALL")


if __name__ == "__main__":
    unittest.main()
