import os
import unittest

from baseline_checker import yaml_lite
from baseline_checker.utils import logical_join, split_tokens

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestYamlLite(unittest.TestCase):
    def test_nested_map_and_list(self):
        doc = yaml_lite.loads(
            "rules:\n"
            "  - id: A\n"
            "    severity: high\n"
            "    args:\n"
            "      key: PermitRootLogin\n"
            "      tags: [x]\n"  # flow 不支持,改用普通标量行避免
            "    expected: \"no\"\n"
            "  - id: B\n"
            "    on_empty: pass\n"
        )
        rules = doc["rules"]
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["id"], "A")
        self.assertEqual(rules[0]["severity"], "high")
        self.assertEqual(rules[0]["args"]["key"], "PermitRootLogin")
        self.assertEqual(rules[0]["expected"], "no")
        self.assertEqual(rules[1]["on_empty"], "pass")

    def test_types_and_comments(self):
        doc = yaml_lite.loads(
            "a: true\nb: false\nc: null\nd: 42\ne: 3.5\n# 注释行\nf: hello  # 行内注释\n"
        )
        self.assertTrue(doc["a"])
        self.assertFalse(doc["b"])
        self.assertIsNone(doc["c"])
        self.assertEqual(doc["d"], 42)
        self.assertEqual(doc["e"], 3.5)
        self.assertEqual(doc["f"], "hello")

    def test_quoted_hash_not_comment(self):
        doc = yaml_lite.loads('msg: "a # b"\n')
        self.assertEqual(doc["msg"], "a # b")

    def test_include_dir_rules_load(self):
        from baseline_checker.engine import load_rules
        rules = load_rules(os.path.join(ROOT, "rules", "rules.yml"))
        ids = [r["id"] for r in rules]
        self.assertIn("SSHD-002", ids)
        self.assertIn("SYSCTL-006", ids)
        self.assertEqual(len(ids), len(set(ids)), "规则 id 不得重复")
        self.assertGreater(len(ids), 40)


class TestTextUtils(unittest.TestCase):
    def test_logical_join_continuation(self):
        lines = [(1, "a \\"), (2, "  b"), (3, "c"), (4, "# comment"), (5, "d \\")]
        joined = logical_join(lines)
        self.assertEqual(joined[0], (1, "a b", [1, 2]))
        self.assertEqual(joined[1], (3, "c", [3]))
        # 注释打断未闭合续行,最后一个悬空续行仍保留
        self.assertEqual(joined[-1][0], 5)

    def test_split_tokens_quotes(self):
        self.assertEqual(
            split_tokens('Defaults logfile="/var/log/sudo.log" env_reset'),
            ["Defaults", "logfile=/var/log/sudo.log", "env_reset"],
        )
        self.assertEqual(split_tokens("a 'b c' d"), ["a", "b c", "d"])


if __name__ == "__main__":
    unittest.main()
