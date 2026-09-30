import json
import unittest

from dnswatch.analyzer import analyze, findings_as_sarif, parse_zeek, shannon_entropy


LOG = """#separator \\x09
#fields ts\\tid.orig_h\\tquery\\trcode
1.0\\t10.0.0.5\\tcdn.example.com\\tNOERROR
2.0\\t10.0.0.5\\tcdn.example.com\\tNOERROR
3.0\\t10.0.0.5\\tcdn.example.com\\tNXDOMAIN
4.0\\t10.0.0.5\\tcdn.example.com\\tNXDOMAIN
5.0\\t10.0.0.5\\tcdn.example.com\\tNXDOMAIN
6.0\\t10.0.0.5\\tcdn.example.com\\tNXDOMAIN
7.0\\t10.0.0.5\\tcdn.example.com\\tNXDOMAIN
8.0\\t10.0.0.5\\tverylonglabel-abcdefghijklmnopqrstuvwxyz.example\\tNOERROR
""".replace("\\t", "\t")


class AnalyzerTests(unittest.TestCase):
    def test_parser_and_heuristics(self) -> None:
        records = list(parse_zeek(LOG))
        findings = analyze(records, max_queries=3, max_query_length=30)
        ids = {finding.rule_id for finding in findings}
        self.assertIn("DNS-HIGH-FREQUENCY", ids)
        self.assertIn("DNS-NXDOMAIN-RATE", ids)
        self.assertIn("DNS-LONG-QUERY", ids)

    def test_entropy_is_zero_for_repeated_text(self) -> None:
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy("a1b2c3d4"), 2.0)

    def test_sarif_is_valid_json(self) -> None:
        findings = analyze(list(parse_zeek(LOG)))
        sarif = json.loads(findings_as_sarif(findings))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)


if __name__ == "__main__":
    unittest.main()

