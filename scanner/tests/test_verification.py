"""
Unit tests for the zero-FP toolkit (scanner/verification.py).

These tests prove that the validators reject common false-positive patterns
(placeholder PII, structurally-invalid SSNs, random non-Luhn numbers, generic
keyword matches) while accepting real ones.

Run with:    python manage.py test scanner.tests.test_verification
"""
import unittest

from scanner.verification import (
    Confidence, CONFIDENCE_THRESHOLD_DEFAULT,
    luhn_check, is_real_email, is_real_ssn, detect_db_error,
    statistical_timing_test, collect_timing_samples,
    make_anchor, looks_like_login_page, looks_like_meaningful_data,
    build_finding, boost_confidence, filter_by_confidence,
)


class LuhnTests(unittest.TestCase):
    def test_known_valid_cards(self):
        # Standard test card numbers (Visa, MC, Amex, Discover)
        self.assertTrue(luhn_check("4111111111111111"))
        self.assertTrue(luhn_check("5555555555554444"))
        self.assertTrue(luhn_check("378282246310005"))
        self.assertTrue(luhn_check("6011111111111117"))

    def test_known_invalid_numbers(self):
        self.assertFalse(luhn_check("4111111111111112"))   # bad checksum
        self.assertFalse(luhn_check("1234567890123456"))   # random non-Luhn
        self.assertFalse(luhn_check("1234"))               # too short

    def test_handles_spaces_and_dashes(self):
        self.assertTrue(luhn_check("4111-1111-1111-1111"))
        self.assertTrue(luhn_check("4111 1111 1111 1111"))

    def test_rejects_non_numeric(self):
        self.assertFalse(luhn_check("4111111111111ABC"))
        self.assertFalse(luhn_check(""))


class EmailFilterTests(unittest.TestCase):
    def test_real_emails_pass(self):
        self.assertTrue(is_real_email("john.smith@gmail.com"))
        self.assertTrue(is_real_email("alice@company.co.uk"))

    def test_placeholder_domains_rejected(self):
        for e in ("user@example.com", "test@example.org", "x@test.com",
                  "y@localhost", "foo@yourdomain.com"):
            self.assertFalse(is_real_email(e), f"expected reject: {e}")

    def test_placeholder_locals_rejected(self):
        for e in ("test@somesite.com", "admin@somesite.com",
                  "noreply@somesite.com", "example@somesite.com"):
            self.assertFalse(is_real_email(e), f"expected reject: {e}")

    def test_template_tokens_rejected(self):
        self.assertFalse(is_real_email("{{user.email}}@somesite.com"))
        self.assertFalse(is_real_email("user@<host>"))


class SSNFilterTests(unittest.TestCase):
    def test_real_ssns_pass(self):
        self.assertTrue(is_real_ssn("234-56-7890"))
        self.assertTrue(is_real_ssn("123-45-6788"))

    def test_known_fakes_rejected(self):
        for s in ("000-00-0000", "123-45-6789", "111-11-1111",
                  "078-05-1120", "999-99-9999"):
            self.assertFalse(is_real_ssn(s), f"expected reject: {s}")

    def test_structurally_invalid_rejected(self):
        # SSNs cannot start with 000, 666, or 9xx
        self.assertFalse(is_real_ssn("000-12-3456"))
        self.assertFalse(is_real_ssn("666-12-3456"))
        self.assertFalse(is_real_ssn("912-34-5678"))
        # group cannot be 00, serial cannot be 0000
        self.assertFalse(is_real_ssn("234-00-5678"))
        self.assertFalse(is_real_ssn("234-56-0000"))


class DBErrorTests(unittest.TestCase):
    def test_mysql(self):
        self.assertEqual(detect_db_error("You have an error in your SQL syntax; check..."), "mysql")

    def test_postgres(self):
        self.assertEqual(detect_db_error("ERROR: unterminated quoted string at or near \"foo\""), "postgresql")

    def test_mssql(self):
        self.assertEqual(detect_db_error("Microsoft SQL Native Client error '80040e14'"), "mssql")

    def test_oracle(self):
        self.assertEqual(detect_db_error("ORA-00911: invalid character"), "oracle")

    def test_mongo(self):
        self.assertEqual(detect_db_error("MongoError: E11000 duplicate key error"), "mongodb")

    def test_generic_keyword_does_not_match(self):
        """The bare word "SQL" or "MySQL" in friendly help text must NOT fire."""
        self.assertIsNone(detect_db_error("Learn SQL with our MySQL tutorial!"))
        self.assertIsNone(detect_db_error("We use PostgreSQL for our analytics database."))
        self.assertIsNone(detect_db_error("Available databases: MySQL, PostgreSQL, MongoDB"))

    def test_empty_input(self):
        self.assertIsNone(detect_db_error(""))
        self.assertIsNone(detect_db_error(None))


class TimingTests(unittest.TestCase):
    def test_significant_delay_detected(self):
        # 4 samples around 0.1s, attack at 5s — clearly significant
        self.assertTrue(statistical_timing_test([0.1, 0.12, 0.11, 0.13], 5.0))

    def test_within_jitter_not_flagged(self):
        # Stable baseline, attack barely above — should not fire
        self.assertFalse(statistical_timing_test([0.1, 0.12, 0.11, 0.13], 0.25))

    def test_too_few_samples_returns_false(self):
        """Conservative: refuse to flag when sample size is too small."""
        self.assertFalse(statistical_timing_test([5.0], 10.0))
        self.assertFalse(statistical_timing_test([0.1, 0.1, 0.1], 5.0))

    def test_min_absolute_delay_required(self):
        """Even if statistically significant, must be > min_absolute_delay seconds."""
        # Very low variance baseline, modest attack — statistically big but
        # absolute delay is too small to be a real time-based injection.
        self.assertFalse(statistical_timing_test([0.01, 0.01, 0.01, 0.01], 1.0))

    def test_collect_timing_samples(self):
        """collect_timing_samples should swallow exceptions and return remaining samples."""
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            if calls["n"] == 3:
                raise RuntimeError("boom")

        samples = collect_timing_samples(fn, n=5)
        # 5 calls, 1 raises -> 4 valid samples
        self.assertEqual(len(samples), 4)


class MeaningfulDataTests(unittest.TestCase):
    def test_rich_json_passes(self):
        body = '{"id": 1, "username": "alice", "email": "alice@x.com", "role": "user"}'
        self.assertTrue(looks_like_meaningful_data(body, "application/json"))

    def test_trivial_status_response_rejected(self):
        self.assertFalse(looks_like_meaningful_data('{"status": "ok"}', "application/json"))
        self.assertFalse(looks_like_meaningful_data('{"success": true}', "application/json"))
        self.assertFalse(looks_like_meaningful_data('{}', "application/json"))

    def test_empty_rejected(self):
        self.assertFalse(looks_like_meaningful_data("", "application/json"))
        self.assertFalse(looks_like_meaningful_data("   ", "application/json"))

    def test_html_rejected(self):
        self.assertFalse(looks_like_meaningful_data(
            "<html><body><h1>Welcome</h1></body></html>", "text/html"))

    def test_json_array(self):
        # arrays with substantive items must pass
        body = '[{"id":1,"username":"alice"},{"id":2,"username":"bob"}]'
        self.assertTrue(looks_like_meaningful_data(body, "application/json"))
        self.assertFalse(looks_like_meaningful_data('[]', "application/json"))


class LoginPageTests(unittest.TestCase):
    def test_detects_login_page(self):
        html = '<html><body><form><input type="password"><button>Sign in</button></form></body></html>'
        self.assertTrue(looks_like_login_page(html))

    def test_non_login_page_passes(self):
        self.assertFalse(looks_like_login_page("<html>Welcome</html>"))


class FindingBuilderTests(unittest.TestCase):
    def test_basic_finding(self):
        f = build_finding("Test", "High", "desc", 8.0, "API1", Confidence.HIGH)
        self.assertEqual(f["name"], "Test")
        self.assertEqual(f["confidence"], 90)
        self.assertNotIn("evidence", f)

    def test_finding_with_evidence_and_path(self):
        f = build_finding(
            "Test", "High", "desc", 8.0, "API1",
            Confidence.HIGH, evidence={"payload": "x"}, path="/api/v1/x",
        )
        self.assertEqual(f["evidence"], {"payload": "x"})
        self.assertEqual(f["path"], "/api/v1/x")

    def test_confidence_clamped(self):
        f = build_finding("Test", "High", "desc", 8.0, "API1", 999)
        self.assertEqual(f["confidence"], 100)
        f = build_finding("Test", "High", "desc", 8.0, "API1", -10)
        self.assertEqual(f["confidence"], 0)

    def test_boost(self):
        f = build_finding("Test", "High", "desc", 8.0, "API1", Confidence.LOW)
        boost_confidence(f, delta=20)
        self.assertEqual(f["confidence"], 70)

    def test_filter_by_confidence(self):
        a = build_finding("a", "High", "x", 8.0, "API1", 90)
        b = build_finding("b", "High", "x", 8.0, "API1", 65)
        c = build_finding("c", "High", "x", 8.0, "API1", 40)
        kept = filter_by_confidence([a, b, c], threshold=70)
        self.assertEqual([f["name"] for f in kept], ["a"])


class AnchorTests(unittest.TestCase):
    def test_anchor_uniqueness(self):
        a = {make_anchor() for _ in range(100)}
        self.assertEqual(len(a), 100)

    def test_anchor_prefix(self):
        self.assertTrue(make_anchor("xss").startswith("xss"))


class IntegrationConstantsTests(unittest.TestCase):
    def test_threshold_default(self):
        self.assertEqual(CONFIDENCE_THRESHOLD_DEFAULT, 70)

    def test_confidence_ladder_ordered(self):
        self.assertLess(Confidence.SUSPICIOUS, Confidence.LOW)
        self.assertLess(Confidence.LOW, Confidence.MODERATE)
        self.assertLess(Confidence.MODERATE, Confidence.HIGH)
        self.assertLess(Confidence.HIGH, Confidence.DEFINITIVE)


if __name__ == "__main__":
    unittest.main()
