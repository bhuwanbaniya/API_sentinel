"""
Unit tests for DAST helper functions in scan_engine.py.

These tests target pure / near-pure helpers (no network) so they run fast
and deterministically. The functions that actually hit the wire are exercised
through integration scripts (test_mst.py, test_ratelimit.py) rather than here.

Run with:    python manage.py test scanner.tests.test_scan_engine_helpers
"""
import re
import unittest

from scanner.scan_engine import (
    _build_url,
    remove_dynamic_keys,
    generate_mock_param,
)
from scanner.payload_generator import PayloadGenerator


class BuildUrlTests(unittest.TestCase):
    def test_strips_trailing_slash_on_base(self):
        self.assertEqual(_build_url("http://x.com/", "/a"), "http://x.com/a")

    def test_adds_leading_slash_on_path(self):
        self.assertEqual(_build_url("http://x.com", "a/b"), "http://x.com/a/b")

    def test_no_double_slash(self):
        self.assertEqual(_build_url("http://x.com/", "/a"), "http://x.com/a")


class RemoveDynamicKeysTests(unittest.TestCase):
    def test_strips_top_level_dynamic_keys(self):
        obj = {"id": 1, "name": "x", "timestamp": "now"}
        self.assertEqual(remove_dynamic_keys(obj), {"name": "x"})

    def test_strips_nested_dynamic_keys(self):
        obj = {"user": {"id": 1, "name": "x"}, "created_at": "now"}
        self.assertEqual(
            remove_dynamic_keys(obj),
            {"user": {"name": "x"}},
        )

    def test_handles_lists(self):
        obj = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
        self.assertEqual(
            remove_dynamic_keys(obj),
            [{"name": "a"}, {"name": "b"}],
        )

    def test_passthrough_primitives(self):
        self.assertEqual(remove_dynamic_keys("hi"), "hi")
        self.assertEqual(remove_dynamic_keys(42), 42)


class GenerateMockParamTests(unittest.TestCase):
    def test_uuid_param(self):
        out = generate_mock_param("/api/sessions/{session_uuid}")
        # Real UUIDs have dashes; placeholder still has slashes
        self.assertNotIn("{", out)
        self.assertRegex(out, r"/api/sessions/[0-9a-f-]{8,}")

    def test_id_param_is_integer(self):
        out = generate_mock_param("/api/users/{user_id}")
        self.assertNotIn("{", out)
        # the substituted segment should be numeric (1000-9999)
        m = re.search(r"/api/users/(\d+)", out)
        self.assertIsNotNone(m)
        self.assertTrue(1000 <= int(m.group(1)) <= 9999)

    def test_slug_param(self):
        out = generate_mock_param("/api/products/{slug}")
        self.assertNotIn("{", out)
        self.assertIn("test-item-", out)

    def test_no_placeholders_passes_through(self):
        self.assertEqual(generate_mock_param("/api/me"), "/api/me")


class PayloadGeneratorTests(unittest.TestCase):
    def test_sqli_payloads_present(self):
        payloads = PayloadGenerator.get_sqli_payloads()
        self.assertGreater(len(payloads), 5)
        self.assertIn("' OR 1=1--", payloads)

    def test_xss_payloads_present(self):
        payloads = PayloadGenerator.get_xss_payloads()
        self.assertGreater(len(payloads), 5)
        self.assertTrue(any("<script>" in p for p in payloads))

    def test_cmd_payloads_present(self):
        payloads = PayloadGenerator.get_cmd_injection_payloads()
        self.assertGreater(len(payloads), 5)
        self.assertTrue(any("whoami" in p for p in payloads))

    def test_ssrf_payloads_target_metadata(self):
        payloads = PayloadGenerator.get_ssrf_payloads()
        self.assertTrue(any("169.254.169.254" in p for p in payloads))

    def test_xxe_payloads_contain_doctype(self):
        payloads = PayloadGenerator.get_xxe_payloads()
        self.assertTrue(all("<!DOCTYPE" in p for p in payloads))


if __name__ == "__main__":
    unittest.main()
