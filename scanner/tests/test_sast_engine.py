"""
Unit tests for the SAST (Static Application Security Testing) engine.

These tests build a tiny on-disk "project" inside a temp dir and run the
SASTScanner against it, asserting that the expected vulnerability categories
are detected and that obviously-safe code does NOT trigger false positives.

Run with:    python manage.py test scanner.tests.test_sast_engine
"""
import os
import shutil
import tempfile
import unittest

from scanner.sast_engine import SASTScanner


def _write(path, contents):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(contents)


class SASTScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sast_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---------- Shadow API extraction ----------
    def test_detects_flask_route(self):
        _write(os.path.join(self.tmp, "app.py"),
               "@app.route('/api/v1/users')\ndef users(): pass\n")
        report = SASTScanner(self.tmp).scan_directory()
        self.assertIn("ANY /api/v1/users", report["endpoints"])

    def test_detects_express_route(self):
        _write(os.path.join(self.tmp, "server.js"),
               "app.get('/api/products', (req, res) => res.json([]));\n")
        report = SASTScanner(self.tmp).scan_directory()
        self.assertIn("GET /api/products", report["endpoints"])

    def test_detects_django_path(self):
        _write(os.path.join(self.tmp, "urls.py"),
               "urlpatterns = [path('api/orders/', views.orders)]\n")
        report = SASTScanner(self.tmp).scan_directory()
        self.assertTrue(any("orders" in e for e in report["endpoints"]))

    # ---------- Secret detection ----------
    def test_detects_aws_access_key(self):
        _write(os.path.join(self.tmp, "leak.py"),
               'aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        report = SASTScanner(self.tmp).scan_directory()
        self.assertTrue(any(v["name"] == "Hardcoded Secret/Token"
                            for v in report["vulnerabilities"]))

    def test_detects_github_pat(self):
        _write(os.path.join(self.tmp, "leak.py"),
               'token = "ghp_' + "A" * 36 + '"\n')
        report = SASTScanner(self.tmp).scan_directory()
        self.assertTrue(any(v["name"] == "Hardcoded Secret/Token"
                            for v in report["vulnerabilities"]))

    def test_ignores_placeholder_password(self):
        """Tightened regex must NOT fire on obvious placeholders."""
        _write(os.path.join(self.tmp, "config.py"),
               'password = "your_password_here"\n'
               'api_key = "PLACEHOLDER"\n'
               'secret = "<change-me>"\n')
        report = SASTScanner(self.tmp).scan_directory()
        secret_findings = [v for v in report["vulnerabilities"]
                           if v["name"] == "Hardcoded Secret/Token"]
        self.assertEqual(secret_findings, [],
                         "Placeholder values should not be flagged as secrets")

    # ---------- SQLi detection ----------
    def test_detects_fstring_sqli(self):
        _write(os.path.join(self.tmp, "db.py"),
               'cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n')
        report = SASTScanner(self.tmp).scan_directory()
        self.assertTrue(any(v["name"].startswith("Static SQL Injection")
                            for v in report["vulnerabilities"]))

    def test_detects_concat_sqli(self):
        _write(os.path.join(self.tmp, "db.py"),
               'cursor.execute("SELECT * FROM users WHERE id=" + uid)\n')
        report = SASTScanner(self.tmp).scan_directory()
        self.assertTrue(any(v["name"].startswith("Static SQL Injection")
                            for v in report["vulnerabilities"]))

    def test_ignores_parameterised_query(self):
        """Properly parameterised queries must NOT be flagged."""
        _write(os.path.join(self.tmp, "db.py"),
               'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n')
        report = SASTScanner(self.tmp).scan_directory()
        sqli = [v for v in report["vulnerabilities"]
                if v["name"].startswith("Static SQL Injection")]
        self.assertEqual(sqli, [],
                         "Parameterised query should not be flagged as SQLi")

    # ---------- Command Injection ----------
    def test_detects_shell_true(self):
        _write(os.path.join(self.tmp, "exec.py"),
               'subprocess.run(cmd, shell=True)\n')
        report = SASTScanner(self.tmp).scan_directory()
        self.assertTrue(any(v["name"] == "Static Command Injection"
                            for v in report["vulnerabilities"]))

    # ---------- CORS ----------
    def test_detects_wildcard_cors(self):
        _write(os.path.join(self.tmp, "settings.py"),
               "CORS_ORIGIN_ALLOW_ALL = True\n")
        report = SASTScanner(self.tmp, scan_options={
            "sast_secrets": False, "sast_sqli": False,
            "sast_shadow_api": False, "sast_cors": True,
            "sast_cmdinj": False, "sast_ratelimit": False,
        }).scan_directory()
        self.assertTrue(any(v["name"] == "Static Insecure CORS"
                            for v in report["vulnerabilities"]))

    # ---------- Rate limiter detection ----------
    def test_missing_rate_limiter(self):
        _write(os.path.join(self.tmp, "app.py"),
               "@app.route('/api/v1/login')\ndef login(): pass\n")
        report = SASTScanner(self.tmp, scan_options={
            "sast_secrets": False, "sast_sqli": False,
            "sast_shadow_api": True, "sast_cors": False,
            "sast_cmdinj": False, "sast_ratelimit": True,
        }).scan_directory()
        self.assertTrue(any(v["name"] == "Missing Rate Limiter (Static)"
                            for v in report["vulnerabilities"]))

    def test_rate_limiter_present(self):
        _write(os.path.join(self.tmp, "app.py"),
               "from flask_limiter import Limiter\n"
               "@app.route('/api/v1/login')\ndef login(): pass\n")
        report = SASTScanner(self.tmp, scan_options={
            "sast_secrets": False, "sast_sqli": False,
            "sast_shadow_api": True, "sast_cors": False,
            "sast_cmdinj": False, "sast_ratelimit": True,
        }).scan_directory()
        self.assertFalse(any(v["name"] == "Missing Rate Limiter (Static)"
                             for v in report["vulnerabilities"]))


if __name__ == "__main__":
    unittest.main()
