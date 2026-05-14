"""
Zero-False-Positive Toolkit
===========================

Shared helpers used by every detection check in scan_engine.py to achieve a
high-confidence, low-noise scan report. The philosophy is:

1.  Match *specific* signatures (DB errors, regex anchors), never broad keywords.
2.  Require *differential* confirmation against a recorded baseline.
3.  Use *statistical* tests (median + std-dev) for timing, not single samples.
4.  *Validate* findings with structural checks (Luhn, fake-data filters).
5.  Re-verify every positive in a second pass before reporting it.

Each detection returns a *vulnerability dict* with a `confidence` field
(0-100). The verification round at the end of start_scan() drops anything
below CONFIDENCE_THRESHOLD_DEFAULT (configurable via scan_options).
"""
from __future__ import annotations

import re
import json
import math
import uuid
import statistics
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Confidence scale (0 - 100)
# ---------------------------------------------------------------------------
class Confidence:
    """Confidence levels used across all checks. Use these instead of magic numbers."""
    DEFINITIVE = 100        # OAST callback, JWT alg=none, exact AWS key
    HIGH = 90               # Multiple independent signals confirm
    MODERATE = 75           # Single strong signal + passed verification round
    LOW = 50                # Heuristic match, single signal
    SUSPICIOUS = 30         # Pattern fired but couldn't be independently confirmed


# Default cut-off applied during the verification round. Anything below this
# is dropped from the final report.
CONFIDENCE_THRESHOLD_DEFAULT = 70


# ---------------------------------------------------------------------------
# Database / Backend error signatures
# ---------------------------------------------------------------------------
# These are *specific* error strings emitted by real database engines. Matching
# any of these proves a SQL/NoSQL parser saw our payload, which is much stronger
# evidence than seeing the word "sql" in the response body.
DB_ERROR_SIGNATURES = {
    "mysql": [
        r"you have an error in your sql syntax",
        r"warning.*?mysqli?_",
        r"mysql_fetch_(?:array|assoc|row)\s*\(",
        r"mysqlclient\.errors",
        r"\(1064,\s*\"you have an error",
    ],
    "postgresql": [
        r"unterminated quoted string at or near",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"psycopg2\.errors",
        r"postgresql query failed",
        r"syntax error at or near",
    ],
    "mssql": [
        r"microsoft sql native client error",
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
        r"\[microsoft\]\[odbc sql server driver\]",
    ],
    "oracle": [
        r"ora-\d{5}",
        r"oracle.*?error",
        r"\bquoted string not properly terminated\b",
    ],
    "sqlite": [
        r"sqlite3?\.operationalerror",
        r"sqlite_error",
        r"unrecognized token:",
    ],
    "mongodb": [
        r"mongoerror",
        r"bsonerror",
        r"e11000 duplicate key",
        r"\$where.*?must be",
    ],
}


def detect_db_error(text: str) -> Optional[str]:
    """
    Returns the DB family name (e.g. "mysql") if a *specific* DB error
    signature is detected in the response body. Returns None otherwise.

    NEVER matches on generic keywords like the bare word "sql" or "mysql" —
    only matches actual error messages emitted by the driver itself.
    """
    if not text:
        return None
    text_l = text.lower()
    for db, sigs in DB_ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, text_l):
                return db
    return None


# ---------------------------------------------------------------------------
# Credit card validation (Luhn) and PII filters
# ---------------------------------------------------------------------------
def luhn_check(card_number: str) -> bool:
    """
    Validates a credit-card number using the Luhn checksum algorithm.
    Returns True only if the number is structurally a valid card number.
    Random 16-digit numbers fail this test ~90% of the time, killing most
    timestamp / opaque-ID false positives.
    """
    s = re.sub(r"[\s\-]", "", card_number)
    if not s.isdigit() or not (13 <= len(s) <= 19):
        return False
    total = 0
    parity = len(s) % 2
    for i, ch in enumerate(s):
        n = int(ch)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Email / SSN placeholder lists. Findings against these are dropped.
FAKE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "localhost",
    "foo.com", "bar.com", "sample.com", "domain.com", "yourdomain.com",
    "email.com", "mail.com",
}

# Common documentation / dummy local-parts
FAKE_EMAIL_LOCALPARTS = {
    "test", "user", "admin", "example", "foo", "bar", "baz",
    "noreply", "no-reply", "donotreply", "support@", "info",
    "you", "your", "name",
}

# SSNs that are reserved / invalid / used in examples
FAKE_SSN_VALUES = {
    "000-00-0000", "123-45-6789", "111-11-1111", "222-22-2222",
    "333-33-3333", "444-44-4444", "555-55-5555", "666-66-6666",
    "777-77-7777", "888-88-8888", "999-99-9999", "012-34-5678",
    "078-05-1120",  # The famous "Woolworth" wallet SSN — used in every demo
}


def is_real_email(email: str) -> bool:
    """Returns True only if the email looks like genuine PII (not a placeholder)."""
    if not email or "@" not in email:
        return False
    local, _, domain = email.partition("@")
    local = local.lower().strip()
    domain = domain.lower().strip()
    if domain in FAKE_EMAIL_DOMAINS:
        return False
    if local in FAKE_EMAIL_LOCALPARTS:
        return False
    # Reject obvious template tokens like {{user.email}} or %s
    if any(c in email for c in "{}<>%"):
        return False
    return True


def is_real_ssn(ssn: str) -> bool:
    """
    Filters out placeholder SSNs and structurally-impossible numbers.
    The SSA rules: area cannot be 000, 666, or 9xx; group cannot be 00;
    serial cannot be 0000.
    """
    if ssn in FAKE_SSN_VALUES:
        return False
    parts = ssn.split("-")
    if len(parts) != 3:
        return False
    area, group, serial = parts
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


# ---------------------------------------------------------------------------
# Timing analysis (replaces the +2.5s heuristic)
# ---------------------------------------------------------------------------
def statistical_timing_test(
    baseline_samples: Iterable[float],
    attack_elapsed: float,
    sigma_factor: float = 3.0,
    min_absolute_delay: float = 2.5,
) -> bool:
    """
    Statistical test for blind / time-based injection.

    Returns True only if the attack timing is BOTH:
      - more than `sigma_factor` standard deviations above the baseline median, AND
      - at least `min_absolute_delay` seconds above the baseline median.

    Requires at least 4 baseline samples so that stdev is meaningful. Without
    that many samples, returns False (no detection) to stay conservative.
    """
    samples = [s for s in baseline_samples if s is not None and s > 0]
    if len(samples) < 4:
        return False
    try:
        median = statistics.median(samples)
        stdev = statistics.stdev(samples) if len(samples) > 1 else 0.0
    except statistics.StatisticsError:
        return False

    sigma_threshold = median + (sigma_factor * stdev)
    absolute_threshold = median + min_absolute_delay
    return attack_elapsed > sigma_threshold and attack_elapsed > absolute_threshold


def collect_timing_samples(request_fn, n: int = 5) -> list[float]:
    """
    Run request_fn() n times and return the list of elapsed durations.
    Failed samples (exceptions, timeouts) are silently dropped — that's fine,
    statistical_timing_test() requires >=4 valid samples and returns False
    otherwise.
    """
    import time
    samples: list[float] = []
    for _ in range(n):
        try:
            t0 = time.time()
            request_fn()
            samples.append(time.time() - t0)
        except Exception:
            continue
    return samples


# ---------------------------------------------------------------------------
# Anchor tokens for echo / reflection detection
# ---------------------------------------------------------------------------
def make_anchor(prefix: str = "sentinel") -> str:
    """
    Build a globally unique anchor token. We use these to confirm that an
    XSS / SQLi payload was *actually reflected by the application* — rather
    than seeing a random "<script>" in the response that happened to be
    part of the normal page layout.
    """
    return f"{prefix}{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Response classifiers
# ---------------------------------------------------------------------------
_LOGIN_PAGE_INDICATORS = (
    'type="password"', "type='password'", "csrf_token", "csrftoken",
    "csrfmiddlewaretoken", "<form", "sign in", "sign-in", "log in",
    "login required", "authentication required", "please log in",
)

_TRIVIAL_JSON_META_KEYS = {
    "status", "ok", "message", "error", "errors", "timestamp",
    "success", "code", "detail", "title",
}


def looks_like_login_page(text: str) -> bool:
    """Heuristic to spot generic SPA login landing pages (HTTP 200 but no data)."""
    if not text:
        return False
    tl = text.lower()
    score = sum(1 for ind in _LOGIN_PAGE_INDICATORS if ind in tl)
    return score >= 2


def looks_like_meaningful_data(text: str, content_type: str = "") -> bool:
    """
    Returns True if the response body looks like *real* API data:
    a non-trivial JSON object/array with substantive fields, OR a non-trivial
    plain payload. Returns False for empty bodies, boilerplate JSON
    ({"status": "ok"}), and HTML/SPA shells.
    """
    if not text or len(text.strip()) < 20:
        return False
    ct = (content_type or "").lower()
    if "application/json" in ct or text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
        except Exception:
            return False
        if isinstance(data, list):
            return len(data) > 0
        if isinstance(data, dict):
            if not data:
                return False
            # Reject responses that are pure metadata (no business fields)
            key_set = set(data.keys())
            if key_set.issubset(_TRIVIAL_JSON_META_KEYS):
                return False
            return True
        return False
    # Non-JSON: assume it's an SPA shell or HTML — not API data
    return False


# ---------------------------------------------------------------------------
# Vulnerability builder helpers
# ---------------------------------------------------------------------------
def build_finding(
    name: str,
    severity: str,
    description: str,
    cvss: float,
    owasp: str,
    confidence: int,
    evidence: Optional[dict] = None,
    path: Optional[str] = None,
) -> dict:
    """
    Standardised vulnerability-dict factory. Every check should go through
    this so every finding has the same shape — name, severity, description,
    cvss, owasp, confidence, evidence, path.

    `evidence` is a dict of free-form fields explaining WHY the finding was
    raised (payload used, response excerpt, timing samples, etc). It's
    extremely useful for the verification round and for the FYP examiner.
    """
    finding = {
        "name": name,
        "severity": severity,
        "description": description,
        "cvss": cvss,
        "owasp": owasp,
        "confidence": int(max(0, min(100, confidence))),
    }
    if evidence:
        finding["evidence"] = evidence
    if path:
        finding["path"] = path
    return finding


def boost_confidence(finding: dict, delta: int = 15) -> dict:
    """Raise a finding's confidence (used after a verification round passes)."""
    if not finding:
        return finding
    cur = int(finding.get("confidence", Confidence.LOW))
    finding["confidence"] = max(0, min(100, cur + delta))
    return finding


def filter_by_confidence(findings: list[dict], threshold: int) -> list[dict]:
    """Drop every finding below the given confidence threshold."""
    return [f for f in findings if int(f.get("confidence", 0)) >= threshold]
