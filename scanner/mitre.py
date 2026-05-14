"""
MITRE ATT&CK Mapping
====================

Maps API Sentinel findings to MITRE ATT&CK Enterprise techniques (v15+).

Why this exists
---------------
Security teams already speak ATT&CK. Mapping API vulnerabilities to ATT&CK
techniques means:

  * Findings can be plotted on the same heat-map as the rest of the org's
    threat-intel feed.
  * Detection engineers can match scanner output against existing SIEM rules.
  * Leadership reports can show TTP coverage instead of raw CVE counts.

Mapping philosophy
------------------
Two layers of mapping:

  1. *Finding-name* override — most precise. Use whenever we can say
     "Reflected XSS" implies "T1059.007" (JavaScript) directly.
  2. *OWASP API Top 10 fallback* — coarser, but covers any new check that
     doesn't have its own override yet.

If neither layer matches, the finding gets technique `T1190`
("Exploit Public-Facing Application") which is the universal default for
anything that compromises a web/API endpoint.

Each mapping returns a structured dict with `id`, `name`, `tactic`, and a
direct URL into the public ATT&CK Navigator.
"""
from __future__ import annotations

from typing import Optional


# ---------------------------------------------------------------------------
# Technique catalogue (subset relevant to API security)
# ---------------------------------------------------------------------------
# Each entry: id -> (name, tactic)
TECHNIQUES = {
    # ---- Initial Access ----
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    # ---- Execution ----
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "Execution"),
    "T1059.006": ("Command and Scripting Interpreter: Python", "Execution"),
    # ---- Credential Access ----
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1212": ("Exploitation for Credential Access", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1556": ("Modify Authentication Process", "Credential Access"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    # ---- Defense Evasion ----
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Defense Evasion"),
    "T1550": ("Use Alternate Authentication Material", "Defense Evasion"),
    "T1550.001": ("Use Alternate Authentication Material: Application Access Token", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    # ---- Discovery ----
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1596": ("Search Open Technical Databases", "Reconnaissance"),
    # ---- Collection ----
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1530": ("Data from Cloud Storage", "Collection"),
    # ---- Privilege Escalation ----
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    # ---- Impact ----
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1499.003": ("Endpoint Denial of Service: Application Exhaustion Flood", "Impact"),
    "T1565": ("Data Manipulation", "Impact"),
    # ---- Lateral Movement ----
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
}


# ---------------------------------------------------------------------------
# Per-finding-name overrides (highest precision)
# ---------------------------------------------------------------------------
# Use lowercase substring matches on the vulnerability 'name' field.
FINDING_NAME_MAP = {
    # Injection family
    "sql injection": "T1190",
    "nosql injection": "T1190",
    "time-based blind": "T1190",
    "os command injection": "T1059",
    "command injection": "T1059",
    "reflected xss": "T1059.007",
    "xml external entity": "T1212",
    "xxe": "T1212",
    # Authentication
    "broken authentication": "T1078",
    "insecure jwt": "T1556",
    "jwt algorithm confusion": "T1556",
    "auth bypass": "T1078",
    "credential stuffing": "T1110.004",
    "brute force": "T1110",
    # Object level
    "bola": "T1078.004",
    "idor": "T1078.004",
    "cross-user bola": "T1078.004",
    "bfla": "T1068",
    "broken function level authorization": "T1068",
    # Mass assignment / privilege
    "mass assignment": "T1068",
    "privilege escalation": "T1068",
    # Discovery / inventory
    "undocumented": "T1595",
    "shadow api": "T1595",
    "hidden api": "T1595",
    "hidden parameter": "T1595",
    "exposed login portal": "T1592",
    "exposed sensitive path": "T1592",
    "graphql introspection": "T1596",
    "graphql": "T1596",
    "wayback": "T1596",
    # Rate / DoS
    "missing rate limiting": "T1499.003",
    "missing rate limiter": "T1499.003",
    # SSRF / data exposure
    "server-side request forgery": "T1530",
    "ssrf": "T1530",
    "excessive data": "T1213",
    "pii exposure": "T1213",
    "sensitive data": "T1213",
    # Secrets / static analysis
    "hardcoded secret": "T1552.001",
    "exposed infrastructure": "T1133",
    "exposed ports": "T1133",
    # Misc
    "unsafe http method": "T1027",
    "insecure cors": "T1190",
    "out-of-band": "T1190",
    "blind vulnerability": "T1190",
}


# ---------------------------------------------------------------------------
# OWASP API Top 10 (2023) → ATT&CK fallback
# ---------------------------------------------------------------------------
OWASP_TO_ATTACK = {
    "API1:2023": "T1078.004",  # Broken Object Level Authorization
    "API2:2023": "T1078",      # Broken Authentication
    "API3:2023": "T1068",      # Broken Object Property Level Auth
    "API4:2023": "T1499.003",  # Unrestricted Resource Consumption
    "API5:2023": "T1068",      # Broken Function Level Authorization
    "API6:2023": "T1499",      # Unrestricted Access to Sensitive Business Flows
    "API7:2023": "T1530",      # Server-Side Request Forgery
    "API8:2023": "T1190",      # Security Misconfiguration
    "API9:2023": "T1595",      # Improper Inventory Management
    "API10:2023": "T1190",     # Unsafe Consumption of APIs
}


def _technique_meta(tid: str) -> dict:
    """Return a structured technique meta-dict for a given ATT&CK ID."""
    name, tactic = TECHNIQUES.get(tid, ("Unknown", "Unknown"))
    return {
        "id": tid,
        "name": name,
        "tactic": tactic,
        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }


def map_finding(finding: dict) -> Optional[dict]:
    """
    Return the ATT&CK technique meta-dict for a given finding, or None if the
    finding doesn't match anything (which should never happen because the
    OWASP fallback catches all API findings).

    A finding gets one technique. That's deliberate: we want clean heatmap
    visuals, not noisy multi-tag entries. If a finding genuinely needs two
    techniques the calling code can extend `finding["mitre_attack_extra"]`.
    """
    name = (finding.get("name") or "").lower()
    # 1. Finding-name overrides (substring match, longest match wins)
    best_key = ""
    for key in FINDING_NAME_MAP:
        if key in name and len(key) > len(best_key):
            best_key = key
    if best_key:
        return _technique_meta(FINDING_NAME_MAP[best_key])

    # 2. OWASP API fallback
    owasp = (finding.get("owasp") or "").strip()
    for prefix, tid in OWASP_TO_ATTACK.items():
        if owasp.startswith(prefix):
            return _technique_meta(tid)

    # 3. Universal default — never returns None, so the UI can always show a chip
    return _technique_meta("T1190")


def annotate_findings(findings: list) -> list:
    """In-place: attach a `mitre_attack` field to every finding. Returns the list."""
    for f in findings or []:
        if isinstance(f, dict) and "mitre_attack" not in f:
            f["mitre_attack"] = map_finding(f)
    return findings


def build_heatmap(findings: list) -> dict:
    """
    Aggregate findings by ATT&CK technique. Returns:

        {
          "by_technique": [{"id":"T1190", "name":..., "tactic":..., "count":3, "severity":"High"}, ...],
          "by_tactic":    {"Initial Access": 5, "Credential Access": 2, ...},
          "total":        7,
        }

    Severity for each technique is the highest severity of any finding mapped
    to it — that's what shows up as the cell colour on the heatmap.
    """
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    by_id: dict = {}
    by_tactic: dict = {}
    for f in findings or []:
        meta = f.get("mitre_attack") or map_finding(f)
        tid = meta["id"]
        ent = by_id.setdefault(tid, {**meta, "count": 0, "severity": "Info"})
        ent["count"] += 1
        if sev_rank.get(f.get("severity", "Info"), 0) > sev_rank.get(ent["severity"], 0):
            ent["severity"] = f.get("severity", "Info")
        by_tactic[meta["tactic"]] = by_tactic.get(meta["tactic"], 0) + 1
    # Sort techniques by severity, then count
    techniques = sorted(by_id.values(), key=lambda e: (sev_rank.get(e["severity"], 0), e["count"]), reverse=True)
    return {
        "by_technique": techniques,
        "by_tactic": by_tactic,
        "total": len(findings or []),
    }
