import requests
import yaml
import re
import time
import base64
import json
import socket
import uuid
import random
from urllib.parse import urlparse, urljoin

def generate_mock_param(path_str):
    """
    Intelligently generates realistic data for path variables.
    Instead of passing '1' to everything, it generates UUIDs for {uuid},
    random integers for {id}, and 'test' for strings.
    """
    def repl(match):
        param_name = match.group(0).strip('{}').lower()
        if 'uuid' in param_name:
            return str(uuid.uuid4())
        elif 'id' in param_name or 'num' in param_name:
            return str(random.randint(1000, 9999))
        return "test_mock_value"
    
    return re.sub(r'\{.*?\}', repl, path_str)

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
        try:
            self.api_spec = yaml.safe_load(self.spec_content)
            if isinstance(self.api_spec, dict):
                self.report["status"] = "Success"
                return True
        except Exception as e:
            print(f"[-] Error parsing spec: {e}")
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
            headers = requests.get(self.target_base_url, timeout=5).headers
            missing = [h for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"] if h not in headers]
            if missing:
                self.report["vulnerabilities"].append({"name": "Missing Security Headers", "severity": "Low", "description": f"Missing headers: {', '.join(missing)}", "cvss": 3.1, "owasp": "API8:2023 Security Misconfiguration"})
        except: pass

    def parse_endpoints(self):
        if not self.api_spec: return
        paths = self.api_spec.get('paths', {})
        for path, methods in paths.items():
            for method in methods:
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    self.report["endpoints"].append(f"{method.upper()} {path}")

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
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching swagger: {e}")
        return None

def _build_url(base_url, path_str):
    clean_base = base_url.rstrip('/')
    clean_path = path_str if path_str.startswith('/') else f"/{path_str}"
    return f"{clean_base}{clean_path}"

def check_broken_authentication(method, path, base_url, logger=None):
    if 'login' in path or 'register' in path or '.well-known' in path or 'auth' in path: return None
    try:
        url = _build_url(base_url, re.sub(r'\{.*?\}', '1', path))
        res = requests.request(method, url, timeout=5)
        # 401 Unauthorized, 403 Forbidden, 404/405 usually indicate it's not implemented or wrong method, not a bypass
        if res.status_code in [200, 201, 202, 204]: 
            return {"name": "Broken Authentication", "severity": "High", "description": f"Endpoint {method.upper()} {path} permitted unauthenticated access (Status: {res.status_code}). [Violates PCI-DSS Req. 8]", "cvss": 8.8, "owasp": "API2:2023 Broken Authentication"}
    except: pass
    return None

def check_bola_vulnerability(method, path, base_url, auth_headers):
    if '{' not in path: return None
    try:
        url1 = _build_url(base_url, generate_mock_param(path))
        url2 = _build_url(base_url, generate_mock_param(path))
        res1 = requests.request(method, url1, headers=auth_headers, timeout=5)
        res2 = requests.request(method, url2, headers=auth_headers, timeout=5)
        
        if res1.status_code == 200 and res2.status_code == 200 and res1.content != res2.content:
            return {"name": "BOLA / IDOR", "severity": "High", "description": f"Endpoint {path} allows accessing multiple separate object IDs successfully under the same token. [Violates GDPR Art. 32]", "cvss": 8.5, "owasp": "API1:2023 Broken Object Level Authorization"}
    except: pass
    return None

def check_injection(method, path, base_url, auth_headers):
    if '.well-known' in path: return None
    payloads = {
        "SQLi": ["' OR 1=1--", "admin'--", "1' OR '1'='1", "1; WAITFOR DELAY '0:0:5'--"],
        "XSS": ["<script>alert(1)</script>", "\"><img src=x onerror=prompt(1)>"],
        "CmdInj": ["; id", "| whoami", "`ping -c 1 127.0.0.1`"]
    }
    db_errors = ["sql ", "mysql", "syntax", "ora-", "postgresql", "unexpected token", "pg_query"]
    
    for inj_type, p_list in payloads.items():
        for p in p_list:
            try:
                if method in ['post', 'put', 'patch']:
                    url = _build_url(base_url, path)
                    json_payload = {"email": p, "password": p, "username": p, "id": p, "search": p, "q": p, "query": p}
                    res = requests.request(method, url, json=json_payload, headers=auth_headers, timeout=5)
                else:
                    url = _build_url(base_url, f"{generate_mock_param(path)}?q={p}&id={p}&search={p}")
                    res = requests.request(method, url, headers=auth_headers, timeout=5)
                    
                text_lower = res.text.lower()
                
                if inj_type == "SQLi":
                    if res.status_code == 500 and any(err in text_lower for err in db_errors):
                        return {"name": "SQL Injection (Error-Based)", "severity": "Critical", "description": f"Endpoint {path} triggered DB errors with payload '{p}'. [Violates PCI-DSS Req. 6.5.1]", "cvss": 9.8, "owasp": "API8:2023 Security Misconfiguration"}
                    if res.status_code == 200 and 'token' in text_lower and 'error' not in text_lower:
                        return {"name": "SQL Injection (Auth Bypass)", "severity": "Critical", "description": f"Endpoint {path} bypassed auth / logic with payload '{p}'.", "cvss": 9.8, "owasp": "API8:2023 Security Misconfiguration"}
                        
                elif inj_type == "XSS":
                    if res.status_code == 200 and p in res.text:
                        return {"name": "Reflected Cross-Site Scripting (XSS)", "severity": "Medium", "description": f"Endpoint {path} reflected unsafe script payload.", "cvss": 6.1, "owasp": "API8:2023 Security Misconfiguration"}
                        
                elif inj_type == "CmdInj":
                    if "uid=" in text_lower or "root:" in text_lower or ("127.0.0.1" in text_lower and "ping" not in p):
                        return {"name": "OS Command Injection", "severity": "Critical", "description": f"Endpoint {path} executed system command '{p}'.", "cvss": 10.0, "owasp": "API8:2023 Security Misconfiguration"}
            except: pass
    return None

def check_rate_limit(method, path, base_url, auth_headers):
    try:
        url = _build_url(base_url, re.sub(r'\{.*?\}', '1', path))
        
        # Pre-flight check: only blast endpoints that actually exist
        preflight_res = requests.request(method, url, headers=auth_headers, timeout=3)
        if preflight_res.status_code in [404, 405]: 
            return None
            
        requests_sent = 1
        for _ in range(49):
            res = requests.request(method, url, headers=auth_headers, timeout=2)
            requests_sent += 1
            if res.status_code == 429: return None # Properly rate limited
            
            # If server crashes or blocks us entirely via firewall rules
            if res.status_code in [500, 502, 503, 403]: return None 
            
        return {"name": "Missing Rate Limiting", "severity": "Medium", "description": f"Endpoint allowed {requests_sent} rapid burst requests (Status {preflight_res.status_code}) without throwing a 429 Too Many Requests. [Violates SOC 2 CC6]", "cvss": 5.3, "owasp": "API4:2023 Unrestricted Resource Consumption"}
    except: pass
    return None

def check_sensitive_data(method, path, base_url, auth_headers):
    if method != 'get': return None
    patterns = {
        "Email Exposure": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', 
        "SSN Exposure": r'\b\d{3}-\d{2}-\d{4}\b',
        "Credit Card (Visa/MC)": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b',
        "IP Address Leak": r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    }
    try:
        url = _build_url(base_url, re.sub(r'\{.*?\}', '1', path))
        res = requests.get(url, headers=auth_headers, timeout=5)
        found = [k for k, v in patterns.items() if re.search(v, res.text)]
        if "IP Address Leak" in found and ("127.0.0.1" in res.text or "172." in res.text):
            found.remove("IP Address Leak")
            
        if found: return {"name": "Excessive Data / PI Exposure", "severity": "High", "description": f"Endpoint leaked patterned data: {', '.join(found)}. [Violates GDPR Art. 5]", "cvss": 7.5, "owasp": "API3:2023 Broken Object Property Level Auth"}
    except: pass
    return None

def check_mass_assignment(method, path, base_url, auth_headers):
    if method not in ['post', 'put', 'patch']: return None
    payloads = [
        {"isAdmin": True, "role": "admin", "permissions": "all"},
        {"is_admin": 1, "account_type": "premium"},
        {"user": {"role": "admin", "privilege": 999}}
    ]
    try:
        url = _build_url(base_url, generate_mock_param(path))
        for payload in payloads:
            res = requests.request(method, url, json=payload, headers=auth_headers, timeout=5)
            if res.status_code in [200, 201, 202] and ("admin" in res.text.lower() or "premium" in res.text.lower()):
                return {"name": "Potential Mass Assignment", "severity": "Medium", "description": f"Endpoint {method.upper()} {path} accepted a privileged payload and reflected successful state change.", "cvss": 6.5, "owasp": "API3:2023 Broken Object Property Level Auth"}
    except: pass
    return None

def check_unsafe_methods(path, base_url):
    try:
        url = _build_url(base_url, path)
        for method in ["TRACE", "TRACK", "DEBUG"]:
            res = requests.request(method, url, timeout=5)
            if res.status_code == 200 and ("Via" in res.headers or "TRACE" in res.text or method in res.text):
                return {"name": f"Unsafe HTTP Method ({method})", "severity": "Low", "description": f"Server actively enabled {method} method on {path}.", "cvss": 3.7, "owasp": "API8:2023 Security Misconfiguration"}
    except: pass
    return None

def check_jwt_weakness(auth_header):
    if not auth_header or "Bearer " not in auth_header: return None
    try:
        token = auth_header.split(" ")[1]
        if "." not in token: return None
        header_segment = token.split(".")[0]
        padded = header_segment + '=' * (-len(header_segment) % 4)
        header_data = json.loads(base64.urlsafe_b64decode(padded))
        
        if header_data.get('alg', '').lower() == 'none':
            return {"name": "Insecure JWT (None Alg)", "severity": "Critical", "description": "JWT allows 'None' algorithm.", "cvss": 9.8, "owasp": "API2:2023 Broken Authentication"}
        if header_data.get('alg', '').upper() == 'HS256':
            return {"name": "Weak JWT Key (HS256)", "severity": "Low", "description": "JWT uses symmetric HS256 key.", "cvss": 4.8, "owasp": "API2:2023 Broken Authentication"}
    except: pass
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
    for p in paths:
        try:
            url = f"{clean_base}{p}"
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                html_lower = res.text.lower()
                is_login = False
                if "<form" in html_lower and "type=\"password\"" in html_lower:
                    is_login = True
                elif "keycloak administration" in html_lower or "title>login" in html_lower or "sign-in" in html_lower:
                    is_login = True
                
                if is_login:
                    return {"name": "Exposed Login Portal", "severity": "Low", "description": f"Login page or Auth SPA accessible at {p}.", "cvss": 3.0, "owasp": "API9:2023 Improper Inventory Management"}
                return {"name": "Exposed Sensitive Path", "severity": "Medium", "description": f"Path {p} is accessible.", "cvss": 5.8, "owasp": "API9:2023 Improper Inventory Management"}
        except: pass
    return None

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
    except: pass
    return None

def check_cors_policy(base_url):
    try:
        clean_base = base_url.rstrip('/')
        headers = {'Origin': 'https://evil-attacker.com'}
        # Active CORS checking
        res = requests.options(clean_base, headers=headers, timeout=5)
        acao = res.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or acao == 'https://evil-attacker.com':
            return {"name": "Insecure CORS Policy (Dynamic)", "severity": "Medium", "description": f"The server explicitly allowed cross-origin requests from an untrusted origin: Access-Control-Allow-Origin: {acao}", "cvss": 6.5, "owasp": "API8:2023 Security Misconfiguration"}
    except: pass
    return None

def find_hidden_api_endpoints(base_url, logger=None):
    found_vulns = []
    found_endpoints = []
    clean_base = base_url.rstrip('/')
    
    def log(msg):
        if logger: logger(msg)

    # 1. Robots.txt / Sitemap Recon
    try:
        robots_res = requests.get(f"{clean_base}/robots.txt", timeout=3)
        if robots_res.status_code == 200:
            disallowed = re.findall(r'Disallow:\s*(/.*)', robots_res.text)
            for d in disallowed:
                if 'api' in d.lower():
                    found_vulns.append({"name": "Hidden API Discovered (Recon)", "severity": "Medium", "description": f"Robots.txt leaks hidden API path: {d}. [Violates NIST SP 800-53 CM-8]", "cvss": 5.0, "owasp": "API9:2023 Improper Inventory Management"})
                    found_endpoints.append(f"GET {d}")
    except: pass

    # 2. Extract from Javascript files (Crawling frontend SPA)
    try:
        root_res = requests.get(clean_base, timeout=5)
        scripts = re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', root_res.text)
        for script in scripts[:5]:  # Analyze top 5 JS bundles
            s_url = script if script.startswith('http') else f"{clean_base}/{script.lstrip('/')}"
            try:
                s_res = requests.get(s_url, timeout=3)
                if s_res.status_code == 200:
                    api_paths = set(re.findall(r'["\'](/api/(?:v[1-3]/)?[a-zA-Z0-9_\-/]+)["\']', s_res.text))
                    for ap in api_paths:
                        found_endpoints.append(f"GET {ap}")
                        found_endpoints.append(f"POST {ap}")
            except: pass
    except: pass

    # 3. Enhanced API Fuzzing Dictionary
    fuzz_paths = [
        '/api', '/api/v1', '/api/v2', '/v1', '/graphql',
        '/api/users', '/api/v1/users', '/api/private/users', '/api/dev/users',
        '/users/me', '/auth/login', '/api/admin', '/api/products', '/api/health',
        '/.well-known/openid-configuration',
        '/realms/master/.well-known/openid-configuration',
        '/realms/ingtech/.well-known/openid-configuration'
    ]
    
    to_fuzz = list(set([p.split(" ")[1] if " " in p else p for p in found_endpoints] + fuzz_paths))
    
    for p in to_fuzz:
        try:
            res = requests.get(f"{clean_base}{p}", timeout=2)
            if res.status_code in [200, 401, 403, 405] and 'application/json' in res.headers.get('Content-Type', ''):
                if p in fuzz_paths: # It was found purely by fuzzing
                    found_vulns.append({"name": "Undocumented API Found", "severity": "Low", "description": f"Discovered reachable endpoint {p}.", "cvss": 3.0, "owasp": "API9:2023 Improper Inventory Management"})
                found_endpoints.append(f"GET {p}")
                found_endpoints.append(f"POST {p}")
        except: pass
        
    if found_endpoints:
        log(f"     [+] Recon Engine discovered {len(set(found_endpoints))} potential endpoints dynamically.")
        
    return found_vulns, list(set(found_endpoints))

# ==============================================================================
# MASTER SCAN FUNCTION (UPDATED)
# ==============================================================================
def start_scan(spec_content, base_url, auth_headers, scan_options=None, logger=None, report_id=None):
    def log(msg):
        print(msg)
        if logger: logger(msg)

    if scan_options is None:
        scan_options = {'bola': True, 'auth': True, 'injection': True, 'ratelimit': True, 'jwt': True, 'debug': True}

    log(f"[*] Initializing scan for: {base_url}")
    
    passive_scanner = APIScanner(spec_content=spec_content, target_base_url=base_url)
    report = passive_scanner.run_passive_scan()
    
    if report['status'] == 'Failed':
        # Don't return! Just log and continue with empty endpoints
        log("[!] Warning: Could not parse OpenAPI spec. Proceeding with Host-Level checks.")
        endpoints = []
    else:
        endpoints = report.get("endpoints", [])
        log(f"[+] Successfully parsed {len(endpoints)} endpoints.")
    
    log("\n[*] Starting Active Scan Phase...")

    # --- Run Global Checks ---
    if scan_options.get('debug'):
        if report_id:
            from .models import ScanReport 
            if ScanReport.objects.get(id=report_id).status == "Stopped":
                log("[!] Scan stopped by user command.")
                report['status'] = "Stopped"
                return report

        vuln = check_debug_endpoints(base_url)
        if vuln and vuln not in report["vulnerabilities"]:
            report["vulnerabilities"].append(vuln)
            log(f"     [!] Found: Exposed Hidden Path")
            
        vuln = check_cors_policy(base_url)
        if vuln and vuln not in report["vulnerabilities"]:
            report["vulnerabilities"].append(vuln)
            log(f"     [!] Found: Insecure CORS Policy")
            
        vuln = check_open_ports(base_url)
        if vuln and vuln not in report["vulnerabilities"]:
            report["vulnerabilities"].append(vuln)
            log(f"     [!] Found: Exposed Infrastructure Ports")
            
        vulns, new_endpoints = find_hidden_api_endpoints(base_url, logger)
        for v in vulns:
            if v not in report["vulnerabilities"]:
                report["vulnerabilities"].append(v)
                log(f"     [!] Recon Found: {v['name']}")
        endpoints.extend(new_endpoints)

    if scan_options.get('jwt') and auth_headers.get('Authorization'):
        vuln = check_jwt_weakness(auth_headers.get('Authorization'))
        if vuln and vuln not in report["vulnerabilities"]:
            report["vulnerabilities"].append(vuln)
            log(f"     [!] Found: Weak JWT Config")
    
    # --- Run Endpoint Checks (Loop) ---
    if len(endpoints) > 0:
        for endpoint_string in endpoints:
            # --- CHECK STOP SIGNAL ---
            if report_id:
                from .models import ScanReport
                if ScanReport.objects.get(id=report_id).status == "Stopped":
                    log("[!] Scan stopped by user command.")
                    report['status'] = "Stopped"
                    return report
            # -------------------------

            try:
                if not endpoint_string or " " not in endpoint_string: continue
                method, path = endpoint_string.split(" ", 1)
                method = method.lower()
                
                log(f"  -> Scanning {method.upper()} {path} ...")

                if scan_options.get('auth'):
                    vuln = check_broken_authentication(method, path, base_url, logger)
                    if vuln and vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
                        log(f"     [!] Found: Broken Authentication")

                if scan_options.get('bola') and method == 'get' and auth_headers:
                    vuln = check_bola_vulnerability(method, path, base_url, auth_headers)
                    if vuln and vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
                        log(f"     [!] Found: BOLA")

                if scan_options.get('injection'):
                    vuln = check_injection(method, path, base_url, auth_headers)
                    if vuln and vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
                        log(f"     [!] Found: SQL Injection")

                if scan_options.get('ratelimit'):
                    vuln = check_rate_limit(method, path, base_url, auth_headers)
                    if vuln and vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
                        log(f"     [!] Found: Rate Limit Issue")

                vuln = check_sensitive_data(method, path, base_url, auth_headers)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Data Leak")

                vuln = check_mass_assignment(method, path, base_url, auth_headers)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Mass Assignment")

                vuln = check_unsafe_methods(path, base_url)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Unsafe HTTP Method")

            except Exception as e:
                log(f"     [!] Error scanning {path}: {e}")
    else:
        log("[*] No endpoints to scan. Skipping endpoint-specific tests.")

    if len(report["vulnerabilities"]) > 0:
        report["status"] = "Success"

    log("[+] Scan Completed Successfully.")
    return report