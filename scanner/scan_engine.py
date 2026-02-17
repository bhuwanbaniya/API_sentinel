import requests
import yaml
import re
import time
import base64
import json
from urllib.parse import urlparse, urljoin

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
            self.report["vulnerabilities"].append({"name": "Unencrypted Transport", "severity": "High", "description": "API is available via HTTP."})
    
    def check_auth_definitions(self):
        if not self.api_spec: return
        sec = self.api_spec.get('components', {}).get('securitySchemes', {}) or self.api_spec.get('securityDefinitions', {})
        if not sec:
            self.report["vulnerabilities"].append({"name": "Missing Auth Definitions", "severity": "Medium", "description": "No global security schemes found."})

    def check_security_headers(self):
        if not self.target_base_url: return
        try:
            headers = requests.get(self.target_base_url, timeout=5).headers
            missing = [h for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"] if h not in headers]
            if missing:
                self.report["vulnerabilities"].append({"name": "Missing Security Headers", "severity": "Low", "description": f"Missing headers: {', '.join(missing)}"})
        except: pass

    def parse_endpoints(self):
        if not self.api_spec: return
        paths = self.api_spec.get('paths', {})
        for path, methods in paths.items():
            for method in methods:
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    self.report["endpoints"].append(f"{method.upper()} {path}")

    def run_passive_scan(self):
        if self.parse_spec():
            self.check_https()
            self.check_auth_definitions()
            self.check_security_headers()
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

def check_broken_authentication(method, path, base_url, logger=None):
    if 'login' in path or 'register' in path: return None
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        url = f"{clean_base}{re.sub(r'\{.*?\}', '1', path)}"
        res = requests.request(method, url, timeout=5) 
        if res.status_code not in [401, 403]: 
            return {"name": "Broken Authentication", "severity": "High", "description": f"Endpoint {method} {path} processed request without auth (Status: {res.status_code})."}
    except: pass
    return None

def check_bola_vulnerability(method, path, base_url, auth_headers):
    if '{' not in path: return None
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        url1 = f"{clean_base}{re.sub(r'\{.*?\}', '1', path)}"
        url2 = f"{clean_base}{re.sub(r'\{.*?\}', '2', path)}"
        res1 = requests.request(method, url1, headers=auth_headers, timeout=5)
        res2 = requests.request(method, url2, headers=auth_headers, timeout=5)
        if res1.status_code == 200 and res2.status_code == 200 and abs(len(res1.content) - len(res2.content)) < 50:
            return {"name": "BOLA / IDOR", "severity": "High", "description": f"Endpoint {path} allows accessing multiple object IDs."}
    except: pass
    return None

def check_injection(method, path, base_url, auth_headers):
    payloads = ["'", "\"", "' OR 1=1--"]
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        url = f"{clean_base}{path}?id=' OR 1=1--"
        res = requests.request(method, url, headers=auth_headers, timeout=5)
        if res.status_code == 500 or "sql" in res.text.lower():
            return {"name": "SQL Injection", "severity": "High", "description": f"Endpoint {path} returned database error."}
    except: pass
    return None

def check_rate_limit(method, path, base_url, auth_headers):
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        url = f"{clean_base}{re.sub(r'\{.*?\}', '1', path)}"
        for _ in range(5):
            res = requests.request(method, url, headers=auth_headers, timeout=1)
            if res.status_code == 429: return None
        return {"name": "Missing Rate Limiting", "severity": "Medium", "description": "Endpoint allowed rapid burst requests."}
    except: pass
    return None

def check_sensitive_data(method, path, base_url, auth_headers):
    if method != 'get': return None
    patterns = {"Email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', "SSN": r'\b\d{3}-\d{2}-\d{4}\b'}
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        url = f"{clean_base}{re.sub(r'\{.*?\}', '1', path)}"
        res = requests.get(url, headers=auth_headers, timeout=5)
        found = [k for k, v in patterns.items() if re.search(v, res.text)]
        if found: return {"name": "Excessive Data Exposure", "severity": "High", "description": f"Endpoint leaked: {', '.join(found)}"}
    except: pass
    return None

def check_mass_assignment(method, path, base_url, auth_headers):
    if method not in ['post', 'put']: return None
    payload = {"isAdmin": True, "role": "admin"}
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        url = f"{clean_base}{path}"
        res = requests.request(method, url, json=payload, headers=auth_headers, timeout=5)
        if res.status_code in [200, 201] and ("admin" in res.text.lower() or "true" in res.text.lower()):
            return {"name": "Potential Mass Assignment", "severity": "Medium", "description": f"Endpoint {method} {path} accepted a payload with 'isAdmin'."}
    except: pass
    return None

def check_unsafe_methods(path, base_url):
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        url = f"{clean_base}{path}"
        res = requests.request("TRACE", url, timeout=5)
        if res.status_code == 200:
            return {"name": "Unsafe HTTP Method (TRACE)", "severity": "Low", "description": "Server enabled TRACE method."}
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
            return {"name": "Insecure JWT (None Alg)", "severity": "Critical", "description": "JWT allows 'None' algorithm."}
        if header_data.get('alg', '').upper() == 'HS256':
            return {"name": "Weak JWT Key (HS256)", "severity": "Low", "description": "JWT uses symmetric HS256 key."}
    except: pass
    return None

def check_debug_endpoints(base_url):
    paths = ['/admin', '/api/admin', '/metrics', '/health', '/.env', '/config']
    clean_base = base_url.rstrip('/')
    for p in paths:
        try:
            url = f"{clean_base}{p}"
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                return {"name": "Exposed Sensitive Path", "severity": "Medium", "description": f"Path {p} is accessible."}
        except: pass
    return None

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