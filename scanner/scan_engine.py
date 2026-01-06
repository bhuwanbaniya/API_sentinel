import requests
import yaml
import re
import time
from urllib.parse import urlparse, urljoin

# ==============================================================================
# PASSIVE SCANNER CLASS
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
        except (yaml.YAMLError, ValueError) as e:
            print(f"[-] Error parsing spec: {e}")
        return False
        
    def check_https(self):
        if not self.target_base_url: return
        if urlparse(self.target_base_url).scheme != 'https':
            self.report["vulnerabilities"].append({"name": "Unencrypted Transport", "severity": "High", "description": "API is available via HTTP."})
    
    def check_auth_definitions(self):
        if not self.api_spec: return
        sec_schemes = self.api_spec.get('components', {}).get('securitySchemes', {}) or self.api_spec.get('securityDefinitions', {})
        if not sec_schemes:
            self.report["vulnerabilities"].append({"name": "Missing Auth Definitions", "severity": "Medium", "description": "No global security schemes found."})

    def check_security_headers(self):
        if not self.target_base_url: return
        try:
            headers = requests.get(self.target_base_url, timeout=5).headers
            missing = [h for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"] if h not in headers]
            if missing:
                self.report["vulnerabilities"].append({"name": "Missing Security Headers", "severity": "Low", "description": f"Missing headers: {', '.join(missing)}"})
        except requests.RequestException:
            pass

    def parse_endpoints(self):
        if not self.api_spec: return
        endpoints_details = []
        paths = self.api_spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    params = [p.get('name') for p in details.get('parameters', []) if p.get('name')]
                    endpoints_details.append({"path": path, "method": method.upper(), "params": params})
        self.report["endpoints"] = endpoints_details

    def run_passive_scan(self):
        if self.parse_spec():
            self.check_https()
            self.check_auth_definitions()
            self.check_security_headers()
            self.parse_endpoints()
        return self.report

# ==============================================================================
# ACTIVE SCANNING MODULES
# ==============================================================================

def check_broken_authentication(method, path, base_url):
    if any(k in path.lower() for k in ['login', 'register', 'logout']): return None
    print(f"  -> [Broken Auth Check] on {method.upper()} {path}")
    try:
        full_url = urljoin(base_url, re.sub(r'\{.*?\}', '1', path))
        res = requests.request(method, full_url, timeout=5, allow_redirects=False)
        if res.status_code not in [401, 403]:
            return {"name": "Broken Authentication", "severity": "High", "description": f"Endpoint {path} is accessible without authentication."}
    except: pass
    return None

def check_bola_vulnerability(method, path, base_url, auth_headers):
    if '{' not in path: return None
    print(f"  -> [BOLA Check] on {method.upper()} {path}")
    try:
        url_1 = urljoin(base_url, re.sub(r'\{.*?\}', '1', path))
        res1 = requests.request(method, url_1, headers=auth_headers, timeout=5)
        url_2 = urljoin(base_url, re.sub(r'\{.*?\}', '2', path))
        res2 = requests.request(method, url_2, headers=auth_headers, timeout=5)
        if res1.status_code == 200 and res2.status_code == 200:
            return {"name": "BOLA", "severity": "High", "description": f"Endpoint {path} allows access to multiple object IDs."}
    except: pass
    return None

def check_injection(method, path, params, base_url, auth_headers):
    if not params: return None
    print(f"  -> [Injection Check] on {method.upper()} {path}")
    payloads = ["'", "' OR 1=1--"]
    for param in params:
        for payload in payloads:
            try:
                res = requests.request(method, urljoin(base_url, path), params={param: payload}, headers=auth_headers, timeout=5)
                if res.status_code == 500 or any(err in res.text.lower() for err in ["sql", "mysql", "syntax"]):
                    return {"name": "SQL Injection", "severity": "Critical", "description": f"Potential SQLi on param '{param}' at {path}."}
            except: pass
    return None

def check_data_exposure(method, path, base_url, auth_headers):
    print(f"  -> [Data Exposure Check] on {method.upper()} {path}")
    patterns = {"Email": r'[\w\.-]+@[\w\.-]+', "API Key": r'(?i)api_?key.*'}
    try:
        res = requests.request(method, urljoin(base_url, path), headers=auth_headers, timeout=5)
        for name, regex in patterns.items():
            if re.search(regex, res.text):
                return {"name": "Data Exposure", "severity": "High", "description": f"Response contains sensitive {name} pattern at {path}."}
    except: pass
    return None

def check_rate_limit(method, path, base_url, auth_headers):
    print(f"  -> [Rate Limit Check] on {method.upper()} {path}")
    try:
        full_url = urljoin(base_url, re.sub(r'\{.*?\}', '1', path))
        for _ in range(5):
            res = requests.request(method, full_url, headers=auth_headers, timeout=2)
            if res.status_code == 429: return None
        return {"name": "Missing Rate Limit", "severity": "Medium", "description": f"Endpoint {path} does not enforce rate limiting."}
    except: pass
    return None

# ==============================================================================
# MASTER ORCHESTRATOR
# ==============================================================================
def fetch_swagger_from_url(url):
    try:
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        res.raise_for_status()
        return res.text
    except Exception as e:
        print(f"Error fetching swagger: {e}")
        return None

def start_scan(spec_content, base_url, auth_headers):
    passive_scanner = APIScanner(spec_content=spec_content, target_base_url=base_url)
    report = passive_scanner.run_passive_scan()
    if report['status'] == 'Failed': return report

    print("\n[*] Starting Active Scan Phase...")
    for endpoint in report.get("endpoints", []):
        path, method, params = endpoint['path'], endpoint['method'], endpoint['params']
        
        # Call ALL Scanners
        v1 = check_broken_authentication(method, path, base_url)
        if v1: report["vulnerabilities"].append(v1)

        v2 = check_bola_vulnerability(method, path, base_url, auth_headers)
        if v2: report["vulnerabilities"].append(v2)

        v3 = check_injection(method, path, params, base_url, auth_headers)
        if v3: report["vulnerabilities"].append(v3)

        if method == 'GET':
            v4 = check_data_exposure(method, path, base_url, auth_headers)
            if v4: report["vulnerabilities"].append(v4)

        v5 = check_rate_limit(method, path, base_url, auth_headers)
        if v5: report["vulnerabilities"].append(v5)

    print("[+] Active Scan Phase Complete.")
    return report