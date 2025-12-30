import requests
import yaml
import re
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
            if isinstance(self.api_spec, dict): self.report["status"] = "Success"; return True
        except (yaml.YAMLError, ValueError) as e: print(f"[-] Error parsing spec: {e}")
        return False
        
    def check_https(self):
        if not self.target_base_url: return
        if urlparse(self.target_base_url).scheme != 'https': self.report["vulnerabilities"].append({"name": "Unencrypted Transport", "severity": "High", "description": "API is available via HTTP."})
    
    def check_auth_definitions(self):
        if not self.api_spec: return
        sec_schemes = self.api_spec.get('components', {}).get('securitySchemes', {}) or self.api_spec.get('securityDefinitions', {})
        if not sec_schemes: self.report["vulnerabilities"].append({"name": "Missing Auth Definitions", "severity": "Medium", "description": "No global security schemes found."})

    def check_security_headers(self):
        if not self.target_base_url: return
        try:
            headers = requests.get(self.target_base_url, timeout=5).headers
            missing = [h for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"] if h not in headers]
            if missing: self.report["vulnerabilities"].append({"name": "Missing Security Headers", "severity": "Low", "description": f"Missing headers: {', '.join(missing)}"})
        except requests.RequestException: pass

    def parse_endpoints(self):
        if not self.api_spec: return
        for path, methods in self.api_spec.get('paths', {}).items():
            for method in methods:
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']: self.report["endpoints"].append(f"{method.upper()} {path}")

    def run_passive_scan(self):
        if self.parse_spec(): self.check_https(), self.check_auth_definitions(), self.check_security_headers(), self.parse_endpoints()
        return self.report

# ==============================================================================
# ACTIVE SCANNING AND ORCHESTRATION
# ==============================================================================
def fetch_swagger_from_url(url):
    try: response = requests.get(url, timeout=10); response.raise_for_status(); return response.text
    except requests.RequestException as e: print(f"Error fetching swagger: {e}"); return None

def check_bola_vulnerability(method, path, base_url, auth_headers):
    if '{' not in path and '}' not in path: return None
    print(f"  -> [BOLA Check] on {method.upper()} {path}")
    try:
        path_1 = re.sub(r'\{.*?\}', '1', path); url_1 = urljoin(base_url, path_1)
        res1 = requests.request(method, url_1, headers=auth_headers, timeout=5)
        path_2 = re.sub(r'\{.*?\}', '2', path); url_2 = urljoin(base_url, path_2)
        res2 = requests.request(method, url_2, headers=auth_headers, timeout=5)
        print(f"     ... ID 1 Status: {res1.status_code}, ID 2 Status: {res2.status_code}")
        if res1.status_code == 200 and res2.status_code == 200:
            if abs(len(res1.content) - len(res2.content)) < (len(res1.content) * 0.1):
                return {"name": "Broken Object Level Authorization (BOLA)", "severity": "High", "description": f"Endpoint {method.upper()} {path} may be vulnerable."}
        elif res1.status_code == 200 and res2.status_code in [401, 403, 404]:
            print(f"     [+] SUCCESS: Endpoint correctly blocked access to ID 2 (Status: {res2.status_code}). Not vulnerable to BOLA.")
        elif res1.status_code == 404:
            print(f"     [*] INFO: Test object with ID 1 not found (Status: {res1.status_code}). Cannot perform BOLA check.")
    except requests.RequestException as e: print(f"     ... [BOLA Check] Error: {e}")
    return None

def check_broken_authentication(method, path, base_url):
    if any(keyword in path.lower() for keyword in ['login', 'register', 'logout', 'swagger', 'api-docs']): return None
    print(f"  -> [Broken Auth Check] on {method.upper()} {path}")
    try:
        full_url = urljoin(base_url, path)
        if '{' in full_url and '}' in full_url: full_url = re.sub(r'\{.*?\}', '1', full_url)
        response = requests.request(method, full_url, timeout=5, allow_redirects=False)
        if response.status_code not in [401, 403]:
            return {"name": "Broken Authentication", "severity": "High", "description": f"The endpoint {method.upper()} {path} is accessible without authentication (Status: {response.status_code})."}
        else:
            print(f"     [+] SUCCESS: Endpoint correctly blocked unauthenticated access (Status: {response.status_code}).")
    except requests.RequestException as e: print(f"     ... [Broken Auth Check] Error: {e}")
    return None

def check_data_exposure(method, path, base_url, auth_headers):
    print(f"  -> [Data Exposure Check] on {method.upper()} {path}")
    SENSITIVE_DATA_PATTERNS = {"Email Address": r'[\w\.-]+@[\w\.-]+', "API Key": r'(?i)api_?key[\s_]*[=:\'"]\s*[\w-]{32,}', "Simple Word 'user'": r'user'}
    vulnerabilities = []
    try:
        full_url = urljoin(base_url, path)
        if '{' in full_url and '}' in full_url: full_url = re.sub(r'\{.*?\}', '1', full_url)
        response = requests.request(method, full_url, headers=auth_headers, timeout=5)
        if 200 <= response.status_code < 300:
            for name, regex in SENSITIVE_DATA_PATTERNS.items():
                if re.search(regex, response.text):
                    vulnerabilities.append({"name": f"Excessive Data Exposure ({name})", "severity": "Medium", "description": f"The response from {method.upper()} {path} appears to contain sensitive data: '{name}'."})
    except requests.RequestException as e: print(f"     ... [Data Exposure Check] Error: {e}")
    return vulnerabilities
#imporve ---code----


def start_scan(spec_content, base_url, auth_headers):
    """The main function to orchestrate an entire API scan."""
    passive_scanner = APIScanner(spec_content=spec_content, target_base_url=base_url)
    report = passive_scanner.run_passive_scan()
    if report['status'] == 'Failed': return report

    print("\n[*] Starting Active Scan Phase...")
    for endpoint_string in report.get("endpoints", []):
        try:
            method, path = endpoint_string.split(" ", 1); method = method.lower()
            
            # --- FINAL CORRECTED SCANNING LOGIC ---
            
            # 1. Run Broken Auth Check
            broken_auth_vuln = check_broken_authentication(method, path, base_url)
            if broken_auth_vuln and broken_auth_vuln not in report["vulnerabilities"]:
                report["vulnerabilities"].append(broken_auth_vuln)

            # 2. Run BOLA Check (if auth header is provided)
            if method == 'get' and auth_headers:
                bola_vuln = check_bola_vulnerability(method, path, base_url, auth_headers)
                if bola_vuln and bola_vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(bola_vuln)
            
            # 3. ALWAYS run Data Exposure on GET requests for this test
            if method == 'get':
                exposure_vulns = check_data_exposure(method, path, base_url, auth_headers)
                for vuln in exposure_vulns:
                    if vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
            
        except Exception as e: 
            print(f"     ... Error during active scan on {endpoint_string}: {e}")
    
    print("[+] Active Scan Phase Complete.")
    return report