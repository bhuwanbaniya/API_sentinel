import requests
import yaml
import re
import time
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
        if not paths:
            print("[-] No paths found in Swagger file.")
            return
            
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

def check_broken_authentication(method, path, base_url, logger):
    if 'login' in path or 'register' in path: return None
    try:
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        clean_path = re.sub(r'\{.*?\}', '1', path)
        url = f"{clean_base}{clean_path}"
        
        res = requests.request(method, url, timeout=5) 
        
        # If it DOES NOT return 401 or 403, it means Auth is broken.
        if res.status_code not in [401, 403]: 
            # FORCE HIGH SEVERITY FOR EVERYTHING
            return {
                "name": "Broken Authentication", 
                "severity": "High",  # <--- Always High
                "description": f"Endpoint {method} {path} processed the request without authentication (Status: {res.status_code}). Access was not blocked."
            }
    except Exception as e:
        logger(f"Err in Auth Check: {e}")
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
        
        # Send 5 fast requests
        for _ in range(5):
            res = requests.request(method, url, headers=auth_headers, timeout=1)
            if res.status_code == 429: return None
        return {"name": "Missing Rate Limiting", "severity": "Medium", "description": "Endpoint allowed rapid burst requests."}
    except: pass
    return None
def check_sensitive_data(method, path, base_url, auth_headers):
    """
    Active Check: Sends a request and scans the RESPONSE BODY for PII (Personally Identifiable Information).
    """
    # We only check GET requests for data leaks usually
    if method != 'get': return None

    # Regex Patterns for secrets
    patterns = {
        "Email Address": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "Social Security Number (SSN)": r'\b\d{3}-\d{2}-\d{4}\b',
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Private Key": r'-----BEGIN PRIVATE KEY-----',
        "Credit Card (Basic)": r'\b(?:\d[ -]*?){13,16}\b'
    }

    try:
        # Construct URL (replace {id} with 1)
        clean_base = base_url.split('/v2/')[0] + '/v2' if '/v2/' in base_url else base_url.rstrip('/')
        clean_path = re.sub(r'\{.*?\}', '1', path)
        url = f"{clean_base}{clean_path}"

        response = requests.get(url, headers=auth_headers, timeout=5)
        
        if response.status_code == 200:
            content = response.text
            leaked_types = []
            
            # Check content against all patterns
            for name, pattern in patterns.items():
                if re.search(pattern, content):
                    leaked_types.append(name)
            
            if leaked_types:
                return {
                    "name": "Excessive Data Exposure (PII)", 
                    "severity": "High", 
                    "description": f"Endpoint {method.upper()} {path} is leaking sensitive information in the response body. Detected: {', '.join(leaked_types)}."
                }

    except Exception: pass
    return None
# ==============================================================================
# MASTER SCAN FUNCTION
# ==============================================================================
def start_scan(spec_content, base_url, auth_headers, scan_options=None, logger=None):
    """
    Orchestrates the scan based on selected options.
    scan_options is a dictionary, e.g., {'bola': True, 'injection': False}
    """
    def log(msg):
        print(msg)
        if logger: logger(msg)

    # Default to True if no options provided
    if scan_options is None:
        scan_options = {'bola': True, 'auth': True, 'injection': True, 'ratelimit': True}

    log(f"[*] Initializing scan for: {base_url}")
    
    passive_scanner = APIScanner(spec_content=spec_content, target_base_url=base_url)
    report = passive_scanner.run_passive_scan()
    
    if report['status'] == 'Failed':
        log("[-] Parsing failed. Aborting.")
        return report

    endpoints = report.get("endpoints", [])
    log(f"[+] Successfully parsed {len(endpoints)} endpoints.")
    
    log("\n[*] Starting Active Scan Phase...")
    
    for endpoint_string in endpoints:
        try:
            if not endpoint_string or " " not in endpoint_string: continue
            method, path = endpoint_string.split(" ", 1)
            method = method.lower()
            
            log(f"  -> Scanning {method.upper()} {path} ...")

            # --- 1. Broken Auth ---
            if scan_options.get('auth'): # Check if user wanted this
                vuln = check_broken_authentication(method, path, base_url, log)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Broken Authentication")

            # --- 2. BOLA ---
            if scan_options.get('bola'): # Check if user wanted this
                if method == 'get' and auth_headers:
                    vuln = check_bola_vulnerability(method, path, base_url, auth_headers)
                    if vuln and vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
                        log(f"     [!] Found: BOLA")

            # --- 3. Injection ---
            if scan_options.get('injection'): # Check if user wanted this
                vuln = check_injection(method, path, base_url, auth_headers)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: SQL Injection")

            # --- 4. Rate Limit ---
            if scan_options.get('ratelimit'): # Check if user wanted this
                vuln = check_rate_limit(method, path, base_url, auth_headers)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Rate Limit Issue")

        except Exception as e:
            log(f"     [!] Error scanning {path}: {e}")

    log("[+] Scan Completed Successfully.")
    return report