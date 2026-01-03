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
        if urlparse(self.target_base_url).scheme != 'https-': self.report["vulnerabilities"].append({"name": "Unencrypted Transport", "severity": "High", "description": "API is available via HTTP."})
    
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
        """ This function now extracts more detail: path, method, and parameters """
        if not self.api_spec: return
        endpoints_details = []
        paths = self.api_spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    # Extract parameter names for this specific endpoint
                    params = [p.get('name') for p in details.get('parameters', []) if p.get('name')]
                    endpoints_details.append({
                        "path": path,
                        "method": method.upper(),
                        "params": params
                    })
        self.report["endpoints"] = endpoints_details # Store the detailed list

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
    # This function is complete and correct
    if '{' not in path and '}' not in path: return None
    # ... (rest of BOLA logic is the same) ...
    return None

def check_broken_authentication(method, path, base_url):
    # This function is complete and correct
    if any(keyword in path.lower() for keyword in ['login', 'register', 'logout', 'swagger', 'api-docs']): return None
    # ... (rest of Broken Auth logic is the same) ...
    return None

def check_data_exposure(method, path, base_url, auth_headers):
    # This function is complete and correct
    # ... (rest of Data Exposure logic is the same) ...
    return []

# --- UPGRADED INJECTION SCANNER ---
def check_injection(method, path, params, base_url, auth_headers):
    """
    Sends SQLi payloads to actual parameter names discovered from the spec.
    """
    if not params: return None # If this endpoint has no parameters, we can't inject.
    
    print(f"  -> [Injection Check] on {method.upper()} {path} with params: {params}")
    
    INJECTION_PAYLOADS = ["'", "' OR 1=1--"]
    DATABASE_ERRORS = ["sql syntax", "mysql", "unclosed quotation mark", "you have an error in your sql syntax"]
    
    try:
        base_url_with_path = urljoin(base_url, path)
        
        for param_name in params:
            for payload in INJECTION_PAYLOADS:
                # Construct query parameters like ?param1=value&param2=payload
                query_params = {p: "test" for p in params} # a default value for other params
                query_params[param_name] = payload # Inject the payload into the target param
                
                response = requests.request(method, base_url_with_path, params=query_params, headers=auth_headers, timeout=5)

                if response.status_code == 500:
                    return {"name": "Potential SQL Injection (Error-based)", "severity": "High", "description": f"Endpoint {method.upper()} {path} returned a 500 Error when the parameter '{param_name}' was tested with payload: '{payload}'."}
                
                if any(err in response.text.lower() for err in DATABASE_ERRORS):
                    return {"name": "Potential SQL Injection (Leakage-based)", "severity": "High", "description": f"Endpoint {method.upper()} {path} returned a database error message when the parameter '{param_name}' was tested with a payload."}

    except requests.RequestException as e:
        print(f"     ... [Injection Check] Error: {e}")
        
    return None

def start_scan(spec_content, base_url, auth_headers):
    """The main function to orchestrate an entire API scan."""
    passive_scanner = APIScanner(spec_content=spec_content, target_base_url=base_url)
    report = passive_scanner.run_passive_scan()
    if report['status'] == 'Failed': return report

    print("\n[*] Starting Active Scan Phase...")
    # The endpoints object is now a list of dictionaries
    for endpoint in report.get("endpoints", []):
        method = endpoint.get("method", "").lower()
        path = endpoint.get("path", "")
        params = endpoint.get("params", []) # Get the parameter names

        if not method or not path: continue

        try:
            # 1. Run Broken Auth Check
            broken_auth_vuln = check_broken_authentication(method, path, base_url)
            if broken_auth_vuln and broken_auth_vuln not in report["vulnerabilities"]:
                report["vulnerabilities"].append(broken_auth_vuln)

            # --- RUN THE NEW, SMARTER INJECTION CHECK ---
            injection_vuln = check_injection(method, path, params, base_url, auth_headers)
            if injection_vuln and injection_vuln not in report["vulnerabilities"]:
                report["vulnerabilities"].append(injection_vuln)
            
            # (Other checks like BOLA and Data Exposure would go here too)
            # ...
            
        except Exception as e: 
            print(f"     ... Error during active scan on {method.upper()} {path}: {e}")
    
    print("[+] Active Scan Phase Complete.")
    return report