import os
import re

class SASTScanner:
    def __init__(self, target_dir, scan_options=None):
        self.target_dir = target_dir
        self.scan_options = scan_options or {'sast_secrets': True, 'sast_sqli': True, 'sast_shadow_api': True}
        self.report = {
            "target": f"Git Repository Archive",
            "status": "Running",
            "vulnerabilities": [],
            "endpoints": []
        }
        
    def log(self, logger, msg):
        print(msg)
        if logger:
            logger(msg)

    def scan_directory(self, logger=None):
        self.log(logger, f"[*] Starting Static Analysis (SAST) on {self.target_dir}")
        
        # Regex Definitions
        # 1. Shadow APIs
        # Matches Express (app.get('/api')), Flask (@app.route('/api')), Django (path('api/'))
        route_patterns = [
            r"app\.(get|post|put|delete|patch|all)\(\s*['\"]([^'\"]+)['\"]",
            r"router\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]",
            r"@app\.route\(\s*['\"]([^'\"]+)['\"]",
            r"path\(\s*['\"]([^'\"]+)['\"]",
            r"url\(\s*r['\"]([^'\"]+)['\"]",
            r"@(Get|Post|Put|Delete|Patch)Mapping\(\s*(?:path\s*=\s*)?['\"]([^'\"]+)['\"]",
            r"@router\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"
        ]
        
        # 2. Exposed Secrets
        secret_patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic Secret/Password": r"(?i)(password|secret|api_key|token|client_secret)[\s]*[=:]\s*['\"]([^'\"]{8,})['\"]",
            "Private Key": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
            "GitHub PAT": r"ghp_[0-9a-zA-Z]{36}",
            "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "GCP API Key": r"AIza[0-9A-Za-z-_]{35}"
        }
        
        # 3. SQL Injection (Raw Queries without parameters)
        # Matches cursor.execute("SELECT * FROM x WHERE id=" + id) or f"SELECT * FROM x WHERE id={id}"
        sqli_patterns = [
            r"cursor\.execute\s*\(\s*(f['\"].*?\{.*?\}|['\"].*?%.*?['\"]\s*%|.*?\+.*?)",
            r"db\.query\s*\(\s*(f['\"].*?\{.*?\}|['\"].*?%.*?['\"]\s*%|.*?\+.*?)",
            r"sequelize\.query\s*\(\s*['\"`].*?\$\{.*?\}",
            r"ORM\.raw\s*\(\s*['\"`].*?\+.*?"
        ]

        # 4. Insecure CORS
        cors_patterns = [
            r"cors\(\{\s*origin\s*:\s*['\"]\*(?:['\"]|\s*\})",
            r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True",
            r"CORS\(.*origins.*\*.*\)"
        ]
        
        # 5. Command Injection
        cmd_patterns = [
            r"os\.system\s*\(\s*(f['\"].*?\{.*?\}|.*?\+.*?)",
            r"subprocess\.(Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True[^)]*\)",
            r"exec\s*\(\s*['\"`].*?(\+.*|\$\{.*?\})",
            r"eval\s*\(" 
        ]
        
        has_rate_limiter = False
        rate_limiter_imports = [
            "express-rate-limit", "flask_limiter", "django_ratelimit", "ratelimit"
        ]

        found_endpoints = set()

        for root, dirs, files in os.walk(self.target_dir):
            if '.git' in dirs: dirs.remove('.git')
            if 'node_modules' in dirs: dirs.remove('node_modules')
            if '__pycache__' in dirs: dirs.remove('__pycache__')
            if 'venv' in dirs: dirs.remove('venv')
            if 'env' in dirs: dirs.remove('env')

            for file in files:
                if file.endswith(('.js', '.ts', '.py', '.php', '.go', '.java', '.rb')):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.target_dir)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            
                            for line_num, line in enumerate(lines, 1):
                                # 1. Extract APIs
                                if self.scan_options.get('sast_shadow_api'):
                                    for pattern in route_patterns:
                                        match = re.search(pattern, line)
                                        if match:
                                            # Handling groups (Express has method in g1, path in g2. Django/Flask has path in g1)
                                            if len(match.groups()) > 1:
                                                method = match.group(1).upper()
                                                path = match.group(2)
                                                found_endpoints.add(f"{method} {path}")
                                            else:
                                                path = match.group(1)
                                                found_endpoints.add(f"ANY {path}")

                                # 2. Check Secrets
                                if self.scan_options.get('sast_secrets'):
                                    for secret_name, pattern in secret_patterns.items():
                                        if re.search(pattern, line):
                                            self.report["vulnerabilities"].append({
                                                "name": "Hardcoded Secret/Token",
                                                "severity": "Critical",
                                                "description": f"Found potentially exposed {secret_name} in {rel_path} on line {line_num}.\nCode Snippet: `{line.strip()}`\n[Violates PCI-DSS Req. 8.2.1]",
                                                "cvss": 9.8,
                                                "owasp": "API9:2023 Improper Inventory Management"
                                            })
                                            self.log(logger, f"     [!] SAST Found: Hardcoded Secret ({secret_name}) in {rel_path}:{line_num}")
                                
                                # 3. Check SQLi
                                if self.scan_options.get('sast_sqli'):
                                    for pattern in sqli_patterns:
                                        if re.search(pattern, line):
                                            self.report["vulnerabilities"].append({
                                                "name": "Static SQL Injection (Insecure Query)",
                                                "severity": "High",
                                                "description": f"Found raw database query concatenation/formatting in {rel_path} on line {line_num}, which may lead to SQL Injection.\nCode Snippet: `{line.strip()}`\n[Violates PCI-DSS Req. 6.5.1]",
                                                "cvss": 8.5,
                                                "owasp": "API8:2023 Security Misconfiguration"
                                            })
                                            self.log(logger, f"     [!] SAST Found: Potential SQLi in {rel_path}:{line_num}")

                                # 4. Check CORS
                                if self.scan_options.get('sast_cors'):
                                    for pattern in cors_patterns:
                                        if re.search(pattern, line):
                                            self.report["vulnerabilities"].append({
                                                "name": "Static Insecure CORS",
                                                "severity": "High",
                                                "description": f"Found wildcard Cross-Origin Resource Sharing (CORS) in {rel_path} on line {line_num}.\nCode Snippet: `{line.strip()}`\n[Violates SOC 2 CC6.1]",
                                                "cvss": 7.5,
                                                "owasp": "API8:2023 Security Misconfiguration"
                                            })
                                            self.log(logger, f"     [!] SAST Found: Insecure CORS in {rel_path}:{line_num}")
                                            
                                # 5. Command Injection
                                if self.scan_options.get('sast_cmdinj', True):
                                    for pattern in cmd_patterns:
                                        if re.search(pattern, line):
                                            self.report["vulnerabilities"].append({
                                                "name": "Static Command Injection",
                                                "severity": "Critical",
                                                "description": f"Found potentially unsafe execution of OS commands via {rel_path} on line {line_num}.\nCode Snippet: `{line.strip()}`\n[Violates PCI-DSS Req. 6.5.1]",
                                                "cvss": 9.8,
                                                "owasp": "API8:2023 Security Misconfiguration"
                                            })
                                            self.log(logger, f"     [!] SAST Found: Command Injection in {rel_path}:{line_num}")
                                
                                # Track Rate limiters
                                if self.scan_options.get('sast_ratelimit') and not has_rate_limiter:
                                    for rl_pkg in rate_limiter_imports:
                                        if rl_pkg in line:
                                            has_rate_limiter = True

                    except Exception as e:
                        self.log(logger, f"[-] Error reading {rel_path}: {e}")

        # Adding Endpoints
        self.report["endpoints"] = list(found_endpoints)
        if found_endpoints:
            self.log(logger, f"[+] SAST Extracted {len(found_endpoints)} endpoints statically from code.")
        
        # Check if rate limiter was completely missing
        if self.scan_options.get('sast_ratelimit') and found_endpoints and not has_rate_limiter:
            self.report["vulnerabilities"].append({
                "name": "Missing Rate Limiter (Static)",
                "severity": "Medium",
                "description": "API endpoints were found in the project, but no common rate-limiting library (e.g., express-rate-limit, flask_limiter) was detected. [Violates SOC 2 CC6.1]",
                "cvss": 5.3,
                "owasp": "API4:2023 Unrestricted Resource Consumption"
            })
            self.log(logger, f"     [!] SAST Found: Missing Rate Limiting Middleware")

        self.report["status"] = "Success"
        self.log(logger, "[+] SAST Completed Successfully.")
        return self.report

def start_sast_scan(target_dir, scan_options=None, logger=None, report_id=None):
    scanner = SASTScanner(target_dir, scan_options)
    return scanner.scan_directory(logger)
