import requests
from urllib.parse import urlparse

class APIScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.report = {
            "target": target_url,
            "status": "Failed",
            "vulnerabilities": [],
            "endpoints": []
        }
        self.swagger_data = None

    def fetch_swagger(self):
        """Step 1: Try to fetch the Swagger/OpenAPI JSON file"""
        try:
            print(f"[*] Fetching {self.target_url}...")
            response = requests.get(self.target_url, timeout=10)
            if response.status_code == 200:
                self.swagger_data = response.json()
                self.report["status"] = "Success"
                print("[+] Successfully fetched API definition.")
                return True
            else:
                print(f"[-] Failed to fetch. Status Code: {response.status_code}")
                return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False

    def check_https(self):
        """Check: Sensitive Data Exposure (Is it using HTTP instead of HTTPS?)"""
        parsed = urlparse(self.target_url)
        if parsed.scheme != 'https':
            self.report["vulnerabilities"].append({
                "name": "Unencrypted Transport",
                "severity": "High",
                "description": "The API is available via HTTP. Sensitive data is not encrypted."
            })
            print("[!] Vulnerability Found: Unencrypted Transport (HTTP)")

    def check_auth_definitions(self):
        """Check: Broken Authentication (Are security schemes defined?)"""
        if not self.swagger_data:
            return

        # Look for 'securitySchemes' in OpenAPI 3.0 or 'securityDefinitions' in Swagger 2.0
        components = self.swagger_data.get('components', {})
        security_schemes = components.get('securitySchemes', {})
        
        # Fallback for older Swagger versions
        if not security_schemes:
            security_schemes = self.swagger_data.get('securityDefinitions', {})

        if not security_schemes:
            self.report["vulnerabilities"].append({
                "name": "Missing Authentication Definitions",
                "severity": "Medium",
                "description": "No global security definitions (like Bearer Token or API Key) found in the spec."
            })
            print("[!] Vulnerability Found: Missing Authentication Definitions")
        else:
            print(f"[+] Found authentication schemes: {list(security_schemes.keys())}")

    def check_security_headers(self):
        """Check: Security Misconfiguration (Missing Security Headers)"""
        try:
            # We send a request to the base URL to check headers
            response = requests.get(self.target_url, timeout=5)
            headers = response.headers
            
            missing_headers = []
            required_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy"
            ]

            for header in required_headers:
                if header not in headers:
                    missing_headers.append(header)

            if missing_headers:
                self.report["vulnerabilities"].append({
                    "name": "Missing Security Headers",
                    "severity": "Low",
                    "description": f"The API response is missing these security headers: {', '.join(missing_headers)}"
                })
                print(f"[!] Vulnerability Found: Missing Headers ({len(missing_headers)})")

        except Exception as e:
            print(f"[-] Error checking headers: {e}")

    def parse_endpoints(self):
        """Extract all endpoints for reporting"""
        if not self.swagger_data:
            return

        paths = self.swagger_data.get('paths', {})
        for path, methods in paths.items():
            for method in methods:
                self.report["endpoints"].append(f"{method.upper()} {path}")
        
        print(f"[*] Found {len(self.report['endpoints'])} endpoints.")

    def run(self):
        """Main execution function"""
        if self.fetch_swagger():
            self.check_https()
            self.check_auth_definitions()
            self.check_security_headers() # Added the header check here
            self.parse_endpoints()
        return self.report