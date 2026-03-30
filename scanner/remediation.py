REMEDIATION_GUIDE = {
    "Broken Authentication": {
        "advice": "Enforce authentication on all private routes. Ensure tokens are validated before processing requests.",
        "snippets": {
            "Python (Django)": "from rest_framework.permissions import IsAuthenticated\n@permission_classes([IsAuthenticated])",
            "Node.js (Express)": "const auth = require('./middleware/auth');\napp.get('/api/data', auth, (req, res) => { ... });",
            "Java (Spring)": "@PreAuthorize(\"isAuthenticated()\")\npublic ResponseEntity getData() { ... }",
            "PHP (Laravel)": "Route::middleware('auth:sanctum')->get('/user', ...);"
        }
    },
    "BOLA": {
        "advice": "Verify that the user requesting the resource actually owns it.",
        "snippets": {
            "Python (Django)": "obj = get_object_or_404(Model, id=id, user=request.user)",
            "PHP (Laravel)": "if ($item->user_id !== auth()->id()) { abort(403); }"
        }
    },
    "SQL Injection": {
        "advice": "Use Parameterized Queries or an ORM to prevent malicious input from executing as code.",
        "snippets": {
            "Python (Django)": "User.objects.filter(username=name) # ORM is safe",
            "Java (JPA)": "@Query(\"SELECT u FROM User u WHERE u.id = :id\")"
        }
    },
    "Missing Rate Limiting": {
        "advice": "Implement a rate-limiter (Throttling) to prevent DDoS and brute-force attacks.",
        "snippets": {
            "Node.js": "const limiter = rateLimit({ windowMs: 15*60*1000, max: 100 });",
            "Nginx": "limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;"
        }
    }
}

def get_remediation(vulnerability_name):
    for key, info in REMEDIATION_GUIDE.items():
        if key.lower() in vulnerability_name.lower():
            return info
    return None