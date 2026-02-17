# scanner/remediation.py

REMEDIATION_GUIDE = {
    "Broken Authentication": {
        "advice": "Enforce authentication on all private routes. Ensure tokens are validated before processing requests.",
        "snippets": {
            "Python (Django)": """from rest_framework.permissions import IsAuthenticated
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_data(request):
    return Response({"data": "Secret"})""",
            
            "Node.js (Express)": """const auth = require('./middleware/auth');
app.get('/api/data', auth, (req, res) => {
  res.json({ data: "Secret" });
});""",

            "Java (Spring)": """@GetMapping("/api/data")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<String> getData() {
    return ResponseEntity.ok("Secret");
}""",

            "PHP (Laravel)": """Route::middleware('auth:sanctum')->get('/api/data', function () {
    return response()->json(['data' => 'Secret']);
});"""
        }
    },
    "BOLA": {
        "advice": "Always verify that the logged-in user ID matches the ID of the resource owner.",
        "snippets": {
            "Python (Django)": """order = get_object_or_404(Order, id=order_id, user=request.user)""",
            
            "Node.js (Express)": """if (order.userId !== req.user.id) {
  return res.status(403).json({ error: "Unauthorized" });
}""",

            "Java (Spring)": """if (!order.getUser().equals(currentUser)) {
    throw new AccessDeniedException("Not authorized");
}""",

            "PHP (Laravel)": """if ($order->user_id !== auth()->id()) {
    abort(403);
}"""
        }
    },
    "SQL Injection": {
        "advice": "Use Parameterized Queries or an ORM. Never concatenate strings into queries.",
        "snippets": {
            "Python (Django)": """# ORM handles escaping automatically
user = User.objects.filter(username=name).first()""",
            
            "Node.js (Sequelize)": """await sequelize.query(
  'SELECT * FROM users WHERE name = ?',
  { replacements: [inputName] }
);""",

            "Java (JPA)": """@Query("SELECT u FROM User u WHERE u.username = :name")
User findByUsername(@Param("name") String name);""",

            "PHP (PDO)": """$stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');
$stmt->execute(['name' => $inputName]);"""
        }
    },
    "Excessive Data Exposure": {
        "advice": "Filter response data to only return necessary fields (Data Transfer Objects).",
        "snippets": {
            "Python (Django)": """class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username'] # No password!""",
            
            "Node.js": """res.json({
  id: user.id,
  username: user.username
});""",

            "Java (Spring)": """public class UserDTO {
    private String username;
    // Password field is omitted
}""",

            "PHP (Laravel)": """return $user->only(['id', 'username']);"""
        }
    },
    "Rate Limiting": {
        "advice": "Configure throttling middleware to prevent DDoS.",
        "snippets": {
            "Python (Django)": """'DEFAULT_THROTTLE_RATES': {
    'anon': '100/day',
    'user': '1000/day'
}""",
            "Node.js": """const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});""",
            "Java (Spring)": """@Bucket4j
public ResponseEntity<String> rateLimitedEndpoint() { ... }""",
            "PHP (Laravel)": """Route::middleware('throttle:60,1')->group(function () { ... });"""
        }
    },
    "Missing Security Headers": {
        "advice": "Add security headers (CSP, X-Frame-Options) via middleware/config.",
        "snippets": {
            "Python (Django)": """MIDDLEWARE += ['csp.middleware.CSPMiddleware']
X_FRAME_OPTIONS = 'DENY'""",
            "Node.js (Helmet)": """const helmet = require('helmet');
app.use(helmet());""",
            "Java (Spring Security)": """http.headers()
    .xssProtection()
    .and().contentSecurityPolicy("script-src 'self'");""",
            "Nginx (Universal)": """add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";"""
        }
    },
    "Mass Assignment": {
        "advice": "Do not bind input data directly to internal objects. Use 'read_only_fields' or DTOs.",
        "snippets": {
            "Python (Django)": """read_only_fields = ['is_admin', 'role']""",
            "Node.js": """// Pick only allowed fields
const { name, email } = req.body;
User.create({ name, email }); // Ignores 'isAdmin'"""
        }
    },
    "Unsafe HTTP Method": {
        "advice": "Disable dangerous HTTP methods like TRACE, TRACK, or DELETE on endpoints that do not require them.",
        "snippets": {
            "Nginx": """limit_except GET POST { deny all; }""",
            "Apache": """<LimitExcept GET POST>
    Deny from all
</LimitExcept>"""
        }
    },
    "Weak JWT": {
        "advice": "Ensure JWTs are signed using strong algorithms (RS256) and secrets. Disable the 'None' algorithm.",
        "snippets": {
            "Python (PyJWT)": """jwt.decode(token, key, algorithms=["HS256"]) # Enforce algo""",
            "Node.js": """jwt.verify(token, secret, { algorithms: ['RS256'] });"""
        }
    },
    "Exposed Sensitive Path": {
        "advice": "Debug endpoints or admin panels should not be accessible on production URLs. Restrict access by IP or disable them.",
        "snippets": {
            "Python (Django)": """if not settings.DEBUG:
    # Remove admin paths
    urlpatterns = [p for p in urlpatterns if 'admin/' not in str(p.pattern)]""",
            "Nginx": """location /admin {
    allow 192.168.1.5; # Internal IP only
    deny all;
}"""
        }
    }
}

def get_remediation(vulnerability_name):
    """Finds the best advice based on the vulnerability name."""
    for key, info in REMEDIATION_GUIDE.items():
        if key.lower() in vulnerability_name.lower():
            return info
    return None