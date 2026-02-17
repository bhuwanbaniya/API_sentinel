# scanner/remediation.py

REMEDIATION_GUIDE = {
    "Broken Authentication": {
        "advice": "The endpoint allows access without a valid token. You must enforce authentication on all private routes.",
        "code_snippet": """# Django REST Framework (views.py)
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes

@api_view(['GET'])
@permission_classes([IsAuthenticated]) # <--- Enforces valid token
def get_private_data(request):
    return Response({"data": "Secret"})
"""
    },
    "BOLA": {
        "advice": "The API checks if the user is logged in, but not if they own the specific data object. Always verify object ownership before returning data.",
        "code_snippet": """# Django (views.py)
def get_order(request, order_id):
    # BAD: order = Order.objects.get(id=order_id)
    
    # GOOD: Filter by the logged-in user
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return Response(OrderSerializer(order).data)
"""
    },
    "SQL Injection": {
        "advice": "Never concatenate strings directly into SQL queries. Use parameterized queries or an ORM like Django's.",
        "code_snippet": """# Django (Safe by default)
# BAD: cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# GOOD: Use the ORM
user = User.objects.filter(username=name).first()
"""
    },
    "Excessive Data Exposure": {
        "advice": "The API is sending too much data (e.g., passwords, emails) to the client. Use Serializers to filter the response.",
        "code_snippet": """# Django REST Framework (serializers.py)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # Only select public fields
        fields = ['id', 'username', 'public_profile'] 
        # Exclude 'password', 'email', 'ssn'
"""
    },
    "Rate Limiting": {
        "advice": "The API allows unlimited requests. Configure throttling to prevent DDoS and brute-force attacks.",
        "code_snippet": """# Django REST Framework (settings.py)
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day'
    }
}
"""
    },
    "Missing Security Headers": {
        "advice": "Responses differ from security best practices. Add middleware to enforce headers.",
        "code_snippet": """# settings.py (using django-csp)
MIDDLEWARE = [
    # ...
    'csp.middleware.CSPMiddleware',
]

CSP_DEFAULT_SRC = ("'self'",)
X_FRAME_OPTIONS = 'DENY'
"""
    },
    "Unsafe HTTP Method": {
        "advice": "Disable dangerous HTTP methods like TRACE, TRACK, or DELETE on endpoints that do not require them.",
        "code_snippet": """# Nginx Configuration
server {
    location /api {
        # Only allow specific methods
        limit_except GET POST { deny all; }
    }
}
"""
    },
    "Mass Assignment": {
        "advice": "Do not bind input data directly to internal objects. Use 'read_only_fields' in serializers.",
        "code_snippet": """# Django REST Framework
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'is_admin']
        # Prevent users from setting this field
        read_only_fields = ['is_admin']
"""
    },
    "Weak JWT": {
        "advice": "Ensure JWTs are signed using strong algorithms (RS256) and secrets. Disable the 'None' algorithm.",
        "code_snippet": """# JWT Configuration
JWT_AUTH = {
    'JWT_ALGORITHM': 'RS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
}
"""
    },
    "Exposed Sensitive Path": {
        "advice": "Debug endpoints or admin panels should not be accessible on production URLs. Restrict access by IP or disable them.",
        "code_snippet": """# urls.py
if not settings.DEBUG:
    # Remove admin paths in production
    urlpatterns = [p for p in urlpatterns if 'admin/' not in str(p.pattern)]
"""
    }
}

def get_remediation(vulnerability_name):
    """Finds the best advice based on the vulnerability name."""
    for key, info in REMEDIATION_GUIDE.items():
        if key.lower() in vulnerability_name.lower():
            return info
    return None