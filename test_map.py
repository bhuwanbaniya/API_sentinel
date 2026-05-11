import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api_sentinel.settings')
django.setup()
from django.test import RequestFactory
from django.contrib.auth.models import User
from scanner.views import threat_map_view
user = User.objects.first()
req = RequestFactory().get('/threat-map/')
req.user = user
resp = threat_map_view(req)
html = resp.content.decode('utf-8')
import re
match = re.search(r'<script id="map-data" type="application/json">(.+?)</script>', html, re.DOTALL)
if match:
    print('MAP DATA:', match.group(1))
else:
    print('No map data found in HTML')
