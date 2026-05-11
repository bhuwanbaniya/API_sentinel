import os, django, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api_sentinel.settings')
django.setup()
from scanner.models import ScanReport

report = ScanReport.objects.filter(target_url__icontains='mysecondteacher').order_by('-scan_date').first()
if report:
    print('Found report!')
    print('Target:', report.target_url)
    print('Status:', report.status)
    try:
        vulns = json.loads(report.vulnerabilities)
        for v in vulns:
            print(f"- {v.get('severity', 'Unknown')}: {v.get('name', 'Unknown')} ({v.get('description', '')})")
    except Exception as e:
        print('Error parsing vulnerabilities:', e)
else:
    print('No report found for mysecondteacher')
