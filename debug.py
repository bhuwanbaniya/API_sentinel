import os
import django
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "api_sentinel.settings")
django.setup()

import datetime, croniter
from django.utils import timezone
from scanner.models import ScanReport

res = ''
for r in ScanReport.objects.filter(is_scheduled=True):
    local_scan_date = timezone.localtime(r.scan_date)
    local_now = timezone.localtime(timezone.now())
    try:
        cron = croniter.croniter(r.cron_expression, local_scan_date)
        next_run = cron.get_next(datetime.datetime)
        should_run = local_now >= next_run
        res += f"ID: {r.id}, Cron: '{r.cron_expression}', Last: {local_scan_date.strftime('%Y-%m-%d %H:%M:%S')}, Next: {next_run.strftime('%Y-%m-%d %H:%M:%S')}, Now: {local_now.strftime('%H:%M:%S')}, Run?: {should_run}\n"
    except Exception as e:
        res += f"ID: {r.id}, Error: {str(e)}\n"

with open('cron_debug.txt', 'w') as f:
    f.write(res)
