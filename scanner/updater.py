import logging
import threading
import croniter
from urllib.parse import urlparse
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from django_apscheduler.jobstores import DjangoJobStore, register_events
from django.utils import timezone
from scanner.models import ScanReport
from django.contrib.auth.models import User

from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Maximum 2 automated scans running simultaneously to avoid straining system resources
automated_scan_pool = ThreadPoolExecutor(max_workers=2)

def run_automated_scans():
    print(">>> CRON SCHEDULER TICK: " + str(timezone.now()))
    with open('tick_debug.log', 'a') as f: f.write(str(timezone.now()) + '\n')
    try:
        # Import inside the function to avoid circular import issues
        from scanner.scan_engine import fetch_swagger_from_url
        from scanner.views import run_scan_in_background
        
        # Get all distinct scheduled targets (avoid running the same target multiple times for one user if they somehow scheduled the same URL multiple times)
        scheduled_reports = ScanReport.objects.filter(is_scheduled=True)
        
        # We group by user and target_url just in case
        targets_to_run = {}
        for r in scheduled_reports:
            key = (r.user_id, r.target_url)
            if key not in targets_to_run:
                targets_to_run[key] = r
                
        for key, report in targets_to_run.items():
            user = report.user
            target_url = report.target_url
            
            # Find the most recent scan globally for this specific target
            latest_scan = ScanReport.objects.filter(
                user=user, 
                target_url=target_url
            ).order_by('-scan_date').first()
            
            if not report.cron_expression:
                continue
                
            if latest_scan:
                try:
                    import datetime
                    
                    # So user-defined cron expressions align exactly with their computer clock.
                    local_now = timezone.localtime(timezone.now())
                    
                    # Calculate the most recent scheduled run time relative to exactly now
                    cron = croniter.croniter(report.cron_expression, local_now)
                    prev_run_local = cron.get_prev(datetime.datetime)
                    
                    # Check if the exact scheduled run time passed within the last 65 seconds
                    # This prevents "catching up" on missed scans from hours/days ago if the server was offline
                    elapsed_since_scheduled = (local_now.replace(tzinfo=None) - prev_run_local.replace(tzinfo=None)).total_seconds()
                    
                    if elapsed_since_scheduled > 65 or elapsed_since_scheduled < 0:
                        continue
                        
                    # Also ensure we don't accidentally run multiple times for a schedule (debounce)
                    if latest_scan:
                        elapsed_since_last_scan = (timezone.now() - latest_scan.scan_date).total_seconds()
                        if elapsed_since_last_scan < 60:
                            continue
                except Exception as e:
                    print(f"Invalid cron expression '{report.cron_expression}' for {target_url}: {e}")
                    continue
            
            print(f"Starting automated scan for user {user.username} on {target_url}")
            
            spec_content = fetch_swagger_from_url(target_url)
            if spec_content:
                base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
                
                # Create a new scan report (note `is_scheduled=False` by default)
                new_report = ScanReport.objects.create(
                    user=user,
                    target_url=target_url,
                    scan_date=timezone.now(),
                    status="Running",
                    result_json={"scan_log": ["Scheduled Automated Scan Initializing..."]}
                )
                
                # Default options for the automated background scan
                scan_options = {
                    'bola': True, 'auth': True, 'injection': True,
                    'ratelimit': True, 'jwt': True, 'debug': False
                }
                
                # Queue the scan in the background thread pool
                automated_scan_pool.submit(
                    run_scan_in_background, 
                    new_report.id, spec_content, base_url, {}, scan_options
                )
                print(f"Automated scan queued for {target_url} (Report ID: {new_report.id})")
            else:
                print(f"Could not fetch swagger from {target_url}. Scan skipped.")
                # Create a failed record so the cron timeline advances and stops retrying every minute
                ScanReport.objects.create(
                    user=user,
                    target_url=target_url,
                    scan_date=timezone.now(),
                    status="Failed",
                    is_scheduled=False,
                    result_json={"scan_log": ["Automated scheduled scan failed: Target machine could not be reached."]}
                )
                    
    except Exception as e:
        print(f"Error in automated scans: {e}")
        logger.error("Error in automated scans: %s", e)


def start_scheduler():
    scheduler = BackgroundScheduler()
    # Removed DjangoJobStore to prevent SQLite "database is locked" issues, defaults to MemoryJobStore.

    # Execute automated scans every minute; the internal logic handles if an interval has actually elapsed.
    scheduler.add_job(
        run_automated_scans,
        trigger=CronTrigger.from_crontab("* * * * *"),
        id="automated_api_scan_job",
        max_instances=1,
        replace_existing=True,
    )

    # register_events(scheduler) # <-- COMMENTED OUT to fix "database is locked" errors
    try:
        scheduler.start()
        print("Scheduler started routing automated scans...")
        return scheduler
    except Exception as e:
        print(f"Error starting scheduler: {e}")
        logger.error("Error starting scheduler: %s", e)
