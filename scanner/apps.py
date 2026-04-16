from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'

    def ready(self):
        import os
        # We put this in a try/except so migrations don't fail if the table doesn't exist
        try:
            # Check for RUN_MAIN so we don't start the scheduler twice due to Django's auto-reloader
            if os.environ.get('RUN_MAIN') == 'true':
                from . import updater
                scheduler = updater.start_scheduler()
                if scheduler:
                    import atexit
                    atexit.register(lambda: scheduler.shutdown(wait=False))
                print("Successfully hooked apscheduler to Django's ready block.")
        except Exception as e:
            print(f"Scheduler failed to start: {e}")
