from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'

    def ready(self):
        # We put this in a try/except so migrations don't fail if the table doesn't exist
        try:
            from . import updater
            updater.start_scheduler()
            print("Successfully hooked apscheduler to Django's ready block.")
        except Exception as e:
            print(f"Scheduler failed to start: {e}")
