from django.db import models
from django.utils import timezone # Import timezone

class ScanReport(models.Model):
    target_url = models.CharField(max_length=255)
    # Remove all auto_now/auto_now_add. We will set the date manually.
    scan_date = models.DateTimeField() 
    status = models.CharField(max_length=50)
    result_json = models.JSONField(default=dict)

    def __str__(self):
        return f"Scan for {self.target_url} on {self.scan_date}"

    class Meta:
        # Order the reports by the most recent first by default
        ordering = ['-scan_date']