from django.db import models

class ScanReport(models.Model):
    # This is the field your form is looking for
    target_url = models.URLField(help_text="The URL of the API or Swagger file")
    
    scan_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default="Pending")
    result_json = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"Scan {self.id} - {self.target_url}"