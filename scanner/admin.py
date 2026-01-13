from django.contrib import admin
from .models import ScanReport

@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ('target_url', 'status', 'scan_date')
    list_filter = ('status', 'scan_date')
    search_fields = ('target_url',)