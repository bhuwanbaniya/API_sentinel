from django.contrib import admin
from .models import ScanReport, UserProfile

@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ('target_url', 'status', 'scan_date')
    list_filter = ('status', 'scan_date')
    search_fields = ('target_url',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'mfa_enabled', 'webhook_threshold')
    list_filter = ('mfa_enabled', 'webhook_threshold')
    search_fields = ('user__username', 'webhook_url')