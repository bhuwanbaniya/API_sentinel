from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Auth
    path('accounts/login/', views.custom_login_view, name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('accounts/register/', views.register_view, name='register'),
    path('accounts/enable-2fa/', views.enable_2fa, name='enable_2fa'),
    path('accounts/verify-2fa/', views.verify_2fa, name='verify_2fa'),

    # App
    path('', views.dashboard, name='dashboard'),
    path('settings/', views.profile_settings_view, name='settings'),
    path('api/test-webhook/', views.test_webhook_api, name='test_webhook_api'),
    path('scan/', views.scan_view, name='new_scan'),
    path('history/', views.history_view, name='scan_history'),
    path('history/<int:report_id>/', views.report_detail_view, name='report_detail'),
    path('history/delete/<int:report_id>/', views.delete_report_view, name='delete_report'),
    path('history/bulk-delete/', views.bulk_delete_reports_view, name='bulk_delete_reports'),
    path('history/<int:report_id>/pdf/', views.download_report_pdf, name='download_pdf'),
    path('history/<int:report_id>/sarif/', views.download_sarif, name='download_sarif'),
    path('scan/progress/<int:report_id>/', views.scan_progress_view, name='scan_progress'),
    path('api/scan-status/<int:report_id>/', views.scan_status_api, name='scan_status_api'),
    path('scan/stop/<int:report_id>/', views.stop_scan_view, name='stop_scan'),
    path('history/toggle_schedule/<int:report_id>/', views.toggle_schedule_api, name='toggle_schedule'),
]