from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('scan/', views.scan_view, name='new_scan'),
    path('history/', views.history_view, name='scan_history'),
    # ADD THIS LINE BACK
    path('history/<int:report_id>/', views.report_detail_view, name='report_detail'),
    path('history/delete/<int:report_id>/', views.delete_report_view, name='delete_report'),
    path('history/<int:report_id>/pdf/', views.download_report_pdf, name='download_pdf'),

    # ... existing urls ...
    path('scan/progress/<int:report_id>/', views.scan_progress_view, name='scan_progress'),
    path('api/scan-status/<int:report_id>/', views.scan_status_api, name='scan_status_api'),

]