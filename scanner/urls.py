from django.urls import path
from . import views

urlpatterns = [
    # Main Views
    path('', views.dashboard, name='dashboard'),
    path('scan/', views.scan_view, name='new_scan'),
    path('history/', views.history_view, name='scan_history'),
    
    # Report Details & Actions
    path('history/<int:report_id>/', views.report_detail_view, name='report_detail'),
    path('history/delete/<int:report_id>/', views.delete_report_view, name='delete_report'),
    path('history/<int:report_id>/pdf/', views.download_report_pdf, name='download_pdf'),
    
    # Live Progress, API, and Control
    path('scan/progress/<int:report_id>/', views.scan_progress_view, name='scan_progress'),
    path('api/scan-status/<int:report_id>/', views.scan_status_api, name='scan_status_api'),
    
    # --- NEW STOP PATH ---
    path('scan/stop/<int:report_id>/', views.stop_scan_view, name='stop_scan'),
]