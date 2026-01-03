# In api_sentinel/urls.py

## In scanner/urls.py

from django.urls import path
from . import views

urlpatterns = [
    # The main dashboard
    path('', views.dashboard, name='dashboard'), 
    
    # The new scan page
    path('scan/', views.scan_view, name='new_scan'), 
    
    # The full scan history page
    path('history/', views.history_view, name='scan_history'),
    
    # The detail page for a single report
    path('history/<int:report_id>/', views.report_detail_view, name='report_detail'),
    
    # --- THIS IS THE MISSING LINE ---
    path('history/delete/<int:report_id>/', views.delete_report_view, name='delete_report'),
]