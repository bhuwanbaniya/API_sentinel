# In api_sentinel/urls.py

# In scanner/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
]