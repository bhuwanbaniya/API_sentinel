from django.urls import path
from . import views

urlpatterns = [
    # We changed 'views.home' to 'views.dashboard' to match your views.py
    path('', views.dashboard, name='dashboard'), 
]