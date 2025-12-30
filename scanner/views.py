from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from .forms import APIScanForm
from .models import ScanReport
from .scan_engine import start_scan, fetch_swagger_from_url
from urllib.parse import urlparse
import yaml

def dashboard(request):
    form = APIScanForm(request.POST or None, request.FILES or None)
    
    if request.method == 'POST' and form.is_valid():
        target_url_from_form = form.cleaned_data.get('target_url')
        api_file = form.cleaned_data.get('api_file')
        auth_header_string = form.cleaned_data.get('auth_header')

        auth_headers = {}
        if auth_header_string:
            if ':' in auth_header_string:
                key, value = auth_header_string.split(':', 1)
                auth_headers[key.strip()] = value.strip()
            else:
                auth_headers['Authorization'] = auth_header_string
        
        spec_content, scan_target_display, base_url_for_scan = None, None, None

        if api_file:
            spec_content = api_file.read().decode('utf-8')
            scan_target_display = f"File: {api_file.name}"
            base_url_for_scan = target_url_from_form
        elif target_url_from_form:
            spec_content = fetch_swagger_from_url(target_url_from_form)
            scan_target_display = target_url_from_form
            if spec_content:
                parsed_url = urlparse(target_url_from_form)
                base_url_for_scan = f"{parsed_url.scheme}://{parsed_url.netloc}"

        if spec_content and base_url_for_scan:
            results = start_scan(spec_content, base_url_for_scan, auth_headers)
            ScanReport.objects.create(target_url=scan_target_display, scan_date=timezone.now(), status=results.get("status", "Failed"), result_json=results)
            messages.success(request, f"Scan for '{scan_target_display}' completed successfully.")
        else:
            error_message = f"Scan failed: Could not retrieve a valid API specification from the provided input."
            ScanReport.objects.create(target_url=scan_target_display or "Invalid Target", scan_date=timezone.now(), status="Failed", result_json={"error": error_message})
            messages.error(request, error_message)

        return redirect('dashboard')

    reports = ScanReport.objects.all()
    context = {'form': form, 'reports': reports}
    return render(request, 'scanner/home.html', context)