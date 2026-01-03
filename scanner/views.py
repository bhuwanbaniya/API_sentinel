from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from .forms import APIScanForm
from .models import ScanReport
from .scan_engine import start_scan, fetch_swagger_from_url
from collections import Counter
from urllib.parse import urlparse
import yaml

# ==============================================================================
# VIEW 1: The Main Dashboard
# ==============================================================================
# In scanner/views.py

def dashboard(request):
    # Get all reports, most recent first
    all_reports = ScanReport.objects.all().order_by('-scan_date')
    
    total_vulnerabilities = 0
    total_endpoints = 0
    severity_counts = Counter()
    critical_findings = []

    for report in all_reports:
        if report.status == 'Success' and report.result_json and 'vulnerabilities' in report.result_json:
            vulnerabilities = report.result_json.get('vulnerabilities', [])
            total_vulnerabilities += len(vulnerabilities)

            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] += 1
                
                # --- THIS IS THE FIX for Critical Findings ---
                if severity in ['High', 'Critical']:
                    finding_copy = vuln.copy()
                    # A better way to get the path
                    path_info = ""
                    desc = finding_copy.get('description', '')
                    if 'endpoint' in desc:
                        try: path_info = desc.split(' ')[1]
                        except IndexError: path_info = "N/A"
                    finding_copy['path'] = path_info
                    critical_findings.append(finding_copy)
        
        # This logic for endpoints is fine
        if report.result_json and 'endpoints' in report.result_json:
            total_endpoints = max(total_endpoints, len(report.result_json.get('endpoints', [])))

    # --- THIS IS THE FIX for Risk Score ---
    raw_score = (severity_counts.get('High', 0) * 10) + \
                (severity_counts.get('Medium', 0) * 5) + \
                (severity_counts.get('Low', 0) * 1)
    risk_score = min(10.0, raw_score / 5.0) # Scaled a bit for better visuals

    # --- THIS IS THE FIX for Overall Risk ---
    overall_risk = "LOW"
    if severity_counts.get('High', 0) > 0 or severity_counts.get('Critical', 0) > 0:
        overall_risk = "HIGH"
    elif severity_counts.get('Medium', 0) > 0:
        overall_risk = "MEDIUM"

    # Sort and prepare chart data (this is fine)
    critical_findings.sort(key=lambda x: ['Low', 'Medium', 'High', 'Critical'].index(x.get('severity', 'Low')), reverse=True)
    chart_data = {'labels': list(severity_counts.keys()), 'data': list(severity_counts.values())}

    # Create the final context dictionary
    context = {
        'reports': all_reports[:5], # Show 5 most recent reports
        'total_vulnerabilities': total_vulnerabilities,
        'total_endpoints': total_endpoints,
        'risk_score': f"{risk_score:.1f}",
        'overall_risk': overall_risk,
        'critical_findings': critical_findings[:5], # Show 5 most critical findings
        'chart_data': chart_data,
    }
    
    return render(request, 'scanner/dashboard.html', context)
# ==============================================================================
# VIEW 2: The "New Scan" Page
# ==============================================================================
def scan_view(request):
    form = APIScanForm()
    latest_report = None
    chart_data = {}

    if request.method == 'POST':
        form = APIScanForm(request.POST, request.FILES)
        if form.is_valid():
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
                base_url_for_scan = target_url_from_form # User MUST provide the base URL in the URL field
                scan_target_display = f"File: {api_file.name} on Host: {base_url_for_scan}"
            elif target_url_from_form:
                spec_content = fetch_swagger_from_url(target_url_from_form)
                scan_target_display = target_url_from_form
                if spec_content:
                    parsed_url = urlparse(target_url_from_form)
                    base_url_for_scan = f"{parsed_url.scheme}://{parsed_url.netloc}"

            if spec_content and base_url_for_scan:
                results = start_scan(spec_content, base_url_for_scan, auth_headers)
                new_report = ScanReport.objects.create(
                    target_url=scan_target_display,
                    scan_date=timezone.now(),
                    status=results.get("status", "Failed"),
                    result_json=results
                )
                messages.success(request, f"Scan completed for '{scan_target_display}'.")
                # We will set the new report as the 'latest_report' to display it
                latest_report = new_report
            else:
                messages.error(request, "Scan failed: Could not get a valid spec or base URL.")
        else:
            messages.error(request, "Invalid input. Please check your form.")
    
    if not latest_report:
        latest_report = ScanReport.objects.order_by('-scan_date').first()

    if latest_report:
        severity_counts = Counter()
        color_map = {'High': 'rgba(217, 83, 79, 0.8)', 'Medium': 'rgba(240, 173, 78, 0.8)', 'Low': 'rgba(91, 192, 222, 0.8)'}
        if latest_report.status == 'Success' and 'vulnerabilities' in latest_report.result_json:
            for vuln in latest_report.result_json['vulnerabilities']:
                severity_counts[vuln.get('severity', 'Unknown')] += 1
        
        chart_data = {
            'labels': list(severity_counts.keys()),
            'data': list(severity_counts.values()),
            'colors': [color_map.get(label, '#808080') for label in severity_counts.keys()]
        }

    context = {
        'form': form,
        'latest_report': latest_report,
        'chart_data': chart_data
    }

    
    # --- THIS IS THE LINE THAT WAS MISSING ---
    return render(request, 'scanner/scan.html', context)
# In scanner/views.py

# ... (keep all your imports and other views) ...

# ==============================================================================
# NEW VIEW 4: The "Report Detail" Page
# ==============================================================================
def report_detail_view(request, report_id):
    # Get the specific report, or show a 404 error if it doesn't exist
    report = get_object_or_404(ScanReport, pk=report_id)
    
    # Calculate chart data for THIS report only
    severity_counts = Counter()
    color_map = {'High': 'rgba(217, 83, 79, 0.8)', 'Medium': 'rgba(240, 173, 78, 0.8)', 'Low': 'rgba(91, 192, 222, 0.8)'}
    
    if report.status == 'Success' and report.result_json and 'vulnerabilities' in report.result_json:
        for vuln in report.result_json['vulnerabilities']:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] += 1
    
    chart_data = {
        'labels': list(severity_counts.keys()),
        'data': list(severity_counts.values()),
        'colors': [color_map.get(label, '#808080') for label in severity_counts.keys()]
    }

    context = {
        'report': report,
        'chart_data': chart_data
    }
    return render(request, 'scanner/report_detail.html', context)
# ==============================================================================
# VIEW 3: The "Scan History" Page
# ==============================================================================
def history_view(request):
    all_reports = ScanReport.objects.all().order_by('-scan_date')
    context = {'all_reports': all_reports}
    return render(request, 'scanner/history.html', context)

    # In scanner/views.py

# ... (keep all your other view functions like dashboard, scan_view, history_view, report_detail_view) ...


# ==============================================================================
# VIEW 5: The "Delete Report" Action
# ==============================================================================
def delete_report_view(request, report_id):
    # Only allow POST requests for safety, to prevent accidental deletion
    if request.method == 'POST':
        # Get the specific report, or show a 404 error if it doesn't exist
        report = get_object_or_404(ScanReport, pk=report_id)
        report_name = report.target_url
        report.delete()
        messages.success(request, f"Scan report for '{report_name}' was successfully deleted.")
    
    # Always redirect back to the history page after the action
    return redirect('scan_history')