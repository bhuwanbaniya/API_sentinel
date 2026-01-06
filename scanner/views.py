from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse
from .forms import APIScanForm
from .models import ScanReport
from .scan_engine import start_scan, fetch_swagger_from_url
from collections import Counter
from urllib.parse import urlparse
from fpdf import FPDF # Import the new PDF library
import yaml

# ==============================================================================
# 1. THE MAIN DASHBOARD
# ==============================================================================
def dashboard(request):
    all_reports = ScanReport.objects.all().order_by('-scan_date')
    total_vulnerabilities, total_endpoints = 0, 0
    severity_counts = Counter()
    critical_findings = []

    for report in all_reports:
        if report.status == 'Success' and report.result_json:
            vulns = report.result_json.get('vulnerabilities', [])
            total_vulnerabilities += len(vulns)
            total_endpoints = max(total_endpoints, len(report.result_json.get('endpoints', [])))
            for vuln in vulns:
                sev = str(vuln.get('severity', 'Low')).title()
                severity_counts[sev] += 1
                if sev in ['High', 'Critical']:
                    vuln['target'] = report.target_url
                    critical_findings.append(vuln)

    today = timezone.now().date()
    days_labels, vulnerability_trend = [], []
    for i in range(6, -1, -1):
        target_date = today - timedelta(days=i)
        days_labels.append(target_date.strftime('%b %d'))
        day_total = sum(len(r.result_json.get('vulnerabilities', [])) for r in ScanReport.objects.filter(scan_date__date=target_date) if r.result_json)
        vulnerability_trend.append(day_total)

    score = (severity_counts['High'] * 10) + (severity_counts['Medium'] * 5) + (severity_counts['Low'] * 2)
    risk_score = min(10.0, score / 50.0) if total_vulnerabilities > 0 else 0

    context = {
        'reports': all_reports[:5],
        'total_vulnerabilities': total_vulnerabilities,
        'total_endpoints': total_endpoints,
        'risk_score': f"{risk_score:.1f}",
        'overall_risk': "HIGH" if severity_counts['High'] > 0 else "LOW",
        'critical_findings': critical_findings[:5],
        'chart_data': {'labels': list(severity_counts.keys()), 'data': list(severity_counts.values())},
        'trend_data': {'labels': days_labels, 'data': vulnerability_trend}
    }
    return render(request, 'scanner/dashboard.html', context)

# ==============================================================================
# 2. NEW SCAN PAGE
# ==============================================================================
def scan_view(request):
    form = APIScanForm()
    if request.method == 'POST':
        form = APIScanForm(request.POST, request.FILES)
        if form.is_valid():
            target_url = form.cleaned_data.get('target_url')
            api_file = form.cleaned_data.get('api_file')
            auth_header_string = form.cleaned_data.get('auth_header')
            auth_headers = {}
            if auth_header_string:
                if ':' in auth_header_string:
                    key, value = auth_header_string.split(':', 1)
                    auth_headers[key.strip()] = value.strip()
                else: auth_headers['Authorization'] = auth_header_string
            
            spec_content, scan_target_display, base_url_for_scan = None, None, None
            if api_file:
                spec_content = api_file.read().decode('utf-8')
                base_url_for_scan = target_url
                scan_target_display = f"File: {api_file.name}"
            elif target_url:
                spec_content = fetch_swagger_from_url(target_url)
                scan_target_display = target_url
                if spec_content: base_url_for_scan = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

            if spec_content and base_url_for_scan:
                results = start_scan(spec_content, base_url_for_scan, auth_headers)
                ScanReport.objects.create(target_url=scan_target_display, scan_date=timezone.now(), status=results.get("status", "Failed"), result_json=results)
                messages.success(request, "Scan successful!")
                return redirect('dashboard')
    return render(request, 'scanner/scan.html', {'form': form})

# ==============================================================================
# 3. HISTORY & DETAILS
# ==============================================================================
def history_view(request):
    return render(request, 'scanner/history.html', {'all_reports': ScanReport.objects.all().order_by('-scan_date')})

def report_detail_view(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    vulns = report.result_json.get('vulnerabilities', [])
    severity_counts = Counter(str(v.get('severity', 'Low')).title() for v in vulns)
    
    color_map = {"High": "#f85149", "Medium": "#f0ad4e", "Low": "#58a6ff"}
    labels = ["High", "Medium", "Low"]
    chart_data = {
        'labels': [l for l in labels if severity_counts[l] > 0],
        'data': [severity_counts[l] for l in labels if severity_counts[l] > 0],
        'colors': [color_map[l] for l in labels if severity_counts[l] > 0]
    }
    return render(request, 'scanner/report_detail.html', {'report': report, 'vulnerabilities': vulns, 'endpoints': report.result_json.get('endpoints', []), 'chart_data': chart_data})

def delete_report_view(request, report_id):
    if request.method == 'POST':
        get_object_or_404(ScanReport, pk=report_id).delete()
        messages.success(request, "Report deleted.")
    return redirect('scan_history')

# ==============================================================================
# 4. NEW: DOWNLOAD PDF REPORT (Using fpdf2)
# ==============================================================================
def download_report_pdf(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    vulns = report.result_json.get('vulnerabilities', [])
    endpoints = report.result_json.get('endpoints', [])

    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_fill_color(22, 27, 34) # Dark sidebar color
    pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 24)
    pdf.cell(0, 20, "API SENTINEL REPORT", ln=True, align="C")
    
    # Body Styling
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    
    # Summary Table
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 8, f"Target URL: {report.target_url}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {report.scan_date.strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.cell(0, 8, f"Total Vulnerabilities Found: {len(vulns)}", ln=True)
    pdf.ln(10)

    # Vulnerabilities Section
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "2. Detected Vulnerabilities", ln=True)
    
    for v in vulns:
        # Severity Color
        sev = str(v.get('severity', 'Low')).upper()
        if sev == "HIGH" or sev == "CRITICAL": pdf.set_text_color(248, 81, 73)
        elif sev == "MEDIUM": pdf.set_text_color(240, 173, 78)
        else: pdf.set_text_color(88, 166, 255)
        
        pdf.set_font("Arial", "B", 11)
        pdf.cell(0, 8, f"[{sev}] {v.get('name')}", ln=True)
        
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Arial", "", 10)
        pdf.multi_cell(0, 6, v.get('description'))
        pdf.ln(4)

    # Endpoints Section
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "3. Scanned Endpoints Inventory", ln=True)
    pdf.set_font("Arial", "", 9)
    
    for ep in endpoints:
        line = f"{ep.get('method')} {ep.get('path')}"
        pdf.cell(0, 6, line, border="B", ln=True)

    # Prepare Response
    response = HttpResponse(bytes(pdf.output()), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="API_Sentinel_Report_{report_id}.pdf"'
    return response