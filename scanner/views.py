from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .remediation import get_remediation
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse, JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from .forms import APIScanForm
from .models import ScanReport
from .scan_engine import start_scan, fetch_swagger_from_url
from collections import Counter
from urllib.parse import urlparse
from fpdf import FPDF
import yaml
import threading
import sys
import io

# ==============================================================================
# HELPER: Background Scan Task
# ==============================================================================
def run_scan_in_background(report_id, spec_content, base_url, auth_headers, scan_options):
    try:
        def db_logger(msg):
            try:
                r = ScanReport.objects.get(id=report_id)
                current_log = r.result_json.get('scan_log', [])
                current_log.append(msg)
                if not r.result_json: r.result_json = {}
                r.result_json['scan_log'] = current_log
                r.save()
            except Exception: pass

        # --- UPDATE: PASS REPORT_ID HERE ---
        results = start_scan(spec_content, base_url, auth_headers, scan_options, logger=db_logger, report_id=report_id)
        
        report = ScanReport.objects.get(id=report_id)
        
        # --- UPDATE: CHECK STOPPED STATUS ---
        if report.status == "Stopped":
            return # Don't overwrite stopped status

        scan_log = report.result_json.get('scan_log', [])
        results['scan_log'] = scan_log 
        
        report.result_json = results
        report.status = results.get("status", "Failed")
        report.save()

        # Email Logic
        vulnerabilities = results.get('vulnerabilities', [])
        high_risk_count = sum(1 for v in vulnerabilities if v.get('severity') == 'High')

        if high_risk_count > 0:
            subject = f"ALERT: High Severity Vulnerabilities Detected in {report.target_url}"
            message = f"""
            API Sentinel Alert System
            -------------------------
            Scan Target: {report.target_url}
            Scan Date: {report.scan_date}
            CRITICAL ALERT:
            The scanner detected {high_risk_count} High Severity vulnerabilities.
            Please check the dashboard immediately for details.
            """
            print(">>> SENDING ALERT EMAIL (Check Console)...") 
            try:
                send_mail(subject, message, settings.EMAIL_HOST_USER, ['admin@example.com'], fail_silently=False)
            except Exception as mail_err:
                print(f"Mail Error: {mail_err}")
        
    except Exception as e:
        print(f"Background Task Error: {e}")
        try:
            r = ScanReport.objects.get(id=report_id)
            r.status = "Failed"
            if not r.result_json: r.result_json = {}
            log = r.result_json.get('scan_log', [])
            log.append(f"CRITICAL ERROR: {str(e)}")
            r.result_json['scan_log'] = log
            r.save()
        except: pass

# ==============================================================================
# VIEW 1: Dashboard
# ==============================================================================
def dashboard(request):
    all_reports = ScanReport.objects.all().order_by('-scan_date')
    
    total_vulnerabilities = 0
    total_endpoints = 0
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

    active_scan = ScanReport.objects.filter(status="Running").first()

    context = {
        'reports': all_reports[:5],
        'total_vulnerabilities': total_vulnerabilities,
        'total_endpoints': total_endpoints,
        'risk_score': f"{risk_score:.1f}",
        'overall_risk': "HIGH" if severity_counts['High'] > 0 else "LOW",
        'critical_findings': critical_findings[:5],
        'chart_data': {'labels': list(severity_counts.keys()), 'data': list(severity_counts.values())},
        'trend_data': {'labels': days_labels, 'data': vulnerability_trend},
        'active_scan': active_scan,
    }
    return render(request, 'scanner/dashboard.html', context)

# ==============================================================================
# VIEW 2: New Scan
# ==============================================================================
def scan_view(request):
    recent_reports = ScanReport.objects.all().order_by('-scan_date')[:5]
    form = APIScanForm()
    
    if request.method == 'POST':
        form = APIScanForm(request.POST, request.FILES)
        if form.is_valid():
            target_url_from_form = form.cleaned_data.get('target_url')
            api_file = form.cleaned_data.get('api_file')
            auth_header_string = form.cleaned_data.get('auth_header')

            scan_options = {
                'bola': form.cleaned_data.get('scan_bola'),
                'auth': form.cleaned_data.get('scan_broken_auth'),
                'injection': form.cleaned_data.get('scan_injection'),
                'ratelimit': form.cleaned_data.get('scan_ratelimit'),
                'jwt': form.cleaned_data.get('scan_jwt'),
                'debug': form.cleaned_data.get('scan_debug'),
            }

            auth_headers = {}
            if auth_header_string:
                if ':' in auth_header_string:
                    key, value = auth_header_string.split(':', 1)
                    auth_headers[key.strip()] = value.strip()
                else: auth_headers['Authorization'] = auth_header_string
            
            spec_content, scan_target_display, base_url_for_scan = None, None, None
            if api_file:
                spec_content = api_file.read().decode('utf-8')
                base_url_for_scan = target_url_from_form
                scan_target_display = f"File: {api_file.name}"
            elif target_url_from_form:
                spec_content = fetch_swagger_from_url(target_url_from_form)
                scan_target_display = target_url_from_form
                if spec_content: base_url_for_scan = f"{urlparse(target_url_from_form).scheme}://{urlparse(target_url_from_form).netloc}"

            if spec_content and base_url_for_scan:
                new_report = ScanReport.objects.create(
                    target_url=scan_target_display,
                    scan_date=timezone.now(),
                    status="Running",
                    result_json={"scan_log": ["Initializing scanner..."]}
                )
                
                thread = threading.Thread(
                    target=run_scan_in_background,
                    args=(new_report.id, spec_content, base_url_for_scan, auth_headers, scan_options)
                )
                thread.start()

                return redirect('scan_progress', report_id=new_report.id)
            else:
                messages.error(request, "Scan failed: Spec content or Base URL missing.")

    return render(request, 'scanner/scan.html', {'form': form, 'recent_reports': recent_reports})

# ==============================================================================
# VIEW 3: Progress & Stop
# ==============================================================================
def scan_progress_view(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    return render(request, 'scanner/scan_progress.html', {'report': report})

def scan_status_api(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    return JsonResponse({
        'status': report.status,
        'log': report.result_json.get('scan_log', [])
    })

# --- NEW: STOP SCAN VIEW ---
def stop_scan_view(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    if report.status == "Running":
        report.status = "Stopped"
        report.save()
        messages.warning(request, "Scan stopped by user command.")
    return redirect('dashboard')

# ==============================================================================
# VIEW 4: History & Details
# ==============================================================================
def history_view(request):
    return render(request, 'scanner/history.html', {'all_reports': ScanReport.objects.all().order_by('-scan_date')})

def delete_report_view(request, report_id):
    if request.method == 'POST':
        get_object_or_404(ScanReport, pk=report_id).delete()
        messages.success(request, "Report deleted.")
    return redirect('scan_history')

def report_detail_view(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    vulnerabilities = report.result_json.get('vulnerabilities', [])
    endpoints = report.result_json.get('endpoints', [])
    
    # --- NEW: Attach remediation advice ---
    enhanced_vulnerabilities = []
    for vuln in vulnerabilities:
        v_copy = vuln.copy() # Make a temporary copy so we don't change the DB
        remediation = get_remediation(v_copy.get('name', ''))
        if remediation:
            v_copy['advice'] = remediation['advice']
            v_copy['code'] = remediation['code_snippet']
        enhanced_vulnerabilities.append(v_copy)
    # --------------------------------------

    severity_counts = Counter(str(v.get('severity', 'Low')).title() for v in vulnerabilities)
    
    color_map = {"High": "#f85149", "Medium": "#f0ad4e", "Low": "#58a6ff"}
    labels = ["High", "Medium", "Low"]
    chart_data = {
        'labels': [l for l in labels if severity_counts[l] > 0],
        'data': [severity_counts[l] for l in labels if severity_counts[l] > 0],
        'colors': [color_map[l] for l in labels if severity_counts[l] > 0]
    }
    
    return render(request, 'scanner/report_detail.html', {
        'report': report, 
        'vulnerabilities': enhanced_vulnerabilities, # Pass the ENHANCED list
        'endpoints': endpoints, 
        'chart_data': chart_data
    })

# ==============================================================================
# VIEW 5: PDF Download
# ==============================================================================
def download_report_pdf(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    vulns = report.result_json.get('vulnerabilities', [])
    endpoints = report.result_json.get('endpoints', [])

    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(22, 27, 34)
    pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 24)
    pdf.cell(0, 20, "API SENTINEL REPORT", ln=True, align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 8, f"Target URL: {report.target_url}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {report.scan_date.strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.cell(0, 8, f"Total Vulnerabilities: {len(vulns)}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "2. Detected Vulnerabilities", ln=True)
    
    for v in vulns:
        sev = str(v.get('severity', 'Low')).upper()
        if sev in ["HIGH", "CRITICAL"]: pdf.set_text_color(248, 81, 73)
        elif sev == "MEDIUM": pdf.set_text_color(240, 173, 78)
        else: pdf.set_text_color(88, 166, 255)
        pdf.set_font("Arial", "B", 11)
        pdf.cell(0, 8, f"[{sev}] {v.get('name')}", ln=True)
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Arial", "", 10)
        pdf.multi_cell(0, 6, v.get('description'))
        pdf.ln(4)

    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "3. Scanned Endpoints Inventory", ln=True)
    pdf.set_font("Arial", "", 9)
    for ep in endpoints:
        line = ep if isinstance(ep, str) else f"{ep.get('method')} {ep.get('path')}"
        pdf.cell(0, 6, line, border="B", ln=True)

    response = HttpResponse(bytes(pdf.output()), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="API_Sentinel_Report_{report_id}.pdf"'
    return response