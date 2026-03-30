from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse, JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from .forms import APIScanForm
from .models import ScanReport, UserProfile
from .scan_engine import start_scan, fetch_swagger_from_url
from .remediation import get_remediation
from collections import Counter
from urllib.parse import urlparse
from fpdf import FPDF
import pyotp
import qrcode
import io
import base64
import yaml
import threading
import sys

# ==============================================================================
# 1. AUTHENTICATION & 2FA VIEWS
# ==============================================================================

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Ensure profile exists
            if not hasattr(user, 'userprofile'):
                UserProfile.objects.create(user=user)
            messages.success(request, "Account created! Please login.")
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'registration/register.html', {'form': form})

def custom_login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            # Check for 2FA
            if hasattr(user, 'userprofile') and user.userprofile.mfa_enabled:
                request.session['pre_2fa_user_id'] = user.id
                return redirect('verify_2fa')
            else:
                login(request, user)
                return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'registration/login.html', {'form': form})

def verify_2fa(request):
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('login')

    if request.method == 'POST':
        try:
            user = UserProfile.objects.get(user_id=user_id).user
            otp_code = request.POST.get('otp_code')
            totp = pyotp.TOTP(user.userprofile.mfa_secret)
            
            if totp.verify(otp_code):
                login(request, user)
                if 'pre_2fa_user_id' in request.session:
                    del request.session['pre_2fa_user_id']
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid 2FA Code.")
        except UserProfile.DoesNotExist:
            messages.error(request, "User profile error.")
            return redirect('login')

    return render(request, 'registration/verify_2fa.html')

@login_required
def enable_2fa(request):
    profile = request.user.userprofile
    
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        totp = pyotp.TOTP(profile.mfa_secret)
        if totp.verify(otp_code):
            profile.mfa_enabled = True
            profile.save()
            messages.success(request, "2FA Enabled Successfully!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid Code. Try again.")

    if not profile.mfa_secret:
        profile.mfa_secret = pyotp.random_base32()
        profile.save()

    otp_uri = pyotp.totp.TOTP(profile.mfa_secret).provisioning_uri(
        name=request.user.email, 
        issuer_name="API Sentinel"
    )
    img = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'registration/enable_2fa.html', {
        'qr_code': qr_code_base64,
        'secret': profile.mfa_secret
    })

# ==============================================================================
# 2. DASHBOARD & SCANNING LOGIC
# ==============================================================================

# Helper for Background Thread
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
            except: pass

        results = start_scan(spec_content, base_url, auth_headers, scan_options, logger=db_logger, report_id=report_id)
        
        report = ScanReport.objects.get(id=report_id)
        if report.status == "Stopped": return

        scan_log = report.result_json.get('scan_log', [])
        results['scan_log'] = scan_log 
        report.result_json = results
        report.status = results.get("status", "Failed")
        report.save()

        # Email Alert
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Fallback to the system's email if the user profile doesn't have an email address
        recipient_email = report.user.email if report.user and report.user.email else getattr(settings, 'EMAIL_HOST_USER', None)
        
        if recipient_email:
            # Generate HTML email content
            vuln_list_html = ""
            for v in vulnerabilities:
                color = "red" if v.get('severity') in ['High', 'Critical'] else "orange" if v.get('severity') == 'Medium' else "blue"
                vuln_list_html += f"<li><strong style='color:{color};'>[{v.get('severity')}]</strong> {v.get('name')}: {v.get('description')}</li>"
            
            if not vulnerabilities:
                vuln_list_html = "<li>No vulnerabilities detected!</li>"
            
            html_message = f"""
            <html>
                <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
                    <h2 style="color: #0d1117;">API Sentinel Scan Report</h2>
                    <p><strong>Target:</strong> {report.target_url}</p>
                    <p><strong>Status:</strong> {report.status}</p>
                    <h3>Vulnerability Summary ({len(vulnerabilities)} found):</h3>
                    <ul>
                        {vuln_list_html}
                    </ul>
                    <hr>
                    <p style="font-size: 0.9em; color: #666;">Log in to your API Sentinel dashboard to view full details and remediation steps.</p>
                </body>
            </html>
            """
            
            subject = f"API Sentinel Report: {report.target_url} - {len(vulnerabilities)} Issues Found"
            message = f"API Sentinel Scan Report for {report.target_url}\nStatus: {report.status}\nVulnerabilities found: {len(vulnerabilities)}"
            
            print(f">>> SENDING HTML ALERT EMAIL TO {report.user.email}...") 
            try:
                from django.core.mail import EmailMultiAlternatives
                msg = EmailMultiAlternatives(subject, message, getattr(settings, 'EMAIL_HOST_USER', 'alert@apisentinel.com'), [recipient_email])
                msg.attach_alternative(html_message, "text/html")
                msg.send(fail_silently=False)
                print(">>> EMAIL SENT SUCCESSFULLY.")
            except Exception as e:
                print(f">>> FAILED TO SEND EMAIL: {e}")
    except Exception as e:
        print(f"Task Error: {e}")
        try:
            r = ScanReport.objects.get(id=report_id)
            r.status = "Failed"
            r.save()
        except: pass

@login_required
def dashboard(request):
    all_reports = ScanReport.objects.filter(user=request.user).order_by('-scan_date')
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
        day_total = sum(len(r.result_json.get('vulnerabilities', [])) for r in all_reports.filter(scan_date__date=target_date) if r.result_json)
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
        'trend_data': {'labels': days_labels, 'data': vulnerability_trend},
        'active_scan': ScanReport.objects.filter(user=request.user, status="Running").first()
    }
    return render(request, 'scanner/dashboard.html', context)

@login_required
def scan_view(request):
    recent_reports = ScanReport.objects.filter(user=request.user).order_by('-scan_date')[:5]
    form = APIScanForm()
    
    if request.method == 'POST':
        form = APIScanForm(request.POST, request.FILES)
        if form.is_valid():
            target_url = form.cleaned_data.get('target_url')
            api_file = form.cleaned_data.get('api_file')
            auth_header = form.cleaned_data.get('auth_header')
            
            scan_options = {
                'bola': form.cleaned_data.get('scan_bola'),
                'auth': form.cleaned_data.get('scan_broken_auth'),
                'injection': form.cleaned_data.get('scan_injection'),
                'ratelimit': form.cleaned_data.get('scan_ratelimit'),
                'jwt': form.cleaned_data.get('scan_jwt'),
                'debug': form.cleaned_data.get('scan_debug'),
            }

            auth_headers = {}
            if auth_header:
                if ':' in auth_header: k, v = auth_header.split(':', 1); auth_headers[k.strip()] = v.strip()
                else: auth_headers['Authorization'] = auth_header
            
            spec_content, scan_target_display, base_url = None, None, None
            if api_file:
                spec_content = api_file.read().decode('utf-8')
                base_url = target_url
                scan_target_display = f"File: {api_file.name}"
            elif target_url:
                spec_content = fetch_swagger_from_url(target_url)
                scan_target_display = target_url
                if spec_content: base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

            if spec_content and base_url:
                new_report = ScanReport.objects.create(
                    user=request.user,
                    target_url=scan_target_display,
                    scan_date=timezone.now(),
                    status="Running",
                    result_json={"scan_log": ["Initializing..."]}
                )
                thread = threading.Thread(target=run_scan_in_background, args=(new_report.id, spec_content, base_url, auth_headers, scan_options))
                thread.start()
                return redirect('scan_progress', report_id=new_report.id)
            else:
                messages.error(request, "Scan failed: Invalid input.")

    return render(request, 'scanner/scan.html', {'form': form, 'recent_reports': recent_reports})

@login_required
def scan_progress_view(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id, user=request.user)
    return render(request, 'scanner/scan_progress.html', {'report': report})

@login_required
def scan_status_api(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id, user=request.user)
    return JsonResponse({'status': report.status, 'log': report.result_json.get('scan_log', [])})

@login_required
def stop_scan_view(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id, user=request.user)
    if report.status == "Running":
        report.status = "Stopped"
        report.save()
    return redirect('dashboard')

@login_required
def history_view(request):
    reports = ScanReport.objects.filter(user=request.user).order_by('-scan_date')
    return render(request, 'scanner/history.html', {'all_reports': reports})

@login_required
def report_detail_view(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id, user=request.user)
    vulns = report.result_json.get('vulnerabilities', [])
    endpoints = report.result_json.get('endpoints', [])
    
    enhanced = []
    for v in vulns:
        v_copy = v.copy()
        rem = get_remediation(v_copy.get('name', ''))
        if rem: v_copy.update(rem)
        enhanced.append(v_copy)

    sev_counts = Counter(str(v.get('severity', 'Low')).title() for v in vulns)
    colors = {"High": "#f85149", "Medium": "#f0ad4e", "Low": "#58a6ff"}
    labels = ["High", "Medium", "Low"]
    
    chart = {'labels': [l for l in labels if sev_counts[l]>0], 'data': [sev_counts[l] for l in labels if sev_counts[l]>0], 'colors': [colors[l] for l in labels if sev_counts[l]>0]}

    return render(request, 'scanner/report_detail.html', {'report': report, 'vulnerabilities': enhanced, 'endpoints': endpoints, 'chart_data': chart})

@login_required
def delete_report_view(request, report_id):
    if request.method == 'POST':
        get_object_or_404(ScanReport, pk=report_id, user=request.user).delete()
    return redirect('scan_history')

@login_required
def download_report_pdf(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id, user=request.user)
    vulns = report.result_json.get('vulnerabilities', [])
    endpoints = report.result_json.get('endpoints', [])

    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(22, 27, 34); pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_font("Arial", "B", 24); pdf.set_text_color(255, 255, 255); pdf.cell(0, 20, "API SENTINEL REPORT", ln=True, align="C")
    
    pdf.set_text_color(0, 0, 0); pdf.ln(10)
    pdf.set_font("Arial", "B", 14); pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 8, f"Target: {report.target_url}", ln=True)
    pdf.cell(0, 8, f"Date: {report.scan_date.strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.cell(0, 8, f"User: {report.user.username if report.user else 'Unknown'}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 14); pdf.cell(0, 10, "2. Findings", ln=True)
    for v in vulns:
        sev = str(v.get('severity', 'Low')).upper()
        pdf.set_font("Arial", "B", 11)
        if sev == "HIGH": pdf.set_text_color(248, 81, 73)
        elif sev == "MEDIUM": pdf.set_text_color(240, 173, 78)
        else: pdf.set_text_color(88, 166, 255)
        pdf.cell(0, 8, f"[{sev}] {v.get('name')}", ln=True)
        pdf.set_text_color(50, 50, 50); pdf.set_font("Arial", "", 10)
        pdf.multi_cell(0, 6, v.get('description')); pdf.ln(4)

    response = HttpResponse(bytes(pdf.output()), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Report_{report_id}.pdf"'
    return response