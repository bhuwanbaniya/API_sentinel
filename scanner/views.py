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
from django.urls import reverse
from django.core.paginator import Paginator
from .forms import APIScanForm, UserProfileForm
from .models import ScanReport, UserProfile
from .scan_engine import start_scan, fetch_swagger_from_url
from .sast_engine import start_sast_scan
from .remediation import get_remediation
import tempfile
import subprocess
import shutil
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
import requests
import time
from concurrent.futures import ThreadPoolExecutor

# Global thread pool for user-initiated scans to limit resource usage
user_scan_pool = ThreadPoolExecutor(max_workers=3)

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

@login_required
def profile_settings_view(request):
    profile = request.user.userprofile
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Settings updated successfully!")
            return redirect('settings')
    else:
        form = UserProfileForm(instance=profile)
    return render(request, 'scanner/settings.html', {'form': form})

import json

@login_required
def test_webhook_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            webhook_url = data.get('webhook_url')
            if not webhook_url:
                return JsonResponse({"status": "error", "message": "No URL provided."})
            
            payload = {
                "text": "API Sentinel: Webhook Test Successful ✅",
                "content": "🛡️ **API Sentinel Test**\nIf you are seeing this message, your webhook integration is configured correctly! ✅",
                "embeds": [
                    {
                        "title": "🛡️ API Sentinel Test",
                        "description": "If you are seeing this message, your webhook integration is configured correctly! ✅",
                        "color": 5763719,
                        "footer": {"text": "API Sentinel Auto-Scanner"}
                    }
                ],
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🛡️ API Sentinel Test"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "If you are seeing this message, your webhook integration is configured correctly! ✅"
                        }
                    }
                ]
            }
            
            for attempt in range(2):
                try:
                    resp = requests.post(webhook_url, json=payload, timeout=5)
                    if resp.status_code in [200, 204]:
                        return JsonResponse({"status": "success"})
                    else:
                        if attempt == 1:
                            return JsonResponse({"status": "error", "message": f"Server responded with status {resp.status_code}"})
                        time.sleep(1)
                except Exception as request_error:
                    if attempt == 1:
                        return JsonResponse({"status": "error", "message": str(request_error)})
                    time.sleep(1)
                    
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})
            
    return JsonResponse({"status": "error", "message": "Invalid request method."})

# ==============================================================================
# 2. DASHBOARD & SCANNING LOGIC
# ==============================================================================

# Helper for Background Thread
def run_scan_in_background(report_id, spec_content, base_url, auth_headers, scan_options, is_sast=False, git_url=None):
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

        if is_sast and git_url:
            with tempfile.TemporaryDirectory() as temp_dir:
                db_logger(f"[*] Cloning repository {git_url} into secure temporary directory...")
                try:
                    subprocess.run(["git", "clone", git_url, temp_dir], check=True, capture_output=True, text=True)
                    db_logger(f"[+] Repository cloned successfully.")
                except subprocess.CalledProcessError as e:
                    db_logger(f"[-] Failed to clone repository: {e.stderr}")
                    report = ScanReport.objects.get(id=report_id)
                    report.status = "Failed"
                    report.save()
                    return

                results = start_sast_scan(temp_dir, scan_options, logger=db_logger, report_id=report_id)
                db_logger("[*] Cleaning up temporary directory...")
        else:
            results = start_scan(spec_content, base_url, auth_headers, scan_options, logger=db_logger, report_id=report_id)
        
        report = ScanReport.objects.get(id=report_id)
        if report.status == "Stopped": return

        scan_log = report.result_json.get('scan_log', [])
        results['scan_log'] = scan_log 
        report.result_json = results
        report.status = results.get("status", "Failed")
        report.save()

        vulnerabilities = results.get('vulnerabilities', [])
        
        # Computed Diff Analysis
        previous_report = ScanReport.objects.filter(
            user=report.user, 
            target_url=report.target_url, 
            status='Success'
        ).exclude(id=report_id).order_by('-scan_date').first()
        
        trend_summary = ""
        trend_html = ""
        new_vulns_count, fixed_vulns_count = 0, 0
        if previous_report and previous_report.result_json:
            prev_vulns = {v.get('name') for v in previous_report.result_json.get('vulnerabilities', [])}
            curr_vulns = {v.get('name') for v in vulnerabilities}
            new_vulns_count = len(curr_vulns - prev_vulns)
            fixed_vulns_count = len(prev_vulns - curr_vulns)
            report.result_json['trend'] = {'new': new_vulns_count, 'fixed': fixed_vulns_count}
            report.save()
            trend_summary = f"📈 **Trend Analysis:** {new_vulns_count} New Issues | {fixed_vulns_count} Fixed Issues"
            trend_html = f"<h3>Trend Analysis</h3><p>🔴 {new_vulns_count} New Issues<br>🟢 {fixed_vulns_count} Fixed Issues</p>"

        # Webhook Alert
        if report.user and hasattr(report.user, 'userprofile') and report.user.userprofile.webhook_url:
            threshold = report.user.userprofile.webhook_threshold

            
            highest_severity_val = 0
            for v in vulnerabilities:
                sev = str(v.get('severity', 'low')).lower()
                if sev == 'critical': highest_severity_val = max(highest_severity_val, 3)
                elif sev == 'high': highest_severity_val = max(highest_severity_val, 2)
                elif sev == 'medium': highest_severity_val = max(highest_severity_val, 1)

            should_send = True
            if threshold == 'medium' and highest_severity_val < 1:
                should_send = False
            elif threshold == 'high' and highest_severity_val < 2:
                should_send = False
                
            if should_send:
                print(f">>> SENDING WEBHOOK ALERT TO {report.user.userprofile.webhook_url}...")
                
                # Colors based on severity
                color_code = 5814783 # Blue for low
                if highest_severity_val >= 3:
                    color_code = 16273737 # Red
                elif highest_severity_val == 2:
                    color_code = 16273737 # Red
                elif highest_severity_val == 1:
                    color_code = 15773006 # Orange
                    
                vuln_text = "\\n".join([f"• **{v.get('severity', 'Low')}** - {v.get('name')}" for v in vulnerabilities[:10]])
                if len(vulnerabilities) > 10:
                    vuln_text += f"\\n...and {len(vulnerabilities) - 10} more"
                if not vuln_text:
                    vuln_text = "No vulnerabilities detected! ✅"
                    
                if trend_summary:
                    vuln_text += f"\\n\\n{trend_summary}"

                webhook_payload = {
                    "text": f"API Sentinel Scan Completed for {report.target_url}",
                    "content": f"🛡️ **API Sentinel Scan Report**\n**Target:** {report.target_url}\n**Status:** {report.status}\n**Vulnerabilities Found:** {len(vulnerabilities)}",
                    "embeds": [
                        {
                            "title": "🛡️ API Sentinel Scan Report",
                            "description": f"**Target:** {report.target_url}\n**Status:** {report.status}\n**Vulnerabilities Found:** {len(vulnerabilities)}",
                            "color": color_code,
                            "fields": [
                                {
                                    "name": "Top Findings",
                                    "value": vuln_text
                                }
                            ],
                            "footer": {"text": "API Sentinel Auto-Scanner"}
                        }
                    ],
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": "🛡️ API Sentinel Scan Report"}
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Target:* {report.target_url}\n*Status:* {report.status}\n*Vulnerabilities Found:* {len(vulnerabilities)}"}
                        },
                        {"type": "divider"},
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Top Findings:*\n{vuln_text}"}
                        }
                    ]
                }
                
                max_retries = 2
                for attempt in range(max_retries):
                    try:
                        resp = requests.post(report.user.userprofile.webhook_url, json=webhook_payload, timeout=5)
                        if resp.status_code in [200, 204]:
                            print(">>> WEBHOOK SENT SUCCESSFULLY.")
                            break
                        else:
                            print(f">>> WEBHOOK RETURNED NON-SUCCESS CODE: {resp.status_code}")
                            time.sleep(2)
                    except Exception as e:
                        print(f">>> FAILED TO SEND WEBHOOK (Attempt {attempt+1}/{max_retries}): {e}")
                        time.sleep(2)

        # Email Alert
        
        # We only send an email if the user has explicitly provided an email address
        recipient_email = report.user.email if report.user and report.user.email else None
        
        if recipient_email:
            # Generate HTML email content
            vuln_list_html = ""
            for v in vulnerabilities:
                color = "red" if v.get('severity') in ['High', 'Critical'] else "orange" if v.get('severity') == 'Medium' else "blue"
                vuln_list_html += f"<li><strong style='color:{color};'>[{v.get('severity')}]</strong> {v.get('name')}: {v.get('description')}</li>"
            
            if not vulnerabilities:
                vuln_list_html = "<li>No vulnerabilities detected!</li>"
            
            vuln_list_html += trend_html
            
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
                    vuln['report_id'] = report.id
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
            
            git_url = form.cleaned_data.get('git_url')
            
            scan_options = {
                'bola': form.cleaned_data.get('scan_bola'),
                'auth': form.cleaned_data.get('scan_broken_auth'),
                'injection': form.cleaned_data.get('scan_injection'),
                'ratelimit': form.cleaned_data.get('scan_ratelimit'),
                'jwt': form.cleaned_data.get('scan_jwt'),
                'debug': form.cleaned_data.get('scan_debug'),
                'sast_shadow_api': form.cleaned_data.get('scan_sast_shadow_api'),
                'sast_secrets': form.cleaned_data.get('scan_sast_secrets'),
                'sast_sqli': form.cleaned_data.get('scan_sast_sqli'),
                'sast_cors': form.cleaned_data.get('scan_sast_cors'),
                'sast_ratelimit': form.cleaned_data.get('scan_sast_ratelimit'),
                
                # Automated Auth Crawler Fields
                'auth_login_url': form.cleaned_data.get('auth_login_url'),
                'auth_type': form.cleaned_data.get('auth_type'),
                'admin_username': form.cleaned_data.get('admin_username'),
                'admin_password': form.cleaned_data.get('admin_password'),
                'user_username': form.cleaned_data.get('user_username'),
                'user_password': form.cleaned_data.get('user_password'),
            }

            auth_headers = {}
            if auth_header:
                if ':' in auth_header: k, v = auth_header.split(':', 1); auth_headers[k.strip()] = v.strip()
                else: auth_headers['Authorization'] = auth_header
            
            # --- HANDLE SAST SCAN ---
            if git_url:
                new_report = ScanReport.objects.create(
                    user=request.user,
                    target_url=f"SAST: {git_url}",
                    scan_date=timezone.now(),
                    status="Running",
                    result_json={"scan_log": ["Initializing SAST engine..."]}
                )
                user_scan_pool.submit(run_scan_in_background, new_report.id, None, None, auth_headers, scan_options, is_sast=True, git_url=git_url)
                return redirect('scan_progress', report_id=new_report.id)

            # --- HANDLE DAST SCAN ---
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
                    result_json={"scan_log": ["Initializing DAST engine..."]}
                )
                user_scan_pool.submit(run_scan_in_background, new_report.id, spec_content, base_url, auth_headers, scan_options, is_sast=False, git_url=None)
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
def toggle_schedule_api(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id, user=request.user)
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            cron_expr = data.get('cron', '').strip()
        except (ValueError, TypeError, json.JSONDecodeError):
            return JsonResponse({'status': 'error', 'message': 'Invalid parameters'}, status=400)
            
        # Basic validation can be done here by checking if it matches standard cron format (5 parts)
        # Empty string turns off the schedule
        if cron_expr and len(cron_expr.split()) != 5 and cron_expr != 'off':
             return JsonResponse({'status': 'error', 'message': 'Invalid cron expression format. Expected 5 parts (e.g. * * * * *)'}, status=400)

        report.cron_expression = cron_expr
        report.is_scheduled = bool(cron_expr and cron_expr != 'off')
        report.save()
        return JsonResponse({'status': 'success', 'is_scheduled': report.is_scheduled, 'cron': report.cron_expression})
    return JsonResponse({'status': 'error', 'message': 'Invalid Request'}, status=400)

@login_required
def history_view(request):
    query = request.GET.get('q', '')
    reports_qs = ScanReport.objects.filter(user=request.user).order_by('-scan_date')
    
    if query:
        reports_qs = reports_qs.filter(target_url__icontains=query)
        
    paginator = Paginator(reports_qs, 10) # Show 10 reports per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'scanner/history.html', {'page_obj': page_obj, 'query': query})

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
def bulk_delete_reports_view(request):
    if request.method == 'POST':
        # Get list of report IDs from the form submission
        report_ids = request.POST.getlist('report_ids')
        if report_ids:
            # Delete those that belong to the user
            ScanReport.objects.filter(id__in=report_ids, user=request.user).delete()
            messages.success(request, f"Successfully deleted {len(report_ids)} reports.")
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
    pdf.cell(0, 8, f"Total Findings: {len(vulns)}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 14); pdf.cell(0, 10, "2. Findings Detail", ln=True)
    for v in vulns:
        sev = str(v.get('severity', 'Low')).upper()
        pdf.set_font("Arial", "B", 11)
        if sev == "CRITICAL" or sev == "HIGH": pdf.set_text_color(248, 81, 73)
        elif sev == "MEDIUM": pdf.set_text_color(240, 173, 78)
        else: pdf.set_text_color(88, 166, 255)
        
        cvss_text = f" (CVSS: {v.get('cvss')})" if v.get('cvss') else ""
        pdf.cell(0, 8, f"[{sev}] {v.get('name')}{cvss_text}", ln=True)
        
        pdf.set_text_color(50, 50, 50); pdf.set_font("Arial", "I", 9)
        if v.get('owasp'):
            pdf.cell(0, 6, f"OWASP Category: {v.get('owasp')}", ln=True)
            
        pdf.set_font("Arial", "", 10)
        pdf.multi_cell(0, 6, v.get('description'))
        pdf.ln(4)

    response = HttpResponse(pdf.output(dest='S').encode('latin-1'), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Report_{report_id}.pdf"'
    return response

@login_required
def download_sarif(request, report_id):
    report = get_object_or_404(ScanReport, id=report_id, user=request.user)
    try:
        report_data = json.loads(report.result_json) if isinstance(report.result_json, str) else report.result_json
    except:
        report_data = {"vulnerabilities": []}

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "API Sentinel Enterprise",
                    "informationUri": "https://github.com/",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    rules_dict = {}
    for vuln in report_data.get("vulnerabilities", []):
        rule_id = vuln.get("owasp", "API-00").split(" ")[0].replace(":", "-")
        if rule_id not in rules_dict:
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": vuln.get("name"),
                "shortDescription": {"text": vuln.get("name")}
            })
            rules_dict[rule_id] = True

        severity = "warning"
        if vuln.get("severity") in ["High", "Critical"]: severity = "error"
        elif vuln.get("severity") == "Low": severity = "note"

        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": severity,
            "message": {"text": vuln.get("description", "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.target_url or "Target"}}}]
        })

    response = HttpResponse(json.dumps(sarif, indent=2), content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="API_Sentinel_SARIF_{report.id}.sarif"'
    return response

import socket
from django.core.cache import cache

@login_required
def threat_map_view(request):
    reports = ScanReport.objects.filter(user=request.user, status='Success').order_by('-scan_date')
    
    targets = {}
    for r in reports:
        if not r.result_json: continue
        
        target = r.target_url
        if target.startswith('File:') or target.startswith('SAST:'): continue
        
        # Parse domain to IP
        domain = urlparse(target).netloc.split(':')[0]
        if not domain: continue
        
        if domain not in targets:
            targets[domain] = {
                'url': target,
                'ip': '',
                'lat': None,
                'lon': None,
                'vuln_count': 0,
                'max_severity': 'Low'
            }
            
        vulns = r.result_json.get('vulnerabilities', [])
        if len(vulns) > targets[domain]['vuln_count']:
            targets[domain]['vuln_count'] = len(vulns)
            
            # Determine highest severity
            severity_val = 0
            for v in vulns:
                s = str(v.get('severity', 'low')).lower()
                if s == 'critical': val = 3
                elif s == 'high': val = 2
                elif s == 'medium': val = 1
                else: val = 0
                severity_val = max(severity_val, val)
                
            if severity_val == 3: targets[domain]['max_severity'] = 'Critical'
            elif severity_val == 2: targets[domain]['max_severity'] = 'High'
            elif severity_val == 1: targets[domain]['max_severity'] = 'Medium'
            else: targets[domain]['max_severity'] = 'Low'

    # Resolve IPs and Geo Location
    map_data = []
    for domain, data in targets.items():
        ip = cache.get(f"ip_{domain}")
        if not ip:
            try:
                ip = socket.gethostbyname(domain)
                cache.set(f"ip_{domain}", ip, 86400) # Cache for 24h
            except socket.gaierror:
                continue
                
        data['ip'] = ip
        
        geo = cache.get(f"geo_{ip}")
        if not geo:
            try:
                # Use a free GeoIP API
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
                if resp.get('status') == 'success':
                    geo = {'lat': resp.get('lat'), 'lon': resp.get('lon')}
                    cache.set(f"geo_{ip}", geo, 86400 * 30) # Cache 30 days
            except Exception:
                pass
                
        if geo:
            import random
            # Add a tiny random jitter (approx 10-20km) so targets on the same CDN (like Cloudflare) don't perfectly overlap
            jitter_lat = random.uniform(-0.1, 0.1)
            jitter_lon = random.uniform(-0.1, 0.1)
            
            data['lat'] = geo['lat'] + jitter_lat
            data['lon'] = geo['lon'] + jitter_lon
            map_data.append(data)

    return render(request, 'scanner/threat_map.html', {'map_data_json': map_data})

@login_required
def topology_view(request):
    reports = ScanReport.objects.filter(user=request.user, status='Success').order_by('-scan_date')
    
    unique_targets = []
    seen = set()
    for r in reports:
        if r.target_url not in seen:
            seen.add(r.target_url)
            unique_targets.append({'id': r.id, 'url': r.target_url})
            
    selected_report_id = request.GET.get('report_id')
    selected_report = None
    
    if selected_report_id:
        selected_report = reports.filter(id=selected_report_id).first()
    elif reports.exists():
        selected_report = reports.first()
        
    nodes = []
    edges = []
    
    if selected_report:
        try:
            res_json = selected_report.result_json
            if isinstance(res_json, str):
                res_json = json.loads(res_json)
                
            endpoints = res_json.get('endpoints', [])
            vulns = res_json.get('vulnerabilities', [])
            
            for v in vulns:
                desc = v.get('description', '')
                if 'Endpoint ' in desc:
                    parts = desc.split('Endpoint ')
                    if len(parts) > 1:
                        path_part = parts[1].split(' ')[0]
                        if path_part.startswith('/'):
                            endpoints.append(path_part)
                        elif '/' in path_part:
                            endpoints.append('/' + path_part.split('/', 1)[1])
                            
            from urllib.parse import urlparse
            domain = urlparse(selected_report.target_url).netloc or selected_report.target_url
            
            node_map = {}
            node_id_counter = 1
            
            node_map['/'] = 0
            nodes.append({'id': 0, 'label': domain, 'group': 'root', 'title': 'Target Domain'})
            
            endpoints = list(set(endpoints))
            
            for ep in endpoints:
                is_unreachable = "(Unreachable)" in ep
                ep = ep.replace("(Unreachable)", "").strip()
                if " " in ep:
                    ep = ep.split(" ")[1]
                    
                if not ep.startswith('/'): ep = '/' + ep
                parts = [p for p in ep.split('/') if p]
                
                current_path = ''
                parent_id = 0
                
                for part in parts:
                    current_path += '/' + part
                    if current_path not in node_map:
                        node_map[current_path] = node_id_counter
                        is_vuln = False
                        vuln_details = []
                        for v in vulns:
                            if current_path in v.get('description', '') or current_path in v.get('name', ''):
                                is_vuln = True
                                vuln_details.append(f"[{v.get('severity')}] {v.get('name')}")
                        
                        if is_vuln:
                            group = 'vulnerable'
                        elif is_unreachable:
                            group = 'unreachable'
                        else:
                            group = 'safe'
                            
                        title = f"Path: {current_path}"
                        if is_vuln: title += "\n" + "\n".join(vuln_details)
                        if is_unreachable: title += "\n[Blocked by WAF / Unreachable]"
                        
                        nodes.append({'id': node_id_counter, 'label': f"/{part}", 'group': group, 'title': title})
                        edges.append({'from': parent_id, 'to': node_id_counter})
                        node_id_counter += 1
                        
                    parent_id = node_map[current_path]
                    
        except Exception as e:
            print("Error parsing topology:", e)

    context = {
        'unique_targets': unique_targets,
        'selected_report_id': int(selected_report.id) if selected_report else None,
        'nodes_json': json.dumps(nodes),
        'edges_json': json.dumps(edges),
    }
    return render(request, 'scanner/topology.html', context)

from django.views.decorators.csrf import csrf_exempt
from .models import OASTEvent
import json

@csrf_exempt
def oast_catch_view(request, token):
    """
    Webhook listener for Out-Of-Band (OAST) security testing.
    Catches SSRF and Blind Command Injections.
    """
    # Get IP Address
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    # Get headers
    headers = {k: v for k, v in request.META.items() if k.startswith('HTTP_')}
    
    # Get payload if any
    payload = request.body.decode('utf-8', errors='ignore')

    # Save to database
    OASTEvent.objects.create(
        token=token,
        source_ip=ip,
        headers=json.dumps(headers),
        payload=payload
    )

    # Return a generic 200 OK so the attacker doesn't know what hit them
    return HttpResponse("OK", status=200)