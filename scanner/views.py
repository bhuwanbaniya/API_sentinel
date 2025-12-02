from django.shortcuts import render, redirect
from .forms import ScanForm
from .models import ScanReport
from .scan_engine import APIScanner  # <--- Importing your new engine

def dashboard(request):
    # 1. Get all previous reports to show in a list
    reports = ScanReport.objects.all().order_by('-scan_date')
    
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            # 2. Save the target URL to the database first
            scan_instance = form.save()
            
            # 3. Run the Scanner Logic
            scanner = APIScanner(scan_instance.target_url)
            results = scanner.run()
            
            # 4. Save the results back to the database
            scan_instance.status = results.get("status", "Failed")
            scan_instance.result_json = results
            scan_instance.save()
            
            # Reload the page to show results
            return redirect('dashboard')
    else:
        form = ScanForm()

    return render(request, 'scanner/home.html', {'form': form, 'reports': reports})