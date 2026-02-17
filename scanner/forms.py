from django import forms

class APIScanForm(forms.Form):
    target_url = forms.URLField(
        required=False, 
        label='Enter API/Swagger URL (or Base URL for file upload)',
        widget=forms.URLInput(attrs={'size': '50', 'placeholder': 'http://127.0.0.1:3000/api/swagger.json'})
    )
    api_file = forms.FileField(
        required=False,
        label='Or Upload an OpenAPI/Swagger File'
    )
    auth_header = forms.CharField(
        required=False,
        label='Authorization Header (e.g., "Authorization: Bearer your_token")',
        widget=forms.TextInput(attrs={'size': '50', 'placeholder': 'Authorization: Bearer ey...'})
    )

    # --- CHECKBOXES FOR MODULES ---
    scan_broken_auth = forms.BooleanField(required=False, initial=True, label="Check for Broken Authentication")
    scan_bola = forms.BooleanField(required=False, initial=True, label="Check for BOLA")
    scan_injection = forms.BooleanField(required=False, initial=True, label="Check for Injection (SQLi)")
    scan_ratelimit = forms.BooleanField(required=False, initial=True, label="Check for Rate Limiting")
    
    # --- NEW MODULES ---
    scan_jwt = forms.BooleanField(required=False, initial=True, label="Check for Weak JWT Config")
    scan_debug = forms.BooleanField(required=False, initial=True, label="Check for Exposed Debug/Admin Paths")