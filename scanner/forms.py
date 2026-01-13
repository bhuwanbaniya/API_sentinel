from django import forms

class APIScanForm(forms.Form):
    target_url = forms.URLField(
        required=False, 
        label='Enter API/Swagger URL',
        widget=forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'http://127.0.0.1:3000/api/swagger.json'})
    )
    api_file = forms.FileField(
        required=False,
        label='Or Upload OpenAPI File'
    )
    auth_header = forms.CharField(
        required=False,
        label='Authorization Header',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Bearer <token>'})
    )

    # --- NEW CHECKBOXES ---
    scan_bola = forms.BooleanField(required=False, initial=True, label="Check for BOLA (Auth required)")
    scan_broken_auth = forms.BooleanField(required=False, initial=True, label="Check for Broken Authentication")
    scan_injection = forms.BooleanField(required=False, initial=True, label="Check for Injection (SQLi)")
    scan_ratelimit = forms.BooleanField(required=False, initial=True, label="Check for Rate Limiting")

    



    