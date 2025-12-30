from django import forms

class APIScanForm(forms.Form):
    target_url = forms.URLField(
        required=False, 
        label='Enter API/Swagger URL (or Base URL for file upload)',
        widget=forms.URLInput(attrs={'size': '50', 'placeholder': 'http://127.0.0.1:3000/rest/api-docs/swagger.json'})
    )
    api_file = forms.FileField(
        required=False,
        label='Or Upload an OpenAPI/Swagger File'
    )
    # --- ADD  NEW FIELD ---
    auth_header = forms.CharField(
        required=False,
        label='Authorization Header (e.g., "Authorization: Bearer your_token")',
        widget=forms.TextInput(attrs={'size': '50', 'placeholder': 'Authorization: Bearer ey...'})
    )