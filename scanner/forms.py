from django import forms
from .models import UserProfile

class UserProfileForm(forms.ModelForm):
    email = forms.EmailField(
        required=False,
        label='Email Address (For Scan Reports)',
        widget=forms.EmailInput(attrs={'class': 'form-input', 'placeholder': 'your.email@example.com'})
    )
    webhook_url = forms.URLField(
        required=False,
        label='Webhook URL for Notifications (Slack/Discord/Teams)',
        widget=forms.URLInput(attrs={'class': 'form-input', 'placeholder': 'https://hooks.slack.com/...'})
    )
    webhook_threshold = forms.ChoiceField(
        choices=UserProfile.THRESHOLD_CHOICES,
        required=False,
        label="Minimum Vulnerability Alert Threshold",
        widget=forms.Select(attrs={'class': 'form-input'})
    )

    class Meta:
        model = UserProfile
        fields = ['webhook_url', 'webhook_threshold']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and hasattr(self.instance, 'user'):
            self.fields['email'].initial = self.instance.user.email

    def save(self, commit=True):
        profile = super().save(commit=False)
        user = profile.user
        user.email = self.cleaned_data.get('email', '')
        if commit:
            user.save()
            profile.save()
        return profile

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