from django import forms
from .models import ScanReport

class ScanForm(forms.ModelForm):
    class Meta:
        model = ScanReport
        fields = ['target_url']
        widgets = {
            'target_url': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'Enter Swagger/OpenAPI URL'}),
        }