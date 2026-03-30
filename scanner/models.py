from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

# --- 1. The Scan Report Model ---
class ScanReport(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    target_url = models.CharField(max_length=500)
    scan_date = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=50, default="Pending")
    result_json = models.JSONField(default=dict, blank=True)
    is_scheduled = models.BooleanField(default=False)
    schedule_interval = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.target_url} - {self.status}"

# --- 2. The User Profile Model (For 2FA) ---
class UserProfile(models.Model):
    THRESHOLD_CHOICES = [
        ('all', 'All Vulnerabilities'),
        ('medium', 'Medium and Above'),
        ('high', 'High and Critical Only'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)
    mfa_enabled = models.BooleanField(default=False)
    webhook_url = models.URLField(max_length=500, blank=True, null=True)
    webhook_threshold = models.CharField(max_length=10, choices=THRESHOLD_CHOICES, default='all')

    def __str__(self):
        return self.user.username

# --- 3. Signals to Auto-Create Profile ---
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    # Check if profile exists before saving (handles old users)
    if hasattr(instance, 'userprofile'):
        instance.userprofile.save()
    else:
        UserProfile.objects.create(user=instance)