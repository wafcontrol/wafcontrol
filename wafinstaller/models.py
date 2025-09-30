from django.contrib.auth.models import AbstractUser, User
from django.db import models
from django.utils.timezone import now


# Create your models here.

# models.py
class Attack(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    country = models.CharField(max_length=100)
    flag = models.CharField(max_length=10)
    rule_id = models.CharField(max_length=20, default="UNKNOWN_RULE")
    message = models.TextField(default="No message")
    uri = models.CharField(max_length=2048)
    referer = models.CharField(max_length=2048, blank=True, null=True)
    status = models.CharField(max_length=20, default="Detected")
    version = models.CharField(max_length=20)
    host = models.CharField(max_length=255, null=True, blank=True)
    severity = models.IntegerField(default=2)      # 0=Info, 1=Low, 2=Medium, 3=High
    anomaly_score = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.timestamp} - {self.ip} - Severity: {self.severity}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, blank=True, null=True)


class CrsVersion(models.Model):
    tag = models.CharField(max_length=100, unique=True)
    published_at = models.DateTimeField()
    zip_url = models.URLField()
    fetched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.tag

class DashboardStat(models.Model):
    fetched_at = models.DateTimeField(default=now)
    cpu_usage = models.CharField(max_length=20)
    cpu_load = models.CharField(max_length=20)
    ram_usage = models.CharField(max_length=20)
    disk_usage = models.CharField(max_length=20)
    storage_free = models.CharField(max_length=20)
    total_processes = models.CharField(max_length=20)
    total_threads = models.CharField(max_length=20)
    total_handles = models.CharField(max_length=20)

    def __str__(self):
        return f"DashboardStat at {self.fetched_at}"

class AppSetting(models.Model):
    key = models.CharField(max_length=255, unique=True)
    value = models.TextField()

    def __str__(self):
        return f"{self.key} = {self.value}"