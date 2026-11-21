from django.contrib.auth.models import AbstractUser, User
from django.db import models
from django.utils.timezone import now


# Create your models here.

class AttackRequest(models.Model):
    """The HTTP request behind one or more Attack rows (one per ModSecurity transaction)."""
    unique_id = models.CharField(max_length=128, blank=True, db_index=True)
    method = models.CharField(max_length=16, blank=True)
    protocol = models.CharField(max_length=16, blank=True)
    user_agent = models.CharField(max_length=1024, blank=True)
    headers = models.JSONField(default=dict, blank=True)
    cookies = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True)
    body_truncated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.method} {self.unique_id}"


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
    request = models.ForeignKey(AttackRequest, null=True, blank=True, on_delete=models.SET_NULL,
                                related_name="attacks")
    # ModSecurity unique_id of the request: deduplicates re-read log entries without hiding repeated attacks.
    txn_id = models.CharField(max_length=128, blank=True, default="", db_index=True)

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

class IpList(models.Model):
    """Named list of IPs / CIDR ranges rendered into include files for nginx and Apache."""
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    ACTION_CHOICES = [(ACTION_ALLOW, "Allow"), (ACTION_DENY, "Deny")]
    KIND_IP = "ip"
    KIND_GEO = "geo"
    KIND_CHOICES = [(KIND_IP, "IP list"), (KIND_GEO, "Geo list (countries)")]

    name = models.CharField(max_length=64, unique=True)
    kind = models.CharField(max_length=3, choices=KIND_CHOICES, default=KIND_IP)
    action = models.CharField(max_length=5, choices=ACTION_CHOICES, default=ACTION_DENY)
    countries = models.CharField(max_length=1024, blank=True,
                                 help_text="Comma-separated ISO 3166-1 alpha-2 codes (geo lists).")
    description = models.CharField(max_length=255, blank=True)
    entries = models.TextField(blank=True, help_text="One IP or CIDR per line, optional '# comment'.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.action})"

    @property
    def is_allow(self):
        return self.action == self.ACTION_ALLOW

    @property
    def is_geo(self):
        return self.kind == self.KIND_GEO

    @property
    def country_list(self):
        return [c for c in self.countries.split(",") if c]

    @property
    def nginx_variable(self):
        """nginx variable set to 1 for clients in a geo list (names allow only [A-Za-z0-9_])."""
        return "wafc_geo_" + self.name.replace("-", "_")

    @property
    def entry_count(self):
        return sum(1 for line in self.entries.splitlines() if line.split("#", 1)[0].strip())
