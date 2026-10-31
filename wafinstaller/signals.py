from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver

from wafinstaller.helper.syslog import WARNING, SyslogService, client_ip
from .models import Attack, UserProfile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


# -------------------------
# Syslog forwarding
# -------------------------

@receiver(post_save, sender=Attack)
def forward_attack_to_syslog(sender, instance, created, **kwargs):
    if created:
        SyslogService.attack(instance)


@receiver(user_logged_in)
def audit_login(sender, request, user, **kwargs):
    SyslogService.audit("login", username=user.get_username(), ip=client_ip(request))


@receiver(user_logged_out)
def audit_logout(sender, request, user, **kwargs):
    SyslogService.audit("logout", username=user.get_username() if user else "", ip=client_ip(request))


@receiver(user_login_failed)
def audit_login_failed(sender, credentials, request=None, **kwargs):
    SyslogService.audit("login_failed", username=credentials.get("username", ""),
                        ip=client_ip(request), severity=WARNING)
