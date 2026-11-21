from django.conf import settings

from wafinstaller.helper.server_conf import ApacheConfManager, NginxConfManager


def server_state(request):
    """Expose which web servers are installed so the sidebar can show their config pages."""
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {}
    return {
        "nginx_installed": NginxConfManager.is_installed(),
        "apache_installed": ApacheConfManager.is_installed(),
    }


def app_info(request):
    return {"app_version": settings.APP_VERSION}
