from django.apps import AppConfig


class WafinstallerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'wafinstaller'

def ready(self):
    import wafinstaller.signals
