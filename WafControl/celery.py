import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'WafControl.settings')
app = Celery('WafControl')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'update-dashboard-stats-every-1-minute': {
        'task': 'wafinstaller.tasks.update_dashboard_stats',
        'schedule': crontab(minute='*/1'),
    },

    # Separate schedules; each task self-skips if server kind mismatches.
    'update-waf-attacks-apache-every-1-minute': {
        'task': 'wafinstaller.tasks.update_waf_attacks_apache',
        'schedule': crontab(minute='*/1'),
    },
    'update-waf-attacks-nginx-every-1-minute': {
        'task': 'wafinstaller.tasks.update_waf_attacks_nginx',
        'schedule': crontab(minute='*/1'),
    },

    'delete-old-attacks-daily': {
        'task': 'wafinstaller.tasks.delete_old_attacks',
        'schedule': crontab(hour=3, minute=0),
    },
    'fetch-crs-versions-every-12h': {
        'task': 'wafinstaller.tasks.fetch_crs_versions_task',
        'schedule': crontab(minute=0, hour='*/12'),
    },
}
