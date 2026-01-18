from celery import Celery
from celery.schedules import crontab
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')

app = Celery('ip_tracking')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks(['ip_tracking'])

app.conf.beat_schedule = {
    'detect-suspicious-ips-hourly': {
        'task': 'ip_tracking.tasks.detect_suspicious_ips',
        'schedule': crontab(minute=0, hour='*'),  # Run every hour
    },
}
