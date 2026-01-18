from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    """
    Hourly task to detect suspicious IP activity
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Detect IPs with excessive requests
    excessive_requests = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=100)
    
    for ip_data in excessive_requests:
        ip_address = ip_data['ip_address']
        count = ip_data['request_count']
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': f'Excessive requests: {count} requests in the last hour',
                'is_active': True
            }
        )
    
    # Detect IPs accessing sensitive paths
    sensitive_paths = ['/admin/', '/login/', '/api/auth/', '/reset-password/']
    
    sensitive_access = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths
    ).values('ip_address').annotate(
        sensitive_count=Count('id')
    ).filter(sensitive_count__gt=5)
    
    for ip_data in sensitive_access:
        ip_address = ip_data['ip_address']
        count = ip_data['sensitive_count']
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': f'Suspicious access: {count} attempts to sensitive paths in the last hour',
                'is_active': True
            }
        )
    
    # Detect potential scanning behavior
    unique_paths_per_ip = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        unique_paths=Count('path', distinct=True)
    ).filter(unique_paths__gt=20)
    
    for ip_data in unique_paths_per_ip:
        ip_address = ip_data['ip_address']
        unique_paths = ip_data['unique_paths']
        
        SuspiciousIP.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'reason': f'Potential scanning: accessed {unique_paths} unique paths in the last hour',
                'is_active': True
            }
        )
    
    return f"Detected {excessive_requests.count() + sensitive_access.count() + unique_paths_per_ip.count()} suspicious IPs"
