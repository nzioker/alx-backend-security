from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.core.cache import cache
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
import logging

logger = logging.getLogger(__name__)

class IPLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Get client IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
        
        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            logger.warning(f"Blocked IP {ip_address} attempted to access {request.path}")
            return HttpResponseForbidden("Access Denied - IP Blocked")
        
        # Store IP in request for later use
        request.client_ip = ip_address
        
        return None
    
    def process_response(self, request, response):
        # Only log if we have the IP stored
        if hasattr(request, 'client_ip'):
            RequestLog.objects.create(
                ip_address=request.client_ip,
                path=request.path,
                timestamp=timezone.now()
            )
        
        return response
