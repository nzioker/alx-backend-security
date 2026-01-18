from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.core.cache import cache
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
import logging
from ipgeolocation import IPGeolocationAPI
from django.conf import settings

logger = logging.getLogger(__name__)

class IPLoggingMiddleware(MiddlewareMixin):
    def _get_geolocation(self, ip_address):
        """Get geolocation data with caching"""
        cache_key = f'ip_geo_{ip_address}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        try:
            # Initialize with your API key (you should add this to settings)
            # For production, get an API key from ipgeolocation.io
            api_key = getattr(settings, 'IPGEOLOCATION_API_KEY', None)
            
            if api_key:
                api = IPGeolocationAPI(api_key)
                result = api.get_geolocation(ip_address=ip_address)
                
                if result and result.get('country_name'):
                    geo_data = {
                        'country': result.get('country_name'),
                        'city': result.get('city')
                    }
                    # Cache for 24 hours (86400 seconds)
                    cache.set(cache_key, geo_data, 86400)
                    return geo_data
        except Exception as e:
            logger.error(f"Geolocation error for IP {ip_address}: {e}")
        
        return {'country': None, 'city': None}
    
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
            geo_data = self._get_geolocation(request.client_ip)
            
            RequestLog.objects.create(
                ip_address=request.client_ip,
                path=request.path,
                timestamp=timezone.now(),
                country=geo_data.get('country'),
                city=geo_data.get('city')
            )
        
        return response
