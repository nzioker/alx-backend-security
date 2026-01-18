from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP
import argparse

class Command(BaseCommand):
    help = 'Block or unblock IP addresses'
    
    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block/unblock')
        parser.add_argument('--reason', type=str, help='Reason for blocking', default='Manual block')
        parser.add_argument('--unblock', action='store_true', help='Unblock the IP instead')
    
    def handle(self, *args, **options):
        ip_address = options['ip_address']
        
        if options['unblock']:
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
                blocked_ip.delete()
                self.stdout.write(self.style.SUCCESS(f'Successfully unblocked IP: {ip_address}'))
            except BlockedIP.DoesNotExist:
                self.stdout.write(self.style.WARNING(f'IP {ip_address} was not blocked'))
        else:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': options['reason']}
            )
            
            if created:
                self.stdout.write(self.style.SUCCESS(f'Successfully blocked IP: {ip_address}'))
            else:
                blocked_ip.reason = options['reason']
                blocked_ip.save()
                self.stdout.write(self.style.SUCCESS(f'Updated block for IP: {ip_address}'))
