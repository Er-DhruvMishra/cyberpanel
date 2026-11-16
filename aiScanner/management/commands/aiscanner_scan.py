"""Run one queued IndiansCloud AI Scanner scan (started by the panel in the background)."""
import os

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Run one queued AI Scanner scan by its scan id'

    def add_arguments(self, parser):
        parser.add_argument('--scan-id', required=True)

    def handle(self, *args, **options):
        try:
            os.nice(5)
        except (AttributeError, OSError):
            pass
        from aiScanner.aiScannerManager import run_scan_by_id
        scan = run_scan_by_id(options['scan_id'])
        self.stdout.write('%s: %s (%d issues)' % (scan.scan_id, scan.status, scan.issues_found))
