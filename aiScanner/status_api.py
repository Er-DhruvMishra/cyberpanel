"""Scan progress endpoints used by api/urls.py.

``receive_status_update`` was the vendor platform's webhook and is retired.
``get_live_scan_progress`` now serves the local progress record, and only to a
logged-in user who may see that scan.
"""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .api import GONE_MESSAGE


@csrf_exempt
def receive_status_update(request):
    return JsonResponse({'success': False, 'error': GONE_MESSAGE}, status=410)


@require_http_methods(['GET'])
def get_live_scan_progress(request, scan_id):
    from .views import getScanStatus
    return getScanStatus(request, scan_id)
