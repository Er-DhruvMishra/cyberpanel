"""Retired endpoints of the former vendor-hosted scanner.

The old design let a remote worker on the vendor's platform list, read,
back up, replace, rename and delete website files through token-protected
endpoints, and post results back.  Scans now run locally (see pipeline.py), so
no outside party needs file access.  The routes in api/urls.py still import
these names; every one now answers 410 Gone without touching any file.
"""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

GONE_MESSAGE = ('This endpoint was removed: the IndiansCloud AI Scanner runs on this server '
                'and no remote worker has file access.')


def _gone(request=None, *args, **kwargs):
    return JsonResponse({'success': False, 'error': GONE_MESSAGE}, status=410)


authenticate_worker = csrf_exempt(_gone)
list_files = csrf_exempt(_gone)
get_file_content = csrf_exempt(_gone)
scan_callback = csrf_exempt(_gone)
scanner_backup_file = csrf_exempt(_gone)
scanner_get_file = csrf_exempt(_gone)
scanner_replace_file = csrf_exempt(_gone)
scanner_rename_file = csrf_exempt(_gone)
scanner_delete_file = csrf_exempt(_gone)
