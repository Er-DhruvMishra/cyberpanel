"""IndiansCloud AI Scanner views (session-authenticated, CSRF-protected)."""
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.http import require_http_methods

from loginSystem.views import loadLoginPage

from .aiScannerManager import AccessDenied, AIScannerManager, can_see_scan, load_actor, scans_for
from .models import ScanHistory


def _uid(request):
    return request.session['userID']


def aiScannerHome(request):
    try:
        user_id = _uid(request)
    except KeyError:
        return redirect(loadLoginPage)
    return AIScannerManager().scannerHome(request, user_id)


def _json_view(method):
    def view(request, *args, **kwargs):
        try:
            user_id = _uid(request)
        except KeyError:
            return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
        return getattr(AIScannerManager(), method)(request, user_id, *args, **kwargs)
    view.__name__ = method
    return view


startScan = require_http_methods(['POST'])(_json_view('startScan'))
getSettings = require_http_methods(['GET'])(_json_view('getSettings'))
saveSettings = require_http_methods(['POST'])(_json_view('saveSettings'))
testKey = require_http_methods(['POST'])(_json_view('testKey'))


def _scan_row(scan, full=False):
    row = {
        'scan_id': scan.scan_id,
        'domain': scan.domain,
        'status': scan.status,
        'scan_type': scan.scan_type,
        'started_at': scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else None,
        'completed_at': scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else None,
        'files_scanned': scan.files_scanned,
        'issues_found': scan.issues_found,
        'summary': scan.summary,
    }
    if full:
        row['findings'] = scan.findings
        row['error_message'] = scan.error_message
    return row


@require_http_methods(['GET'])
def getScanHistory(request):
    try:
        admin, acl, is_admin = load_actor(_uid(request))
    except KeyError:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    except AccessDenied:
        return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
    return JsonResponse({'success': True, 'scans': [_scan_row(s) for s in scans_for(admin, is_admin)[:20]]})


def _visible_scan(request, scan_id):
    admin, acl, is_admin = load_actor(_uid(request))
    scan = ScanHistory.objects.get(scan_id=scan_id)
    if not can_see_scan(scan, admin, is_admin):
        raise AccessDenied('Access denied to this scan')
    return scan


@require_http_methods(['GET'])
def getScanDetails(request, scan_id):
    try:
        scan = _visible_scan(request, scan_id)
    except KeyError:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    except AccessDenied as exc:
        return JsonResponse({'success': False, 'error': str(exc)}, status=403)
    except ScanHistory.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Scan not found'}, status=404)
    return JsonResponse({'success': True, 'scan': _scan_row(scan, full=True)})


@require_http_methods(['GET'])
def getScanStatus(request, scan_id):
    try:
        scan = _visible_scan(request, scan_id)
    except KeyError:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    except AccessDenied as exc:
        return JsonResponse({'success': False, 'error': str(exc)}, status=403)
    except ScanHistory.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Scan not found'}, status=404)
    from .status_models import ScanStatusUpdate
    status = ScanStatusUpdate.objects.filter(scan_id=scan_id).first()
    return JsonResponse({
        'success': True, 'scan_id': scan.scan_id, 'status': scan.status,
        'phase': status.phase if status else scan.status,
        'progress': status.progress if status else (100 if scan.status in ('completed', 'failed') else 0),
        'activity': status.activity_description if status else '',
        'files_scanned': status.files_scanned if status else scan.files_scanned,
        'threats_found': status.threats_found if status else scan.issues_found,
        'is_active': scan.status in ('pending', 'running'),
    })
