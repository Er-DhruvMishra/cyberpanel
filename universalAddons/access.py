"""Access control and request helpers shared by every add-on module.

Every add-on endpoint is administrator-only. JSON endpoints accept POST with a JSON body
(CSRF-protected by Django's middleware); CyberPanel's secMiddleware still screens the body.
"""
import json
from functools import wraps

from django.http import JsonResponse

from plogical.acl import ACLManager


def is_admin(request):
    try:
        user_id = request.session['userID']
    except KeyError:
        return None
    try:
        return ACLManager.loadedACL(user_id).get('admin') == 1
    except Exception:
        return False


def error(message, status=200, **extra):
    data = {'status': 0, 'error_message': message}
    data.update(extra)
    return JsonResponse(data, status=status)


def ok(**data):
    data['status'] = 1
    return JsonResponse(data)


def admin_api(view):
    """POST-only JSON endpoint for administrators. Passes the parsed body as `data`."""
    @wraps(view)
    def checked(request, *args, **kwargs):
        admin = is_admin(request)
        if admin is None:
            return error('Not logged in. Refresh the page and sign in again.', status=401)
        if not admin:
            return error('Administrator access is required.', status=403)
        if request.method != 'POST':
            return error('POST required.', status=405)
        try:
            data = json.loads(request.body or b'{}')
        except ValueError:
            return error('Invalid JSON body.', status=400)
        if not isinstance(data, dict):
            return error('Invalid JSON body.', status=400)
        try:
            return view(request, data, *args, **kwargs)
        except ValueError as exc:  # validation errors raised by service code
            return error(str(exc), status=400)
    return checked
