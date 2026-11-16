"""Apache Manager gate. The licence answer is local (always granted); ACLs stay in the views."""
from functools import wraps
import re

from django.http import JsonResponse
from django.shortcuts import redirect

from plogical.acl import ACLManager
from plogical.universalAlternatives import alternative_for, preferred_alternative, request_from


def apache_manager_available():
    try:
        status = ACLManager.CheckForPremFeature('all')
        return type(status) is int and status == 1
    except Exception:
        return False


def apache_entitlement_error(message='An active entitlement is required for Apache Manager.'):
    return JsonResponse({
        'status': 0, 'saveStatus': 0, 'configstatus': 0,
        'createWebSiteStatus': 0, 'installStatus': 0,
        'error_message': message,
    })


def normalize_apache_backend(value):
    if value is None or value == '':
        return 0
    if type(value) in (int, bool):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r'[+-]?\d+', value.strip()):
        return int(value.strip())
    raise ValueError('Invalid Apache backend selection.')


def apache_backend_entitlement_error(data):
    try:
        requested = normalize_apache_backend((data or {}).get('apacheBackend', 0))
    except (AttributeError, TypeError, ValueError) as error:
        return apache_entitlement_error(str(error))
    if requested and not apache_manager_available():
        return apache_entitlement_error()
    return None


def apache_entitlement_required(page=False):
    def decorate(method):
        @wraps(method)
        def checked(*args, **kwargs):
            if page:
                # Licence-independent: only vendor-dependent pages or features the
                # administrator chose to replace go to the free add-on.
                request = request_from(args, kwargs)
                replacement = preferred_alternative(request.path) if request is not None else None
                if replacement:
                    return redirect(replacement)
            if not apache_manager_available():
                if page:
                    return redirect(alternative_for(request.path if request else '') or 'index')
                return apache_entitlement_error()
            return method(*args, **kwargs)
        return checked
    return decorate
