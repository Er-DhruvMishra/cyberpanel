"""WordPress Manager gate. The licence answer is local (always granted); ACLs stay in the views."""
from functools import wraps

from django.http import JsonResponse
from django.shortcuts import redirect

from plogical.acl import ACLManager
from plogical.universalAlternatives import alternative_for, preferred_alternative, request_from


def wordpress_manager_available():
    try:
        status = ACLManager.CheckForPremFeature('wp-manager')
        return type(status) is int and status == 1
    except Exception:
        return False


def wordpress_entitlement_required(page=False):
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
            if not wordpress_manager_available():
                if page:
                    return redirect(alternative_for(request.path if request else '') or 'index')
                # Existing AJAX and direct API callers use these numeric fields.
                # Denial must never look like a started installer or worker.
                return JsonResponse({
                    'status': 0,
                    'installStatus': 0,
                    'createWebSiteStatus': 0,
                    'fetchStatus': 0,
                    'error_message': 'An active WordPress Manager entitlement is required.',
                })
            return method(*args, **kwargs)
        return checked
    return decorate
