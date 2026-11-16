"""Gate premium operations before an interactive operation starts work.

ACLManager.CheckForPremFeature answers locally (always granted in this fork);
the failure branch is kept fail-closed for safety. Page views may instead be
sent to a free Universal Add-on when universalAlternatives says so; that
choice is independent of licensing.
"""
from functools import wraps

from django.http import JsonResponse
from django.shortcuts import redirect

from plogical.acl import ACLManager
from plogical.universalAlternatives import alternative_for, preferred_alternative, request_from


def premium_entitlement_required(feature, *, label='Premium feature', flags=(), page_redirect=None):
    def decorate(operation):
        @wraps(operation)
        def checked(*args, **kwargs):
            request = request_from(args, kwargs) if page_redirect else None
            if request is not None:
                replacement = preferred_alternative(request.path)
                if replacement:
                    return redirect(replacement)
            try:
                status = ACLManager.CheckForPremFeature(feature)
                available = type(status) is int and status == 1
            except Exception:
                available = False
            if not available:
                if page_redirect:
                    return redirect(alternative_for(request.path if request else '') or page_redirect)
                data = {flag: 0 for flag in flags}
                data.update(status=0, error_message=f'An active {label} entitlement is required.')
                return JsonResponse(data)
            return operation(*args, **kwargs)
        return checked
    return decorate
