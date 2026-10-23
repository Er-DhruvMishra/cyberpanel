import re

from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok

_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


def _call(action, **args):
    try:
        return ok(result=privileged.call('htaccess', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _domain(data):
    value = str(data.get('domain', '')).strip().lower()
    if not _DOMAIN.match(value):
        raise ValueError('Invalid domain.')
    return value


def page(request):
    return httpProc(request, 'universalAddons/htaccess.html', {}, 'admin').render()


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def preview(request, data):
    return _call('preview', domain=_domain(data))


@admin_api
def enable(request, data):
    return _call('enable', domain=_domain(data))


@admin_api
def disable(request, data):
    return _call('disable', domain=_domain(data))
