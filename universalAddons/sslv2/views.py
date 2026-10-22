import re

from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok
from universalAddons.sslv2 import service


def _call(action, **args):
    try:
        return ok(result=privileged.call('sslv2', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def page(request):
    return httpProc(request, 'universalAddons/sslv2.html', {}, 'admin').render()


@admin_api
def inventory(request, data):
    return _call('inventory')


@admin_api
def check(request, data):
    domain = str(data.get('domain', '')).strip().lower()
    if not service.valid_domain(domain) or data.get('provider') not in service.PROVIDERS:
        return error('Choose a valid domain and DNS provider.', status=400)
    return _call('check', domain=domain, provider=data['provider'])


@admin_api
def issue(request, data):
    aliases = data.get('aliases', [])
    if not isinstance(aliases, list):
        return error('Invalid aliases.', status=400)
    try:
        clean = service.validate_request(
            domain=str(data.get('domain', '')), provider=data.get('provider'), wildcard=data.get('wildcard') is True,
            aliases=aliases, ca=data.get('ca', 'letsencrypt'), key=data.get('key', 'ec-256'),
            email=str(data.get('email', '')), cf_token=str(data.get('cfToken', '')))
    except service.SSLError as exc:
        return error(str(exc), status=400)
    return _call('issue', domain=clean['domain'], provider=clean['provider'], wildcard=data.get('wildcard') is True,
                 aliases=aliases, ca=clean['ca'], key=clean['key'], email=clean['email'], cf_token=clean['cf_token'])


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)


@admin_api
def monitor(request, data):
    enable = data.get('enable')
    if enable is None:
        return _call('monitor_status')
    if enable not in (True, False):
        return error('Invalid value.', status=400)
    return _call('monitor_cron', enable=enable)
