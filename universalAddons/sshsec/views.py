import re

from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok
from universalAddons.sshsec import service as sv


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('sshsec', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _actor(request):
    try:
        from loginSystem.models import Administrator
        return Administrator.objects.get(pk=request.session['userID']).userName
    except Exception:
        return ''


def _target(data):
    """Address/CIDR from the page ('addr', with ':' sent as '-'), strictly validated here and again as root."""
    try:
        return str(sv.parse_target(sv.decode_target(data.get('addr'))))
    except sv.SSHSecError as exc:
        raise ValueError(str(exc))


def page(request):
    return httpProc(request, 'universalAddons/sshsec.html', {}, 'admin').render()


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def analyze(request, data):
    window = data.get('window')
    if window not in sv.WINDOWS:
        return error('Choose 24h, 7d or 30d.', status=400)
    return _call('analyze', window=window, client=sv.client_ips(request.META))


@admin_api
def audit(request, data):
    return _call('audit', client=sv.client_ips(request.META))


@admin_api
def blocklist(request, data):
    return _call('blocklist')


@admin_api
def block(request, data):
    target = _target(data)
    try:
        reason = sv.validate_reason(data.get('reason', ''))
    except sv.SSHSecError as exc:
        return error(str(exc), status=400)
    client = sv.client_ips(request.META)
    refusals, _ = sv.block_checks(sv.parse_target(target), client)
    if refusals:  # checked again as root, with the server's own addresses
        return error(' '.join(refusals), status=400)
    return _call('block', target=target, reason=reason, client=client, confirm=data.get('confirm') is True,
                 by=_actor(request))


@admin_api
def unblock(request, data):
    return _call('unblock', target=_target(data))


@admin_api
def enable_jail(request, data):
    if data.get('confirm') is not True:
        return error('Confirmation required.', status=400)
    return _call('enable_f2b_sshd')


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)
