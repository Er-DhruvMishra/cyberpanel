"""Fail2ban ban manager (/addons/bans/), administrators only.

Addresses travel inside the "q" object of the JSON body: CyberPanel's input filter screens plain
string values and would refuse the ':' of IPv6 addresses.
"""
from universalAddons import privileged
from universalAddons.access import admin_api, admin_page, error, ok
from universalAddons.bans import service as sv
from universalAddons.sshsec import service as ssh


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('bans', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _q(data):
    q = data.get('q')
    if not isinstance(q, dict):
        raise ValueError('Invalid request.')
    return q


def page(request):
    return admin_page(request, 'universalAddons/bans.html')


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def search(request, data):
    return _call('search', ip=sv.check_ip(_q(data).get('ip')))


@admin_api
def unban(request, data):
    q = _q(data)
    return _call('unban', jail=sv.check_jail(q.get('jail')), ip=sv.check_ip(q.get('ip')))


@admin_api
def ban(request, data):
    q = _q(data)
    jail, ip = sv.check_jail(q.get('jail')), sv.check_ip(q.get('ip'))
    return _call('ban', jail=jail, ip=ip, client=ssh.client_ips(request.META))


@admin_api
def whitelist_add(request, data):
    return _call('whitelist_add', entry=sv.check_entry(_q(data).get('entry')))


@admin_api
def whitelist_remove(request, data):
    return _call('whitelist_remove', entry=sv.check_entry(_q(data).get('entry')))
