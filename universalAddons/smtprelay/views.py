"""SMTP Relay endpoints (administrators only).

Settings and passwords travel inside nested JSON objects ("config", "secrets"): CyberPanel's request
filter screens only top-level string values, and a password may hold any character. They reach the
root side through a private spool file (privileged.call_private), never on a command line, and no
answer ever contains a password.
"""
from universalAddons import privileged
from universalAddons.access import admin_api, admin_page, error, ok
from universalAddons.smtprelay import service as sv


def page(request):
    return admin_page(request, 'universalAddons/smtprelay.html')


def _call(action, private=False, **args):
    try:
        caller = privileged.call_private if private else privileged.call
        return ok(result=caller('smtprelay', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def save(request, data):
    config = sv.validate_config(data.get('config'))  # RelayError is a ValueError: 400
    secrets = data.get('secrets') if isinstance(data.get('secrets'), dict) else {}
    clean = {}
    for slot, value in secrets.items():
        if not isinstance(slot, str) or not (slot == 'global' or slot.startswith('domain:')):
            return error('Invalid password field.', status=400)
        password = sv.clean_password(value)
        if password:
            clean[slot] = password
    return _call('apply', private=True, config=config, secrets=clean, confirm=data.get('confirm') is True)


@admin_api
def disable(request, data):
    if data.get('confirm') is not True:
        return error('Confirmation required.', status=400)
    return _call('disable', forget=data.get('forget') is True)


@admin_api
def test(request, data):
    body = data.get('test') if isinstance(data.get('test'), dict) else {}
    to = sv.clean_email(body.get('to'), 'recipient address')
    sender = sv.clean_email(body.get('from'), 'sender address') if body.get('from') else ''
    target = body.get('target') or 'global'
    if target != 'global':
        target = 'domain:' + sv.clean_domain(str(target)[len('domain:'):] if str(target).startswith('domain:') else '')
    return _call('test', to=to, target=target, sender=sender)
