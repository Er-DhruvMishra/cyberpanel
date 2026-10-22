from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok
from universalAddons.emaildebug import service


def _hosted_domains():
    from mailServer.models import Domains
    return sorted(Domains.objects.values_list('domain', flat=True))


def _call(action, **args):
    try:
        return ok(result=privileged.call('emaildebug', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def page(request):
    try:
        domains = _hosted_domains()
    except Exception:
        domains = []
    return httpProc(request, 'universalAddons/emaildebug.html', {'domains': domains}, 'admin').render()


@admin_api
def context(request, data):
    return _call('context')


@admin_api
def dns(request, data):
    domain = str(data.get('domain', '')).strip().lower()
    if not service.valid_domain(domain):
        return error('Enter a valid domain name.', status=400)
    return _call('dns', domain=domain)


@admin_api
def ports(request, data):
    target = data.get('target', 'local')
    if target not in ('local', 'public'):
        return error('Invalid target.', status=400)
    return _call('ports', target=target)


@admin_api
def logs(request, data):
    return _call('logs', query=str(data.get('query', ''))[:200], status=str(data.get('statusFilter', '')),
                 limit=200)


@admin_api
def queue(request, data):
    return _call('queue')


@admin_api
def spam(request, data):
    # 'emailMessage' is the key CyberPanel's input filter reserves for raw message text.
    message = data.get('emailMessage', '')
    if not isinstance(message, str) or not message.strip():
        return error('Paste a complete message, including headers.', status=400)
    if len(message) > 2 * 1024 * 1024:
        return error('Message is larger than 2 MB.', status=400)
    return _call('spam', message=message)


@admin_api
def send(request, data):
    sender = str(data.get('sender', '')).strip()
    recipient = str(data.get('recipient', '')).strip()
    if not service.valid_email(sender) or not service.valid_email(recipient):
        return error('Enter valid sender and recipient addresses.', status=400)
    if sender.rsplit('@', 1)[1].lower() not in {d.lower() for d in _hosted_domains()}:
        return error('The sender must be an address on a domain hosted on this server.', status=400)
    return _call('send', sender=sender, recipient=recipient)
