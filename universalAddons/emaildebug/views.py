"""Email Debugger endpoints.

Site owners (when the policy allows it) get the DNS and reputation checks for their own domains.
The log trace, queue, port tests, spam scoring and test sending show or affect the whole mail
server, so they stay with administrators.
"""
from plogical.acl import ACLManager

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok, site_api, site_page
from universalAddons.emaildebug import service

FEATURE = 'email_debug_for_users'


def _hosted_domains():
    from mailServer.models import Domains
    return sorted(Domains.objects.values_list('domain', flat=True))


def _own_mail_domains(request):
    """Mail domains of the websites (and child domains) the caller manages."""
    from mailServer.models import Domains
    user_id = request.session['userID']
    sites = ACLManager.findAllSites(ACLManager.loadedACL(user_id), user_id, 1)
    return sorted(Domains.objects.filter(domain__in=sites).values_list('domain', flat=True))


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('emaildebug', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def page(request):
    def data(is_admin):
        try:
            return {'domains': _hosted_domains() if is_admin else _own_mail_domains(request)}
        except Exception:
            return {'domains': []}
    return site_page(request, 'universalAddons/emaildebug.html', FEATURE, data)


# --- administrators, and site owners for their own domains (when the policy allows it)

@site_api(FEATURE)
def context(request, data, context):
    return _call('context')


@site_api(FEATURE)
def dns(request, data, context):
    domain = str(data.get('domain', '')).strip().lower()
    if not service.valid_domain(domain):
        return error('Enter a valid domain name.', status=400)
    if not context.is_admin:
        context.require_site(domain)
    return _call('dns', domain=domain)


# --- administrators only: these show or affect the whole mail server


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
