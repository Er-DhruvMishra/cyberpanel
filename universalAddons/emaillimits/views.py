"""Email Limits endpoints. Database changes happen here; pushing them into cpecs goes through root."""
from plogical.acl import ACLManager
from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, load_policy, ok, site_api
from universalAddons.emaillimits import service as svc

FEATURE = 'email_limits_for_users'
MAX_BULK = 2000


def _owned_sites(context):
    return ACLManager.findAllSites(context.acl, context.user_id, 1)


def _domain(data, context):
    """The mail domain named in the request, after checking the caller manages its website."""
    name = svc.clean_domain(data.get('domain'))
    mail_domain = svc.get_mail_domain(name)
    if mail_domain is None:
        if context.is_admin:
            raise ValueError('%s has no email domain.' % name)
        raise PermissionError('You do not manage %s.' % name)  # same answer as for a foreign domain
    context.require_site(svc.owner_site(mail_domain))
    return mail_domain


def _sync(commands):
    """Push cache commands to cpecs. The database is already saved; report a failed push, don't undo."""
    if not commands:
        return {'delivered': 0}
    try:
        return privileged.call('emaillimits', 'sync', commands=commands)
    except RuntimeError as exc:
        return {'delivered': 0, 'error': str(exc)}


def page(request):
    """Open to every logged-in user; what they can do is decided per request (see site_api)."""
    try:
        user_id = request.session['userID']
        is_admin = ACLManager.loadedACL(user_id).get('admin') == 1
    except Exception:
        is_admin = False
    for_users = bool(load_policy().get(FEATURE))
    return httpProc(request, 'universalAddons/emaillimits.html', {
        'is_admin': is_admin, 'enabled': is_admin or for_users, 'for_users': for_users}).render()


# --- everyone allowed by the policy (administrators: all domains)

@site_api(FEATURE)
def overview(request, data, context):
    return ok(result={'domains': svc.overview(None if context.is_admin else _owned_sites(context)),
                      'is_admin': context.is_admin})


@site_api(FEATURE)
def detail(request, data, context):
    return ok(result=svc.detail(_domain(data, context)))


@site_api(FEATURE)
def save_mailbox(request, data, context):
    mail_domain = _domain(data, context)
    email = svc.clean_email(data.get('mailbox'))
    if email.split('@')[1] != mail_domain.domain:
        raise ValueError('%s is not a mailbox of %s.' % (email, mail_domain.domain))
    change = (email, svc.clean_status(data.get('enabled'), 'Limit status'), svc.clean_limit(data.get('monthly'), 'Monthly limit'),
              svc.clean_limit(data.get('hourly'), 'Hourly limit'))
    commands = svc.save_mailboxes(mail_domain, [change], context.is_admin)
    return ok(result={'sync': _sync(commands), 'detail': svc.detail(mail_domain)})


@site_api(FEATURE)
def apply_all(request, data, context):
    """Give every mailbox of the domain the same status and limits."""
    mail_domain = _domain(data, context)
    status = svc.clean_status(data.get('enabled'), 'Limit status')
    monthly = svc.clean_limit(data.get('monthly'), 'Monthly limit')
    hourly = svc.clean_limit(data.get('hourly'), 'Hourly limit')
    emails = svc.domain_emails(mail_domain)
    if not emails:
        raise ValueError('%s has no mailboxes.' % mail_domain.domain)
    if len(emails) > MAX_BULK:
        raise ValueError('More than %d mailboxes; change them in smaller groups.' % MAX_BULK)
    commands = svc.save_mailboxes(mail_domain, [(e, status, monthly, hourly) for e in emails], context.is_admin)
    return ok(result={'sync': _sync(commands), 'updated': len(emails), 'detail': svc.detail(mail_domain)})


@site_api(FEATURE)
def refresh(request, data, context):
    """Have cpecs write its live counters to the database (it is harmless and changes no limit)."""
    try:
        flushed = privileged.call('emaillimits', 'refresh')
    except RuntimeError as exc:
        flushed = {'flushed': False, 'error': str(exc)}
    return ok(result={'refresh': flushed, 'domains': svc.overview(None if context.is_admin else _owned_sites(context))})


# --- administrators only

@admin_api
def save_domain(request, data):
    name = svc.clean_domain(data.get('domain'))
    mail_domain = svc.get_mail_domain(name)
    if mail_domain is None:
        return error('%s has no email domain.' % name, status=400)
    commands = svc.save_domain(mail_domain, svc.clean_status(data.get('enabled'), 'Limit status'),
                               svc.clean_limit(data.get('monthly'), 'Monthly limit'))
    return ok(result={'sync': _sync(commands), 'detail': svc.detail(mail_domain)})


@admin_api
def health(request, data):
    try:
        return ok(result=privileged.call('emaillimits', 'health'))
    except RuntimeError as exc:
        return error(str(exc))


@admin_api
def repair_cron(request, data):
    try:
        return ok(result=privileged.call('emaillimits', 'repair_cron'))
    except RuntimeError as exc:
        return error(str(exc))


@admin_api
def policy(request, data):
    if not isinstance(data.get('enabled'), bool):
        return error('enabled must be true or false.', status=400)
    try:
        return ok(result=privileged.call('emaillimits', 'set_policy', enabled=data['enabled']))
    except RuntimeError as exc:
        return error(str(exc))
