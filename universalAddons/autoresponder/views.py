"""Autoresponders & Spam Rules endpoints.

Who may use them: administrators, and accounts whose panel ACL has the Email Forwarding
permission (emailForwarding), for mailboxes of mail domains whose website or child domain they
own; resellers also for the websites of the accounts they created (the panel's checkOwnership:
mailbox -> mail domain -> website/child domain -> owner).
"""
import datetime
import json
from functools import wraps

from plogical.acl import ACLManager

from universalAddons import privileged
from universalAddons.access import SiteContext, error, forbidden, ok
from universalAddons.autoresponder import service as svc

ACL_KEY = 'emailForwarding'
MAX_LIST_MAILBOXES = 5000


def _context(request):
    from loginSystem.models import Administrator
    user_id = request.session['userID']
    acl = ACLManager.loadedACL(user_id)
    return SiteContext(user_id, acl, Administrator.objects.get(pk=user_id))


def allowed(acl):
    return acl.get('admin') == 1 or acl.get(ACL_KEY) == 1


def mail_api(admin_only=False):
    def decorate(view):
        @wraps(view)
        def checked(request, *args, **kwargs):
            if 'userID' not in request.session:
                return error('Not logged in. Refresh the page and sign in again.', status=401)
            if request.method != 'POST':
                return error('POST required.', status=405)
            try:
                context = _context(request)
            except Exception:
                return error('Could not load your account.', status=403)
            if not allowed(context.acl) or (admin_only and not context.is_admin):
                return error('Your account may not manage email rules.' if not admin_only
                             else 'Administrator access is required.', status=403)
            try:
                data = json.loads(request.body or b'{}')
            except ValueError:
                return error('Invalid JSON body.', status=400)
            if not isinstance(data, dict):
                return error('Invalid JSON body.', status=400)
            try:
                return view(request, data, context, *args, **kwargs)
            except PermissionError as exc:
                return error(str(exc), status=403)
            except ValueError as exc:
                return error(str(exc), status=400)
        return checked
    return decorate


# ----------------------------------------------------------------------------- ownership

def _owner_site(mail_domain):
    if mail_domain.domainOwner_id:
        return mail_domain.domainOwner.domain
    if mail_domain.childOwner_id:
        return mail_domain.childOwner.domain
    return mail_domain.domain


def require_mailbox(context, email):
    """The mailbox, after checking the caller manages the website its mail domain belongs to."""
    from mailServer.models import EUsers
    email = svc.clean_email(email)
    try:
        mailbox = EUsers.objects.select_related('emailOwner__domainOwner', 'emailOwner__childOwner').get(email=email)
    except EUsers.DoesNotExist:
        if context.is_admin:
            raise ValueError('Unknown mailbox %s.' % email)
        raise PermissionError('You do not manage %s.' % email)   # same answer as for a foreign mailbox
    if not context.is_admin and not context.owns(_owner_site(mailbox.emailOwner)):
        raise PermissionError('You do not manage %s.' % email)
    return email


def owned_mailboxes(context):
    from django.db.models import Q
    from mailServer.models import EUsers
    query = EUsers.objects.select_related('emailOwner__domainOwner', 'emailOwner__childOwner').order_by('email')
    if not context.is_admin:
        sites = [s.lower() for s in ACLManager.findAllSites(context.acl, context.user_id, 1)]
        query = query.filter(Q(emailOwner__domainOwner__domain__in=sites) | Q(emailOwner__childOwner__domain__in=sites))
    return [{'email': m.email, 'domain': m.emailOwner_id, 'site': _owner_site(m.emailOwner)}
            for m in query[:MAX_LIST_MAILBOXES]]


# ----------------------------------------------------------------------------- page and endpoints

def page(request):
    from plogical.httpProc import httpProc
    is_admin = False
    if 'userID' in request.session:
        try:
            acl = ACLManager.loadedACL(request.session['userID'])
        except Exception:
            acl = {}
        if not allowed(acl):
            return forbidden(request, 'Your account may not manage email rules.')
        is_admin = acl.get('admin') == 1
    wanted = str(request.GET.get('mailbox', '')).strip()[:80]
    return httpProc(request, 'universalAddons/autoresponder.html', {
        'is_admin': is_admin, 'mailbox': wanted if '@' in wanted else '',
        'max_body': svc.MAX_BODY, 'max_subject': svc.MAX_SUBJECT}).render()


def _call(action, **args):
    try:
        return ok(result=privileged.call('autoresponder', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


@mail_api()
def mailboxes(request, data, context):
    return ok(result={'mailboxes': owned_mailboxes(context), 'is_admin': context.is_admin})


@mail_api()
def get(request, data, context):
    return _call('status', email=require_mailbox(context, data.get('email')))


@mail_api()
def save(request, data, context):
    email = require_mailbox(context, data.get('email'))
    settings = svc.clean_settings({'vacation': data.get('vacation'), 'spam': data.get('spam')},
                                  datetime.date.today())
    return _call('save', email=email, settings=settings)


@mail_api(admin_only=True)
def health(request, data, context):
    return _call('health')
