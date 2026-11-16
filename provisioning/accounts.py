"""Account-level operations for the provisioning API, each permission-checked.

Permission model (matches the panel's own ownership rules, see ACLManager.checkUserOwnerShip):

* an administrator may act on every account;
* any other account (a reseller) may act on itself and on accounts it owns (``owner == its id``);
* destructive actions (suspend, terminate) never target the caller itself, and an administrator
  account can only be suspended or terminated from the panel, never through the API.
"""
import json
import re
import secrets
import hashlib
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

USERNAME_RE = re.compile(r'^[a-z0-9][a-z0-9_.-]{2,49}$')
REDIRECT_RE = re.compile(r'^/[A-Za-z0-9/_.\-]{0,190}$')
SSO_TTL_SECONDS = 60
DEFAULT_REDIRECT = '/base/'


class AccountError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- permissions

def acl_config(account):
    try:
        return json.loads(account.acl.config or '{}')
    except Exception:
        return {}


def is_admin(account):
    from plogical.acl import ACLManager
    try:
        return ACLManager.isAdminACL(account.acl)
    except Exception:
        return False


def permission(account, name):
    if is_admin(account):
        return True
    config = acl_config(account)
    if name in config:
        return int(config.get(name) or 0) == 1
    return int(getattr(account.acl, name, 0) or 0) == 1


def is_reseller(account):
    return not is_admin(account) and permission(account, 'resellerCenter')


def can_manage(actor, target):
    if is_admin(actor):
        return True
    return target.pk == actor.pk or target.owner == actor.pk


def require_manage(actor, target):
    if not can_manage(actor, target):
        raise AccountError('Not authorized to manage this account.', 403)


def require_destructive(actor, target):
    require_manage(actor, target)
    if target.pk == actor.pk:
        raise AccountError('An account cannot do this to itself through the API.', 403)
    if is_admin(target):
        raise AccountError('Administrator accounts can only be changed from the panel.', 403)


def managed_accounts(actor):
    from loginSystem.models import Administrator
    if is_admin(actor):
        return Administrator.objects.all().order_by('userName')
    from django.db.models import Q
    return Administrator.objects.filter(Q(owner=actor.pk) | Q(pk=actor.pk)).order_by('userName')


def get_account(username):
    from loginSystem.models import Administrator
    username = str(username or '').strip()
    if not username:
        raise AccountError('Missing username.')
    try:
        return Administrator.objects.get(userName=username)
    except Administrator.DoesNotExist:
        raise AccountError('Account not found.', 404)


def sub_accounts(account):
    from loginSystem.models import Administrator
    return Administrator.objects.filter(owner=account.pk).exclude(pk=account.pk)


def _json(response):
    try:
        return json.loads(response.content.decode())
    except Exception:
        return {}


# --------------------------------------------------------------------------- listing / usage

def account_info(account):
    sites = list(account.websites_set.all().order_by('domain').values_list('domain', flat=True))
    return {
        'username': account.userName,
        'email': account.email,
        'firstName': account.firstName,
        'lastName': account.lastName,
        'acl': account.acl.name,
        'state': account.state,
        'owner_id': account.owner,
        'reseller': is_reseller(account),
        'websites': sites,
        'websitesLimit': account.initWebsitesLimit,
    }


def list_accounts(actor):
    return [account_info(a) for a in managed_accounts(actor)]


def site_usage(website):
    from plogical.virtualHostUtilities import virtualHostUtilities
    disk, disk_pct, bw, bw_pct = virtualHostUtilities.FindStats(website)
    try:
        config = json.loads(website.config or '{}')
    except ValueError:
        config = {}

    def num(value):
        try:
            return round(float(value), 2)
        except (TypeError, ValueError):
            return 0

    return {
        'domain': website.domain,
        'package': website.package.packageName,
        'state': 'suspended' if website.state == 0 else 'active',
        'disk_mb': num(disk),
        'disk_percent': num(disk_pct),
        'disk_limit_mb': int(website.package.diskSpace or 0),     # 0 = unlimited
        'bandwidth_mb': num(bw),
        'bandwidth_percent': num(bw_pct),
        'bandwidth_limit_mb': int(website.package.bandwidth or 0),
        'checked_at': config.get('storageUsageCheckedAt'),
    }


def account_usage(account):
    sites = [site_usage(w) for w in account.websites_set.all().order_by('domain')]
    return {
        'username': account.userName,
        'state': account.state,
        'sites': sites,
        'total': {
            'disk_mb': round(sum(s['disk_mb'] for s in sites), 2),
            'disk_limit_mb': sum(s['disk_limit_mb'] for s in sites),
            'bandwidth_mb': round(sum(s['bandwidth_mb'] for s in sites), 2),
            'bandwidth_limit_mb': sum(s['bandwidth_limit_mb'] for s in sites),
        },
    }


# --------------------------------------------------------------------------- suspend / unsuspend

def _purge_sessions(account_id):
    """Log out the account everywhere (database session backend; best effort)."""
    try:
        from django.contrib.sessions.models import Session
        for session in Session.objects.filter(expire_date__gt=timezone.now()).iterator():
            try:
                if session.get_decoded().get('userID') == account_id:
                    session.delete()
            except Exception:
                continue
    except Exception:
        pass


def _set_site_state(actor, domain, state):
    from websiteFunctions.website import WebsiteManager
    result = _json(WebsiteManager().submitWebsiteStatus(actor.pk, {'websiteName': domain, 'state': state}))
    return result.get('websiteStatus') == 1, result.get('error_message', '')


def _suspend_one(actor, account, reason, parent=None):
    from .models import AccountSuspension
    suspended, errors = [], []
    for website in account.websites_set.all().order_by('domain'):
        if website.state == 0:
            continue                # already suspended on its own; unsuspend will leave it alone
        ok, message = _set_site_state(actor, website.domain, 'Suspend')
        (suspended.append(website.domain) if ok else errors.append('%s: %s' % (website.domain, message)))
    account.state = 'SUSPENDED'
    account.save(update_fields=['state'])
    record, created = AccountSuspension.objects.get_or_create(
        account_id=account.pk,
        defaults={'sites': json.dumps(suspended), 'reason': reason[:200], 'suspended_by_id': actor.pk,
                  'parent_account_id': parent.pk if parent else None})
    if not created:                # suspended again: remember every site we have taken down
        merged = sorted(set(json.loads(record.sites or '[]')) | set(suspended))
        record.sites = json.dumps(merged)
        if reason:
            record.reason = reason[:200]
        record.save(update_fields=['sites', 'reason'])
    _purge_sessions(account.pk)
    return suspended, errors


def suspend_account(actor, target, reason=''):
    """Suspend every site of ``target`` and block its panel login. A reseller's own accounts are
    suspended with it (unless already suspended on their own)."""
    require_destructive(actor, target)
    if not permission(actor, 'suspendWebsite'):
        raise AccountError('Your account may not suspend websites.', 403)
    reason = re.sub(r'[\x00-\x1f\x7f]', ' ', str(reason or ''))[:200]
    suspended, errors = _suspend_one(actor, target, reason)
    cascaded = []
    if is_reseller(target):
        for child in sub_accounts(target):
            if child.state == 'SUSPENDED' or is_admin(child):
                continue
            child_sites, child_errors = _suspend_one(actor, child, reason, parent=target)
            cascaded.append(child.userName)
            suspended += child_sites
            errors += child_errors
    return {'username': target.userName, 'state': 'SUSPENDED', 'suspended_sites': suspended,
            'suspended_accounts': cascaded, 'errors': errors}


def _unsuspend_one(actor, account):
    from .models import AccountSuspension
    record = AccountSuspension.objects.filter(account_id=account.pk).first()
    if record is not None:
        domains = json.loads(record.sites or '[]')
    else:                # suspended in the panel or by the old API: restore every suspended site
        domains = list(account.websites_set.filter(state=0).values_list('domain', flat=True))
    restored, errors = [], []
    from websiteFunctions.models import Websites
    for domain in domains:
        website = Websites.objects.filter(domain=domain, admin_id=account.pk).first()
        if website is None or website.state != 0:
            continue
        ok, message = _set_site_state(actor, domain, 'UN-Suspend')
        (restored.append(domain) if ok else errors.append('%s: %s' % (domain, message)))
    account.state = 'ACTIVE'
    account.save(update_fields=['state'])
    if record is not None and not errors:
        record.delete()
    return restored, errors


def unsuspend_account(actor, target):
    from .models import AccountSuspension
    from loginSystem.models import Administrator
    require_destructive(actor, target)
    if not permission(actor, 'suspendWebsite'):
        raise AccountError('Your account may not unsuspend websites.', 403)
    restored, errors = _unsuspend_one(actor, target)
    cascaded = []
    for record in AccountSuspension.objects.filter(parent_account_id=target.pk):
        child = Administrator.objects.filter(pk=record.account_id).first()
        if child is None:
            record.delete()
            continue
        child_sites, child_errors = _unsuspend_one(actor, child)
        cascaded.append(child.userName)
        restored += child_sites
        errors += child_errors
    return {'username': target.userName, 'state': 'ACTIVE', 'unsuspended_sites': restored,
            'unsuspended_accounts': cascaded, 'errors': errors}


# --------------------------------------------------------------------------- password / package

def change_password(actor, target, password):
    from plogical import hashPassword
    require_manage(actor, target)
    if target.pk != actor.pk and is_admin(target) and not is_admin(actor):
        raise AccountError('Not authorized to manage this account.', 403)
    password = str(password or '')
    if len(password) < 8 or len(password) > 128:
        raise AccountError('The password must be 8 to 128 characters.')
    target.password = hashPassword.hash_password(password)
    target.save(update_fields=['password'])
    if target.pk != actor.pk:
        _purge_sessions(target.pk)
    return {'username': target.userName}


def find_package(actor, name):
    from packages.models import Package
    from plogical.acl import ACLManager
    name = str(name or '').strip()
    if not name:
        raise AccountError('Missing package name.')
    package = Package.objects.filter(packageName=name).first()
    if package is None:            # panel package names are "<creator>_<name>"
        package = Package.objects.filter(packageName='%s_%s' % (actor.userName, name)).first()
    if package is None:
        raise AccountError('Package not found: %s' % name[:50], 404)
    if ACLManager.CheckPackageOwnership(package, actor, {'admin': 1 if is_admin(actor) else 0}) != 1:
        raise AccountError('Not authorized to use this package.', 403)
    return package


def change_package(actor, target, package_name, domain=None):
    require_manage(actor, target)
    if not permission(actor, 'modifyWebsite'):
        raise AccountError('Your account may not modify websites.', 403)
    package = find_package(actor, package_name)
    sites = target.websites_set.all()
    if domain:
        sites = sites.filter(domain=str(domain).strip().lower())
        if not sites.exists():
            raise AccountError('This account has no website %s.' % str(domain)[:100], 404)
    changed = []
    for website in sites:
        website.package = package
        website.save(update_fields=['package'])
        changed.append(website.domain)
    return {'username': target.userName, 'package': package.packageName, 'websites': changed}


# --------------------------------------------------------------------------- create / terminate

def _resolve_acl(actor, acl_name):
    from loginSystem.models import ACL
    acl_name = str(acl_name or 'user').strip() or 'user'
    acl = ACL.objects.filter(name=acl_name).first()
    if acl is None:
        raise AccountError('ACL not found: %s' % acl_name[:50], 404)
    if not is_admin(actor):
        from plogical.acl import ACLManager
        if ACLManager.isAdminACL(acl):
            raise AccountError('Only an administrator can create administrator accounts.', 403)
        if acl.name != 'user' and not permission(actor, 'changeUserACL'):
            raise AccountError("Your account may only create accounts with the 'user' ACL.", 403)
    return acl


def create_website(actor, owner, domain, package, php, email):
    """Create a website for ``owner`` through the panel's own creation path."""
    from websiteFunctions.website import WebsiteManager
    data = {
        'domainName': domain, 'adminEmail': email, 'phpSelection': php or 'PHP 8.1',
        'package': package.packageName, 'websiteOwner': owner.userName,
        'ssl': 1, 'dkimCheck': 1, 'openBasedir': 1,
    }
    result = _json(WebsiteManager().submitWebsiteCreation(actor.pk, data))
    if result.get('createWebSiteStatus') != 1:
        raise AccountError(result.get('error_message') or 'Website creation failed.')
    return result


def create_account(actor, data):
    """Create a panel account and (optionally) its first website. Rolls the account back if the
    website cannot be started."""
    from loginSystem.models import Administrator
    from plogical import hashPassword
    from plogical.acl import ACLManager
    from plogical.securityUtils import generate_api_token
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError

    username = str(data.get('username') or '').strip().lower()
    if not USERNAME_RE.match(username):
        raise AccountError('Username must be 3-50 characters: lowercase letters, digits, "_", "." or "-".')
    email = str(data.get('email') or '').strip()
    try:
        validate_email(email)
    except ValidationError:
        raise AccountError('Invalid email address.')
    password = str(data.get('password') or '')
    if len(password) < 8 or len(password) > 128:
        raise AccountError('The password must be 8 to 128 characters.')
    domain = str(data.get('domain') or '').strip().lower().rstrip('.')
    if domain.startswith('www.'):
        domain = domain[4:]
    if not permission(actor, 'createNewUser'):
        raise AccountError('Your account may not create accounts.', 403)
    if domain and not permission(actor, 'createWebsite'):
        raise AccountError('Your account may not create websites.', 403)
    acl = _resolve_acl(actor, data.get('acl'))
    try:
        websites_limit = int(data.get('websitesLimit') or 1)
    except (TypeError, ValueError):
        raise AccountError('websitesLimit must be a number.')
    if websites_limit < 0 or websites_limit > 10000:
        raise AccountError('websitesLimit is out of range.')
    if ACLManager.websitesLimitCheck(actor, websites_limit) == 0:
        raise AccountError("You've reached maximum websites limit as a reseller.", 403)
    package = find_package(actor, data.get('package')) if domain else None
    if Administrator.objects.filter(userName=username).exists():
        raise AccountError('Username already exists: %s' % username, 409)
    if domain:
        from websiteFunctions.models import Websites
        if Websites.objects.filter(domain=domain).exists():
            raise AccountError('A website with this domain already exists: %s' % domain, 409)

    def clean_name(key):
        value = re.sub(r'[^\w .\'-]', '', str(data.get(key) or ''), flags=re.UNICODE).strip()
        return value[:50] or 'None'

    with transaction.atomic():
        account = Administrator(
            userName=username, password=hashPassword.hash_password(password), email=email,
            firstName=clean_name('firstName'), lastName=clean_name('lastName'), type=3,
            owner=actor.pk, initWebsitesLimit=websites_limit, acl=acl, token=generate_api_token(),
            api=0)
        account.save()
    result = {'username': username, 'acl': acl.name, 'website': None}
    if domain:
        try:
            created = create_website(actor, account, domain, package, data.get('php'), email)
        except Exception as error:
            account.delete()
            message = error.message if isinstance(error, AccountError) else 'Website creation failed.'
            raise AccountError(message)
        result.update(website=domain, package=package.packageName,
                      tempStatusPath=created.get('tempStatusPath'), LinuxUser=created.get('LinuxUser'))
    return result


def terminate_account(actor, target):
    """Delete every website of ``target`` (through the panel's deletion path), then the account."""
    from websiteFunctions.website import WebsiteManager
    from . import tokens
    from .models import AccountSuspension
    require_destructive(actor, target)
    if not permission(actor, 'deleteUser') or not permission(actor, 'deleteWebsite'):
        raise AccountError('Your account may not delete accounts and websites.', 403)
    children = sub_accounts(target)
    if children.exists():
        raise AccountError('This account owns %d other accounts. Move or remove them first.'
                           % children.count(), 409)
    manager = WebsiteManager()
    for domain in list(target.websites_set.values_list('domain', flat=True)):
        result = _json(manager.submitWebsiteDeletion(actor.pk, {'websiteName': domain}))
        if result.get('websiteDeleteStatus') == 2:
            raise AccountError('Deletion of %s is still running. Retry in a minute.' % domain, 409)
        if result.get('websiteDeleteStatus') != 1:
            raise AccountError('Could not delete %s: %s' % (domain, result.get('error_message', 'unknown error')))
    username = target.userName
    tokens.revoke_all_for(target.pk, actor)
    AccountSuspension.objects.filter(account_id=target.pk).delete()
    _purge_sessions(target.pk)
    try:
        from resellerBranding.models import ResellerBranding
        ResellerBranding.objects.filter(reseller_id=target.pk).delete()
    except Exception:
        pass
    target.delete()
    return {'username': username, 'deleted': True}


# --------------------------------------------------------------------------- single sign-on

def _ticket_hash(ticket):
    return hashlib.sha256(ticket.encode('utf-8')).hexdigest()


def issue_sso_ticket(actor, target, redirect=None, token=None):
    """Create a 60-second, single-use login ticket for ``target``. Returns the plaintext ticket."""
    from .models import SsoTicket
    require_manage(actor, target)
    if target.pk != actor.pk and is_admin(target):
        raise AccountError('Single sign-on into another administrator account is not allowed.', 403)
    if target.state != 'ACTIVE':
        raise AccountError('This account is suspended.', 403)
    redirect = str(redirect or DEFAULT_REDIRECT)
    if not REDIRECT_RE.match(redirect) or redirect.startswith('//') or '..' in redirect:
        raise AccountError('The redirect must be a path on this panel, such as /websites/listWebsites.')
    ticket = secrets.token_urlsafe(32)
    SsoTicket.objects.create(
        ticket_hash=_ticket_hash(ticket), account_id=target.pk, issued_by_id=actor.pk,
        token_id=getattr(token, 'pk', None), redirect=redirect,
        expires_at=timezone.now() + timedelta(seconds=SSO_TTL_SECONDS))
    SsoTicket.objects.filter(expires_at__lt=timezone.now() - timedelta(days=1)).delete()
    return ticket


def redeem_sso_ticket(ticket, ip=''):
    """Consume a ticket atomically. Returns (Administrator, redirect) or raises AccountError."""
    from loginSystem.models import Administrator
    from .models import SsoTicket
    ticket = str(ticket or '')
    if not re.match(r'^[A-Za-z0-9_-]{20,100}$', ticket):
        raise AccountError('Invalid or expired login link.', 401)
    now = timezone.now()
    digest = _ticket_hash(ticket)
    consumed = SsoTicket.objects.filter(ticket_hash=digest, used_at__isnull=True,
                                        expires_at__gt=now).update(used_at=now, used_ip=str(ip)[:64])
    if consumed != 1:
        raise AccountError('Invalid or expired login link.', 401)
    record = SsoTicket.objects.get(ticket_hash=digest)
    account = Administrator.objects.filter(pk=record.account_id).first()
    if account is None or account.state != 'ACTIVE':
        raise AccountError('This account is not available.', 403)
    return account, record.redirect


def legacy_create_website(actor, data):
    """v1 ``createWebsite`` for a token-authenticated caller. Same fields and response keys as
    v1; an existing ``websiteOwner`` gets the site only if the caller manages that account."""
    from loginSystem.models import Administrator
    owner_name = str(data.get('websiteOwner') or '').strip().lower()
    domain = str(data.get('domainName') or '').strip().lower()
    try:
        owner = Administrator.objects.filter(userName=owner_name).first()
        if owner is None:
            result = create_account(actor, {
                'username': owner_name, 'email': data.get('ownerEmail'), 'password': data.get('ownerPassword'),
                'domain': domain, 'package': data.get('packageName'), 'php': data.get('phpSelection'),
                'acl': data.get('acl'), 'websitesLimit': data.get('websitesLimit') or 1})
        else:
            require_manage(actor, owner)
            if not permission(actor, 'createWebsite'):
                raise AccountError('Your account may not create websites.', 403)
            result = create_website(actor, owner, domain, find_package(actor, data.get('packageName')),
                                    data.get('phpSelection'), data.get('ownerEmail') or owner.email)
        return {'status': 1, 'createWebSiteStatus': 1, 'existsStatus': 0, 'error_message': 'None',
                'tempStatusPath': result.get('tempStatusPath'), 'LinuxUser': result.get('LinuxUser')}
    except AccountError as error:
        return {'status': 0, 'createWebSiteStatus': 0, 'existsStatus': 0, 'error_message': error.message}
