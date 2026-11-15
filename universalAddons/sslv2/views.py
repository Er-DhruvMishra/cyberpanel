"""SSL V2 endpoints.

Administrators: every domain, any CA, the saved Cloudflare token and the expiry e-mails. Site
owners (when the policy allows it): certificates for domains they manage only, from Let's Encrypt,
with their own Cloudflare token when they use Cloudflare.
"""
import re

from universalAddons import privileged
from universalAddons.access import (admin_api, error, ok, owned_sites, remember_job, require_job, site_api,
                                    site_page)
from universalAddons.sslv2 import service

FEATURE = 'ssl_for_users'
USER_CAS = ('letsencrypt', 'letsencrypt_test')   # ZeroSSL would register a server-wide ACME account


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('sslv2', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _alias_domains(context):
    """Domain aliases (parked domains) of the caller's websites."""
    from websiteFunctions.models import aliasDomains
    sites = owned_sites(context) or []
    return {a.lower() for a in aliasDomains.objects.filter(master__domain__in=sites).values_list('aliasDomain', flat=True)}


def _foreign_subdomains(context, bases):
    """Panel sites below `bases` that the caller does not manage (a wildcard would cover them)."""
    from websiteFunctions.models import ChildDomains, Websites
    found = set()
    for base in bases:
        suffix = '.' + base
        for model in (Websites, ChildDomains):
            found.update(d.lower() for d in model.objects.filter(domain__iendswith=suffix).values_list('domain', flat=True))
    return sorted(d for d in found if not context.owns(d))


def _require_domains(context, domain, aliases, wildcard=False):
    """Site owners may only name domains they manage: their sites, child domains and domain aliases.

    A wildcard is refused when it would also cover a site of another account.
    """
    if context.is_admin:
        return
    context.require_site(domain)
    pending = [a for a in aliases if a != domain and not context.owns(a)]
    if pending:
        allowed = _alias_domains(context)
        foreign = [a for a in pending if a not in allowed]
        if foreign:
            raise PermissionError('You do not manage %s.' % ', '.join(sorted(foreign)))
    if wildcard:
        others = _foreign_subdomains(context, sorted({domain} | set(aliases)))
        if others:
            raise PermissionError('A wildcard for this domain would also cover %s, which you do not manage. '
                                  'Issue the certificate without *.%s.' % (', '.join(others[:5]), domain))


def page(request):
    return site_page(request, 'universalAddons/sslv2.html', FEATURE)


@site_api(FEATURE)
def inventory(request, data, context):
    if context.is_admin:
        return _call('inventory')
    try:
        result = privileged.call('sslv2', 'inventory', domains=owned_sites(context))
    except RuntimeError as exc:
        return error(str(exc))
    result.pop('saved_cloudflare_token', None)  # the administrator's token is not for users
    return ok(result=result)


@site_api(FEATURE)
def check(request, data, context):
    domain = str(data.get('domain', '')).strip().lower()
    if not service.valid_domain(domain) or data.get('provider') not in service.PROVIDERS:
        return error('Choose a valid domain and DNS provider.', status=400)
    _require_domains(context, domain, [])
    return _call('check', domain=domain, provider=data['provider'])


@site_api(FEATURE)
def issue(request, data, context):
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
    if not context.is_admin:
        if clean['ca'] not in USER_CAS:
            return error("Choose Let's Encrypt.", status=400)
        if clean['provider'] == 'cloudflare' and not clean['cf_token']:
            return error('Enter your Cloudflare API token (Zone:DNS:Edit for this zone).', status=400)
        _require_domains(context, clean['domain'], [a for a in clean['names'] if not a.startswith('*.')],
                         wildcard=data.get('wildcard') is True)
    try:
        result = privileged.call('sslv2', 'issue', domain=clean['domain'], provider=clean['provider'],
                                 wildcard=data.get('wildcard') is True, aliases=aliases, ca=clean['ca'], key=clean['key'],
                                 email=clean['email'] if context.is_admin else '', cf_token=clean['cf_token'])
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'sslv2', result)
    return ok(result=result)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'sslv2', job_id))


@admin_api
def monitor(request, data):
    enable = data.get('enable')
    if enable is None:
        return _call('monitor_status')
    if enable not in (True, False):
        return error('Invalid value.', status=400)
    return _call('monitor_cron', enable=enable)
