"""Backup destinations: endpoints for every account (administrator, reseller, user).

Each account manages its own destinations. Backups, restores and snapshot listings name a site
and a destination; policy.require_use() decides, server-side, whether the caller may use that
destination for that site (and the root side checks again). No endpoint returns credentials,
tokens or OAuth client secrets.
"""
import json
import re
from functools import wraps

from django.db import IntegrityError, transaction
from django.utils import timezone

from universalAddons import privileged
from universalAddons.access import error, ok, remember_job, require_job
from universalAddons.destinations import clients, oauth, policy, providers

_SNAP = re.compile(r'^[0-9a-f]{8,64}$')
_DBNAME = re.compile(r'^[A-Za-z0-9_]{1,64}$')
_JOB = re.compile(r'^[0-9a-f]{24}$')
MODULE = 'destinations'


def account_api(view):
    """POST JSON endpoint for any logged-in account; passes (request, data, actor)."""
    @wraps(view)
    def checked(request, *args, **kwargs):
        if 'userID' not in request.session:
            return error('Not logged in. Refresh the page and sign in again.', status=401)
        if request.method != 'POST':
            return error('POST required.', status=405)
        try:
            actor = policy.load_actor(request.session['userID'])
        except PermissionError as exc:
            return error(str(exc), status=403)
        try:
            data = json.loads(request.body or b'{}')
        except ValueError:
            return error('Invalid JSON body.', status=400)
        if not isinstance(data, dict):
            return error('Invalid JSON body.', status=400)
        try:
            return view(request, data, actor, *args, **kwargs)
        except PermissionError as exc:
            return error(str(exc), status=403)
        except ValueError as exc:
            return error(str(exc), status=400)
        except RuntimeError as exc:  # failure reported by the root side
            return error(str(exc), status=200)
    return checked


def _owned(actor, data, key='id'):
    return policy.require_owner(actor, policy.get_destination(data.get(key)))


def _site(actor, data):
    return policy.require_site(actor, policy.website(data.get('domain')))


def _usable(actor, data):
    site = _site(actor, data)
    dest = policy.require_use(actor, policy.get_destination(data.get('destination')), site)
    return dest, site


def page(request):
    from plogical.httpProc import httpProc
    return httpProc(request, 'universalAddons/destinations.html', {}).render()


@account_api
def overview(request, data, actor):
    from universalAddons.models import BackupDestination
    mine = [policy.for_owner(d) for d in BackupDestination.objects.filter(owner_id=actor.pk)]
    configured = {key: clients.public_status(key)['configured'] for key in providers.OAUTH_PROVIDERS}
    sites = [s.domain for s in policy.sites_for(actor)]
    return ok(destinations=mine, providers=providers.describe(), oauth_ready=configured, sites=sites,
              role=actor.role, is_admin=actor.is_admin, s3_presets={k: v['title'] for k, v in providers.S3_PRESETS.items()})


@account_api
def save(request, data, actor):
    """Create a key-based destination, or update one of the caller's own (blank secrets keep)."""
    from universalAddons.models import BackupDestination
    provider = str(data.get('provider', ''))
    spec = providers.get(provider)
    if spec['kind'] != 'key':
        raise ValueError('Use Connect to sign in to %s.' % spec['title'])
    public = providers.validate_public(provider, data.get('settings'))
    secret_values = providers.decode_secrets(data.get('secrets'))
    if data.get('id') not in (None, ''):
        dest = _owned(actor, data)
        if dest.provider != provider:
            raise ValueError('The provider of a destination cannot be changed.')
        # Validate before storing: blank fields keep their stored value on the root side.
        providers.validate_secrets(provider, public, secret_values,
                                   existing={f['key']: providers.KEPT for f in spec['fields'] if f['secret']})
        old_public = dest.public_config
        dest.public_config = json.dumps(public, sort_keys=True)
        dest.save(update_fields=['public_config', 'updated'])
        try:
            privileged.call_private(MODULE, 'save_secrets', dest_id=dest.pk, secrets=secret_values, merge=True)
        except RuntimeError:
            dest.public_config = old_public
            dest.save(update_fields=['public_config', 'updated'])
            raise
        return ok(destination=policy.for_owner(dest))
    name = providers.valid_name(data.get('name'))
    providers.validate_secrets(provider, public, secret_values)
    try:
        with transaction.atomic():
            dest = BackupDestination.objects.create(owner_id=actor.pk, name=name, provider=provider,
                                                    public_config=json.dumps(public, sort_keys=True))
    except IntegrityError:
        raise ValueError('You already have a destination named %s.' % name)
    try:
        privileged.call_private(MODULE, 'save_secrets', dest_id=dest.pk, secrets=secret_values)
    except RuntimeError:
        dest.delete()
        raise
    dest.connected = True
    dest.save(update_fields=['connected', 'updated'])
    return ok(destination=policy.for_owner(dest))


@account_api
def rename(request, data, actor):
    dest = _owned(actor, data)
    dest.name = providers.valid_name(data.get('name'))
    try:
        with transaction.atomic():
            dest.save(update_fields=['name', 'updated'])
    except IntegrityError:
        raise ValueError('You already have a destination named %s.' % dest.name)
    return ok(destination=policy.for_owner(dest))


@account_api
def delete(request, data, actor):
    """Delete a destination. Its backups stay in the storage unless purge is true."""
    dest = _owned(actor, data)
    if data.get('confirm') != dest.name:
        raise ValueError('Type the destination name to confirm.')
    purge = data.get('purge') is True
    result = privileged.call(MODULE, 'delete', dest_id=dest.pk, purge=purge)
    dest.delete()
    _write_cron()
    return ok(result=result)


@account_api
def test(request, data, actor):
    dest = _owned(actor, data)
    result = privileged.call(MODULE, 'test', dest_id=dest.pk)
    dest.last_test, dest.last_test_ok = timezone.now(), result.get('ok') is True
    dest.last_test_message = str(result.get('message', ''))[:500]
    dest.save(update_fields=['last_test', 'last_test_ok', 'last_test_message'])
    return ok(result=result, destination=policy.for_owner(dest))


@account_api
def usage(request, data, actor):
    dest = _owned(actor, data)
    return ok(result=privileged.call(MODULE, 'usage', dest_id=dest.pk))


@account_api
def site_destinations(request, data, actor):
    """Destinations the caller may use for one site, labelled Mine / Site owner: x / Reseller: y."""
    site = _site(actor, data)
    items = [policy.for_others(actor, d, site) for d in policy.allowed_destinations(actor, site)]
    return ok(domain=site.domain, destinations=items)


def _job_view(actor, record):
    return {'id': record.pk, 'domain': record.website.domain, 'destination': record.destination_id,
            'destination_name': record.destination.name, 'owner': policy.owner_name(record.destination),
            'label': policy.label(actor, record.destination, record.website), 'schedule': record.schedule,
            'hour': record.hour, 'keep_daily': record.keep_daily, 'keep_weekly': record.keep_weekly,
            'keep_monthly': record.keep_monthly, 'enabled': record.enabled,
            'last_run': record.last_run.isoformat() if record.last_run else '', 'last_status': record.last_status}


@account_api
def jobs(request, data, actor):
    from universalAddons.models import DestinationBackupJob
    sites = policy.sites_for(actor)
    by_pk = {s.pk: s for s in sites}
    records = DestinationBackupJob.objects.select_related('destination').filter(website_id__in=list(by_pk))
    for record in records:
        record._website = by_pk[record.website_id]
    visible = [r for r in records if r.destination.owner_id in policy.allowed_owner_ids(actor, r.website)]
    return ok(jobs=[_job_view(actor, r) for r in visible])


def _number(data, key, default, low, high):
    try:
        value = int(data.get(key, default))
    except (TypeError, ValueError):
        raise ValueError('%s must be a number.' % key)
    if not low <= value <= high:
        raise ValueError('%s must be %d-%d.' % (key, low, high))
    return value


def _write_cron():
    try:
        privileged.call(MODULE, 'write_cron')
    except RuntimeError:
        pass


@account_api
def save_job(request, data, actor):
    from universalAddons.models import DestinationBackupJob
    dest, site = _usable(actor, data)
    schedule = data.get('schedule', 'daily')
    if schedule not in ('manual', 'hourly', 'daily', 'weekly'):
        raise ValueError('Schedule must be manual, hourly, daily or weekly.')
    values = {'schedule': schedule, 'hour': _number(data, 'hour', 2, 0, 23),
              'keep_daily': _number(data, 'keep_daily', 7, 0, 365), 'keep_weekly': _number(data, 'keep_weekly', 4, 0, 520),
              'keep_monthly': _number(data, 'keep_monthly', 6, 0, 240), 'enabled': data.get('enabled', True) is not False,
              'created_by_id': actor.pk}
    if not (values['keep_daily'] or values['keep_weekly'] or values['keep_monthly']):
        raise ValueError('Keep at least one daily, weekly or monthly backup.')
    record, _ = DestinationBackupJob.objects.update_or_create(website_id=site.pk, destination=dest, defaults=values)
    _write_cron()
    record = DestinationBackupJob.objects.select_related('destination').get(pk=record.pk)
    record._website = site
    return ok(job=_job_view(actor, record))


@account_api
def delete_job(request, data, actor):
    from universalAddons.models import DestinationBackupJob
    try:
        record = DestinationBackupJob.objects.select_related('destination').get(pk=int(data.get('id')))
    except Exception:
        raise PermissionError('Unknown schedule.')
    if record.website is None:
        raise PermissionError('Unknown schedule.')
    policy.require_use(actor, record.destination, record.website)
    record.delete()
    _write_cron()
    return ok(deleted=True)


@account_api
def backup_now(request, data, actor):
    dest, site = _usable(actor, data)
    result = privileged.call(MODULE, 'backup_now', actor_id=actor.pk, dest_id=dest.pk, domain=site.domain)
    remember_job(request, MODULE, result)
    return ok(result=result)


@account_api
def snapshots(request, data, actor):
    dest, site = _usable(actor, data)
    return ok(result=privileged.call(MODULE, 'snapshots', actor_id=actor.pk, dest_id=dest.pk, domain=site.domain))


@account_api
def restore(request, data, actor):
    dest, site = _usable(actor, data)
    kind = data.get('kind')
    snapshot = str(data.get('snapshot', ''))
    include, database = str(data.get('include', '')).strip(), str(data.get('database', ''))
    if kind not in ('files', 'db') or not _SNAP.match(snapshot):
        raise ValueError('Invalid restore request.')
    if kind == 'db' and not _DBNAME.match(database):
        raise ValueError('Choose a database.')
    if kind == 'files' and include.rstrip('/') == '/home/%s' % site.domain:
        include = ''
    if kind == 'files' and include and not include.startswith('/home/%s/' % site.domain):
        raise PermissionError('You can only restore paths inside /home/%s.' % site.domain)
    result = privileged.call(MODULE, 'restore', actor_id=actor.pk, dest_id=dest.pk, domain=site.domain,
                             snapshot=snapshot, kind=kind, include=include, database=database if kind == 'db' else '')
    remember_job(request, MODULE, result)
    return ok(result=result)


class _Context:
    def __init__(self, actor):
        self.is_admin = actor.is_admin


@account_api
def job(request, data, actor):
    job_id = str(data.get('job', ''))
    if not _JOB.match(job_id):
        raise ValueError('Invalid job.')
    return ok(result=privileged.call(MODULE, 'job', job_id=require_job(request, _Context(actor), MODULE, job_id)))


@account_api
def oauth_clients(request, data, actor):
    """Administrators: per provider, whether a sign-in app is set, its redirect URI and setup steps.
    With provider + client_id (+ client_secret_b64): save it; with clear: remove it."""
    if not actor.is_admin:
        raise PermissionError('Only an administrator can set up sign-in apps.')
    provider = data.get('provider')
    if provider is not None:
        if provider not in providers.OAUTH_PROVIDERS:
            raise ValueError('Unknown provider.')
        if not oauth._origin_ok(request):
            raise ValueError('Open the panel over https and try again.')
        try:
            if data.get('clear') is True:
                clients.clear(provider)
            else:
                secret = providers.decode_secrets(data.get('client_secret_b64')).get('client_secret', '')
                clients.save(provider, data.get('client_id', ''), secret)
        except clients.ClientError as exc:
            raise ValueError(str(exc))
    return ok(providers=oauth.provider_status(request))


@account_api
def tools(request, data, actor):
    return ok(result=privileged.call(MODULE, 'tool_status'))
