"""Root-side backup destination actions (dispatched by universalAddons/runner.py).

Secrets store: /etc/cyberpanel/backup-destinations (root, 0700)
  secrets/<id>.json   credentials or OAuth tokens of destination <id> (0600)
  keys/dst-<id>.key   restic password of the destination's repository (0600)
  run/                per-run rclone configuration files (0600, deleted after each run)

Every action that touches a destination renders its rclone section into a fresh private file,
points RCLONE_CONFIG at it (restic's rclone backend inherits it), and deletes it afterwards.
Secrets never appear on a command line. Tokens that rclone refreshed during the run are copied
back to the store, so providers that rotate refresh tokens (Box, Microsoft) keep working.

The web layer checks permissions; backup, restore and snapshot actions check them again here,
against the database, for the account that asked (actor_id).
"""
import configparser
import contextlib
import json
import os
import re
import secrets as _secrets
import socket
import tempfile
import time

from universalAddons import jobs
from universalAddons.backupv2 import service as bk
from universalAddons.backupv2.service import BackupError
from universalAddons.destinations import clients, policy, providers

STORE = '/etc/cyberpanel/backup-destinations'
CRON_FILE = '/etc/cron.d/cyberpanel-backup-destinations'
RCLONE = 'rclone'
UNITS = ['files', 'db']
TEST_TIMEOUT = 120
_SNAP = re.compile(r'^[0-9a-f]{8,64}$')


def _django():
    from universalAddons import django_env
    django_env.setup()


def _store(*parts, store=None):
    return os.path.join(store or STORE, *parts)


def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _dest(dest_id):
    _django()
    try:
        return policy.get_destination(dest_id)
    except PermissionError as exc:
        raise BackupError(str(exc))


def _secret_file(dest_id, store=None):
    return _store('secrets', '%d.json' % int(dest_id), store=store)


def load_secrets(dest_id, store=None):
    try:
        with open(_secret_file(dest_id, store)) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_secrets(dest_id, data, store=None):
    directory = _store('secrets', store=store)
    _private_dir(_store(store=store))
    _private_dir(directory)
    fd, temporary = tempfile.mkstemp(prefix='.s-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle)
        os.replace(temporary, _secret_file(dest_id, store))
        temporary = None
    finally:
        if temporary:
            os.unlink(temporary)


def obscure(value, runner=None):
    """rclone's reversible password obscuring; the value goes through stdin, not argv."""
    code, out = bk.run([RCLONE, 'obscure', '-'], runner=runner or bk.subprocess.run, timeout=30, input=value)
    if code != 0 or not out.strip():
        raise BackupError('rclone could not prepare the password (is rclone installed?).')
    return out.strip().splitlines()[-1]


def _panel_uid():
    try:
        from universalAddons.privileged import panel_uid
        return panel_uid()
    except Exception:
        return None


def oauth_client(provider):
    try:
        return clients.load(provider, allowed_uid=_panel_uid())
    except clients.ClientError as exc:
        raise BackupError(str(exc))


def remote_name(dest):
    return 'dst%d' % dest.pk


def repo_for(dest):
    return {'id': 'dst-%d' % dest.pk, 'type': 'rclone', 'remote': remote_name(dest),
            'path': providers.repo_path(dest.provider, policy.public_config(dest))}


def _ensure_key(repo_id, store=None):
    _private_dir(_store(store=store))
    _private_dir(_store('keys', store=store))
    path = _store('keys', repo_id + '.key', store=store)
    if not os.path.exists(path):
        bk._write_secret(path, _secrets.token_urlsafe(48) + '\n')
    return path


@contextlib.contextmanager
def session(dest, store=None, runner=None, wait=0, lock_dir=None):
    """Exclusive use of `dest` with its rclone config in a private temporary file."""
    secrets = load_secrets(dest.pk, store)
    if not secrets:
        raise BackupError('No credentials are stored for this destination. Its owner must reconnect it.')
    spec = providers.get(dest.provider)
    client = oauth_client(dest.provider) if spec['kind'] == 'oauth' else None
    remote = remote_name(dest)
    try:
        text = providers.render(remote, dest.provider, policy.public_config(dest), secrets, client,
                                lambda value: obscure(value, runner))
    except (KeyError, providers.ProviderError) as exc:
        raise BackupError('The destination settings are incomplete: %s' % exc)
    run_dir = _store('run', store=store)
    _private_dir(_store(store=store))
    _private_dir(run_dir)
    with bk.repo_lock('dst-%d' % dest.pk, lock_dir=lock_dir, wait=wait):
        fd, path = tempfile.mkstemp(prefix='rc-', suffix='.conf', dir=run_dir)
        previous = os.environ.get('RCLONE_CONFIG')
        try:
            with os.fdopen(fd, 'w') as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(text)
            os.environ['RCLONE_CONFIG'] = path
            yield remote, path
        finally:
            if previous is None:
                os.environ.pop('RCLONE_CONFIG', None)
            else:
                os.environ['RCLONE_CONFIG'] = previous
            try:
                if spec['kind'] == 'oauth':
                    _sync_token(dest, path, remote, secrets, store)
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(path)


def _sync_token(dest, path, remote, secrets, store=None):
    """Keep the token rclone refreshed during the run (refresh tokens may rotate)."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path)
        token = parser[remote]['token']
    except (configparser.Error, KeyError, OSError):
        return False
    if token == secrets.get('token'):
        return False
    try:
        updated = providers.validate_oauth_secrets(dest.provider, dict(secrets, token=token))
    except providers.ProviderError:
        return False
    write_secrets(dest.pk, updated, store)
    return True


def _rclone(path, args, runner=None, timeout=TEST_TIMEOUT, input=None):
    return bk.run([RCLONE, '--config', path, '--contimeout', '15s', '--timeout', '60s', '--retries', '1',
                   '--low-level-retries', '2'] + args, runner=runner or bk.subprocess.run, timeout=timeout,
                  input=input)


def _target(remote, path):
    return '%s:%s' % (remote, path)


# ----------------------------------------------------------------------------- destination management

def save_secrets(dest_id, secrets, merge=False, store=None):
    dest = _dest(dest_id)
    spec = providers.get(dest.provider)
    try:
        if spec['kind'] == 'oauth':
            clean = providers.validate_oauth_secrets(dest.provider, secrets)
        else:
            existing = load_secrets(dest.pk, store) if merge else {}
            clean = providers.validate_secrets(dest.provider, policy.public_config(dest), secrets, existing)
    except providers.ProviderError as exc:
        raise BackupError(str(exc))
    write_secrets(dest.pk, clean, store)
    return {'saved': True}


def delete(dest_id, purge=False, store=None, runner=None):
    """Forget a destination's credentials; with purge, also delete its backup repository."""
    dest = _dest(dest_id)
    purged = False
    if purge:
        with session(dest, store, runner) as (remote, path):
            code, out = _rclone(path, ['purge', _target(remote, repo_for(dest)['path'])], runner, timeout=6 * 3600)
            if code != 0 and 'directory not found' not in out.lower():
                raise BackupError('The backups could not be deleted: %s' % bk._last_error(out))
        purged = True
    with contextlib.suppress(OSError):
        os.unlink(_secret_file(dest.pk, store))
    if purged:
        with contextlib.suppress(OSError):
            os.unlink(_store('keys', 'dst-%d.key' % dest.pk, store=store))
    return {'deleted': dest.pk, 'purged': purged}


def test(dest_id, store=None, runner=None):
    """Write a small object to the destination folder, list it, delete it."""
    dest = _dest(dest_id)
    base = providers.base_path(dest.provider, policy.public_config(dest))
    name = '.indianscloud-test-%s' % _secrets.token_hex(6)
    try:
        with session(dest, store, runner) as (remote, path):
            code, out = _rclone(path, ['mkdir', _target(remote, base)], runner)
            if code != 0:
                return {'ok': False, 'message': 'Could not open the folder: ' + bk._last_error(out)}
            code, out = _rclone(path, ['rcat', _target(remote, base + '/' + name)], runner,
                                input='IndiansCloud connection test\n')
            if code != 0:
                return {'ok': False, 'message': 'Could not write a test file: ' + bk._last_error(out)}
            code, out = _rclone(path, ['lsjson', '--files-only', _target(remote, base)], runner)
            listed = code == 0 and name in out
            code2, out2 = _rclone(path, ['deletefile', _target(remote, base + '/' + name)], runner)
            if not listed:
                return {'ok': False, 'message': 'The test file was written but could not be listed: ' +
                        bk._last_error(out)}
            if code2 != 0:
                return {'ok': False, 'message': 'The test file could not be deleted: ' + bk._last_error(out2)}
    except BackupError as exc:
        return {'ok': False, 'message': str(exc)[:480]}
    return {'ok': True, 'message': 'Connected: wrote, listed and deleted a test file in %s.' % base}


def usage(dest_id, store=None, runner=None):
    dest = _dest(dest_id)
    if not providers.get(dest.provider).get('about'):
        return {'supported': False, 'message': 'This provider does not report usage or free space.'}
    with session(dest, store, runner) as (remote, path):
        code, out = _rclone(path, ['about', remote + ':', '--json'], runner)
    if code != 0:
        return {'supported': False, 'message': 'Usage is not available: ' + bk._last_error(out)}
    try:
        data = json.loads(out[out.index('{'):])
    except ValueError:
        return {'supported': False, 'message': 'Usage is not available.'}
    result = {'supported': True}
    for key in ('total', 'used', 'free', 'trashed', 'other'):
        if isinstance(data.get(key), (int, float)):
            result[key] = int(data[key])
            result[key + '_text'] = bk.human(data[key])
    return result


# ----------------------------------------------------------------------------- backups and restores

def _context(actor_id, dest_id, domain):
    """(actor, destination, site) after checking actor may use destination for site."""
    _django()
    try:
        actor = policy.load_actor(actor_id)
        site = policy.website(domain)
        dest = policy.get_destination(dest_id)
        policy.require_use(actor, dest, site)
    except PermissionError as exc:
        raise BackupError(str(exc))
    return actor, dest, site


def _databases(domain):
    _django()
    from databases.models import Databases
    return sorted(Databases.objects.filter(website__domain=domain).values_list('dbName', flat=True))


def _hostname():
    return socket.getfqdn() or 'localhost'


def _keep(dest, site):
    from universalAddons.models import DestinationBackupJob
    job = DestinationBackupJob.objects.filter(website_id=site.pk, destination=dest).first()
    if job:
        return {'daily': job.keep_daily, 'weekly': job.keep_weekly, 'monthly': job.keep_monthly}
    return {'daily': 7, 'weekly': 4, 'monthly': 6}


def _backup(job, dest, site, store=None, runner=None, wait=0):
    repo = repo_for(dest)
    databases = _databases(site.domain)
    defaults = bk.mysql_defaults_file() if databases else None
    try:
        with session(dest, store, runner, wait=wait):
            _ensure_key(repo['id'], store)
            job.log(bk.init_repo(repo, config_dir=store or STORE)['detail'])
            result = bk.backup_site(repo, site.domain, UNITS, databases, _hostname(), log=job.log,
                                    config_dir=store or STORE, defaults_file=defaults)
            job.log('%s: %s' % (site.domain, '; '.join('%s %s' % kv for kv in result.items())))
            job.log(bk.apply_retention(repo, site.domain, {'keep': {k: v for k, v in _keep(dest, site).items() if v}},
                                       config_dir=store or STORE))
    finally:
        if defaults:
            os.unlink(defaults)
    return result


def backup_now(actor_id, dest_id, domain):
    _, dest, site = _context(actor_id, dest_id, domain)
    return jobs.spawn('destinations', 'backup_run', {'actor_id': actor_id, 'dest_id': dest.pk, 'domain': site.domain})


def backup_run(job_id, actor_id, dest_id, domain):
    _, dest, site = _context(actor_id, dest_id, domain)

    def body(job):
        return _backup(job, dest, site)
    return jobs.run_job(job_id, [('Back up %s to %s' % (site.domain, dest.name), body)])


def run_scheduled(job_pk):
    """Cron entry point: run a scheduled site backup, re-checking its creator's rights."""
    _django()
    from django.utils import timezone
    from universalAddons.models import DestinationBackupJob
    record = DestinationBackupJob.objects.select_related('destination').get(pk=int(job_pk))
    if not record.enabled:
        return {'skipped': 'disabled'}
    if record.website is None:
        raise BackupError('The website of this schedule no longer exists.')
    os.makedirs(jobs.JOB_DIR, mode=0o700, exist_ok=True)
    try:
        _, dest, site = _context(record.created_by_id, record.destination_id, record.website.domain)
    except BackupError as exc:
        record.last_run, record.last_status = timezone.now(), ('Not run: %s' % exc)[:500]
        record.save(update_fields=['last_run', 'last_status'])
        raise

    def body(job):
        return _backup(job, dest, site, wait=2 * 3600)
    data = jobs.run_job(os.urandom(12).hex(), [('Back up %s to %s' % (site.domain, dest.name), body)])
    record.last_run = timezone.now()
    record.last_status = ('ok' if data.get('state') == 'done' else 'failed: %s' % data.get('error', ''))[:500]
    record.save(update_fields=['last_run', 'last_status'])
    return {'state': data.get('state')}


def snapshots(actor_id, dest_id, domain, store=None, runner=None):
    _, dest, site = _context(actor_id, dest_id, domain)
    with session(dest, store, runner) as _:
        items = bk.site_snapshots(repo_for(dest), site.domain, config_dir=store or STORE)
    return {'snapshots': items, 'databases': _databases(site.domain)}


def restore(actor_id, dest_id, domain, snapshot, kind, include='', database=''):
    _, dest, site = _context(actor_id, dest_id, domain)
    if kind not in ('files', 'db') or not _SNAP.match(snapshot or ''):
        raise BackupError('Invalid restore request.')
    if kind == 'db' and database not in _databases(site.domain):
        raise BackupError('Database %s does not belong to %s.' % (database, site.domain))
    if kind == 'files' and include:
        include = os.path.normpath(include)
        if not include.startswith('/home/%s/' % site.domain):
            raise BackupError('You can only restore paths inside /home/%s.' % site.domain)
    return jobs.spawn('destinations', 'restore_run', {'actor_id': actor_id, 'dest_id': dest.pk, 'domain': site.domain,
                                                      'snapshot': snapshot, 'kind': kind, 'include': include or '',
                                                      'database': database or ''})


def restore_run(job_id, actor_id, dest_id, domain, snapshot, kind, include='', database=''):
    _, dest, site = _context(actor_id, dest_id, domain)
    repo = repo_for(dest)

    def body(job):
        with session(dest):
            item = bk.snapshot_for_site(repo, snapshot, site.domain, kind, database, config_dir=STORE)
            if kind == 'db':
                if database not in _databases(site.domain):
                    raise BackupError('Database %s does not belong to %s.' % (database, site.domain))
                defaults = bk.mysql_defaults_file()
                try:
                    return bk.restore_database(repo, item['full_id'], database, config_dir=STORE,
                                               defaults_file=defaults, log=job.log, hostname=_hostname(),
                                               site=site.domain)
                finally:
                    os.unlink(defaults)
            return bk.restore_files_as_owner(repo, item['full_id'], site.domain, site.externalApp, include or None,
                                             config_dir=STORE, log=job.log, hostname=_hostname())
    return jobs.run_job(job_id, [('Restore %s from %s (%s)' % (site.domain, dest.name, snapshot[:8]), body)])


# ----------------------------------------------------------------------------- schedules

def cron_lines(records, python='/usr/local/CyberCP/bin/python',
               runner_path='/usr/local/CyberCP/universalAddons/runner.py'):
    from universalAddons.privileged import encode_args
    lines = ['# IndiansCloud backup destinations (managed by the panel; edit schedules there)']
    for record in records:
        if not record.enabled or record.schedule not in ('hourly', 'daily', 'weekly'):
            continue
        minute = (record.pk * 7) % 60
        hour = int(record.hour) % 24
        timing = {'hourly': '%d * * * *' % minute, 'daily': '%d %d * * *' % (minute, hour),
                  'weekly': '%d %d * * 0' % (minute, hour)}[record.schedule]
        lines.append('%s root %s %s destinations run_scheduled %s >/dev/null 2>&1' % (
            timing, python, runner_path, encode_args({'job_pk': record.pk})))
    return '\n'.join(lines) + '\n'


def write_cron(cron_file=None):
    _django()
    from universalAddons.models import DestinationBackupJob
    content = cron_lines(DestinationBackupJob.objects.all().order_by('pk'))
    target = cron_file or CRON_FILE
    with open(target + '.tmp', 'w') as handle:
        handle.write(content)
    os.chmod(target + '.tmp', 0o644)
    os.replace(target + '.tmp', target)
    return {'entries': content.count('\n') - 1}


def tool_status():
    code, out = bk.run([RCLONE, 'version'], timeout=30)
    rclone = out.splitlines()[0].strip() if code == 0 and out else ''
    code, out = bk.run([bk.RESTIC, 'version'], timeout=30)
    restic = out.splitlines()[0].strip() if code == 0 and out else ''
    return {'rclone': rclone, 'restic': restic}


ACTIONS = {
    'save_secrets': save_secrets,
    'delete': delete,
    'test': test,
    'usage': usage,
    'backup_now': backup_now,
    'backup_run': backup_run,
    'run_scheduled': run_scheduled,
    'snapshots': snapshots,
    'restore': restore,
    'restore_run': restore_run,
    'write_cron': write_cron,
    'tool_status': tool_status,
    'job': lambda job_id: jobs.status(job_id),
}
