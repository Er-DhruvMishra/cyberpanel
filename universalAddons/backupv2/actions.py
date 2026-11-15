"""Root-side Backup V2 actions (dispatched by universalAddons/runner.py)."""
import os
import socket
import subprocess
import time

from universalAddons import jobs
from universalAddons.backupv2 import service as bk
from universalAddons.backupv2.service import BackupError

CRON_FILE = '/etc/cron.d/cyberpanel-universal-backup'
USER_RUN_INTERVAL = 15 * 60   # a site owner may start one backup of a site per 15 minutes


def _django():
    from universalAddons import django_env
    django_env.setup()


def _sites():
    _django()
    from websiteFunctions.models import Websites
    return sorted(d.lower() for d in Websites.objects.values_list('domain', flat=True))


def _databases(domain):
    _django()
    from databases.models import Databases
    return sorted(Databases.objects.filter(website__domain=domain).values_list('dbName', flat=True))


def _site_user(domain):
    _django()
    from websiteFunctions.models import Websites
    return Websites.objects.get(domain=domain).externalApp


def _hostname():
    return socket.getfqdn() or 'localhost'


def overview():
    policies = sorted(bk._load('policies.json').values(), key=lambda p: p['id'])
    return {'repos': bk.list_repos(), 'policies': policies, 'sites': _sites(),
            'cron': os.path.exists(CRON_FILE)}


def save_repo(spec, access_key='', secret_key=''):
    repo = bk.save_repo(spec, access_key, secret_key)
    return {'repo': repo, 'init': bk.init_repo(repo)}


def save_policy(spec):
    repos = bk._load('repos.json')
    policy = bk.validate_policy(spec, repos)
    policies = bk._load('policies.json')
    policies[policy['id']] = policy
    bk._save('policies.json', policies)
    _write_cron(policies)
    return policy


def delete_policy(policy_id):
    policies = bk._load('policies.json')
    if policy_id not in policies:
        raise BackupError('Unknown policy.')
    del policies[policy_id]
    bk._save('policies.json', policies)
    _write_cron(policies)
    return {'deleted': policy_id}


def _write_cron(policies):
    content = bk.cron_lines(sorted(policies.values(), key=lambda p: p['id']))
    with open(CRON_FILE + '.tmp', 'w') as handle:
        handle.write(content)
    os.chmod(CRON_FILE + '.tmp', 0o644)
    os.replace(CRON_FILE + '.tmp', CRON_FILE)


def _notify_failure(policy_id, errors):
    try:
        _django()
        from loginSystem.models import Administrator
        recipients = [a.email for a in Administrator.objects.filter(acl__adminStatus=1) if a.email] or ['root']
        body = 'To: %s\nSubject: [IndiansCloud] Backup policy %s had errors on %s\n\n%s\n' % (
            ', '.join(recipients), policy_id, _hostname(), '\n'.join(errors))
        subprocess.run(['sendmail', '--'] + recipients, input=body, universal_newlines=True, timeout=60)
    except Exception:
        pass


def run_policy(policy_id, job_id=None):
    """Run a policy now (from cron directly, or as a panel job)."""
    if job_id is None:
        job_id = os.urandom(12).hex()
        os.makedirs(jobs.JOB_DIR, mode=0o700, exist_ok=True)
    policy = bk._load('policies.json').get(policy_id)
    if not policy:
        raise BackupError('Unknown policy.')
    repo = bk.get_repo(policy['repo'])
    sites = _sites() if policy['sites'] == 'all' else policy['sites']
    errors = []

    def body(job):
        defaults = bk.mysql_defaults_file() if 'db' in policy['units'] else None
        try:
            with bk.repo_lock(repo['id'], wait=2 * 3600):
                for domain in sites:
                    try:
                        result = bk.backup_site(repo, domain, policy['units'],
                                                _databases(domain) if 'db' in policy['units'] else [],
                                                _hostname(), log=job.log, defaults_file=defaults)
                        job.log('%s: %s' % (domain, '; '.join('%s %s' % kv for kv in result.items())))
                        job.log('%s: %s' % (domain, bk.apply_retention(repo, domain, policy)))
                    except BackupError as exc:
                        errors.append('%s: %s' % (domain, exc))
                        job.log('ERROR %s: %s' % (domain, exc))
                if policy.get('check'):
                    check = bk.check_repo(repo)
                    job.log('repository check: %s' % ('ok' if check['ok'] else 'FAILED\n' + check['output']))
                    if not check['ok']:
                        errors.append('repository check failed')
        finally:
            if defaults:
                os.unlink(defaults)
        if errors:
            if policy.get('notify'):
                _notify_failure(policy_id, errors)
            raise BackupError('%d problem(s): %s' % (len(errors), '; '.join(errors)[:1500]))
        return {'sites': len(sites)}

    return jobs.run_job(job_id, [('Back up %d site(s) to %s' % (len(sites), repo['id']), body)])


def restore_run(job_id, repo_id, snapshot, domain, kind, target='original', include='', database=''):
    repo = bk.get_repo(repo_id)

    def body(job):
        with bk.repo_lock(repo_id):
            if kind == 'db':
                if database not in _databases(domain):
                    raise BackupError('Database %s does not belong to %s.' % (database, domain))
                defaults = bk.mysql_defaults_file()
                try:
                    return bk.restore_database(repo, snapshot, database, defaults_file=defaults, log=job.log,
                                               hostname=_hostname(), site=domain)
                finally:
                    os.unlink(defaults)
            return bk.restore_files(repo, snapshot, domain, target, include or None, log=job.log,
                                    hostname=_hostname())

    return jobs.run_job(job_id, [('Restore %s from %s' % (domain, snapshot), body)])


def restore(repo_id, snapshot, domain, kind, target='original', include='', database=''):
    if kind not in ('files', 'db') or not bk.DOMAIN_RE.match(domain or '') or not bk.SNAP_RE.match(snapshot or ''):
        raise BackupError('Invalid restore request.')
    if domain not in _sites():
        raise BackupError('Unknown site.')
    bk.get_repo(repo_id)
    return jobs.spawn('backupv2', 'restore_run', {'repo_id': repo_id, 'snapshot': snapshot, 'domain': domain,
                                                   'kind': kind, 'target': target, 'include': include,
                                                   'database': database})


def check_run(job_id, repo_id):
    repo = bk.get_repo(repo_id)

    def body(job):
        with bk.repo_lock(repo_id):
            result = bk.check_repo(repo, subset='10%')
        job.log(result['output'])
        if not result['ok']:
            raise BackupError('Repository check failed.')
        return {'ok': True}
    return jobs.run_job(job_id, [('Verify repository %s (10%% of data)' % repo_id, body)])


# ----------------------------------------------------------------------------- site owners
# The web layer has already checked that the caller owns `domain`; these re-check everything else:
# the repository must be open to users, and every snapshot must be the site's own.

def _user_repo(repo_id):
    repo = bk._load('repos.json').get(repo_id)
    if not repo or not repo.get('for_users'):
        raise BackupError('Unknown repository.')
    return repo


def _user_site(domain):
    domain = (domain or '').strip().lower()
    if not bk.DOMAIN_RE.match(domain) or domain not in _sites():
        raise BackupError('Unknown site.')
    return domain


def user_overview(domains):
    wanted = {str(d).lower() for d in domains or ()}
    return {'repos': [{'id': r['id'], 'name': r.get('name') or r['id']} for r in bk.list_repos() if r.get('for_users')],
            'sites': [d for d in _sites() if d in wanted], 'keep_last': bk.USER_KEEP_LAST}


def user_snapshots(repo_id, domain):
    return {'snapshots': bk.site_snapshots(_user_repo(repo_id), _user_site(domain))}


def user_ls(repo_id, domain, snapshot, path='/'):
    repo, domain = _user_repo(repo_id), _user_site(domain)
    item = bk.snapshot_for_site(repo, snapshot, domain, 'files')
    return {'entries': bk.list_files(repo, item['full_id'], path)}


def user_backup(repo_id, domain):
    repo, domain = _user_repo(repo_id), _user_site(domain)
    runs = bk._load('user-runs.json')
    last = runs.get(domain, 0) if isinstance(runs.get(domain, 0), (int, float)) else 0
    wait = int(last + USER_RUN_INTERVAL - time.time())
    if wait > 0:
        raise BackupError('A backup of %s was started recently; try again in %d minute(s).' % (domain, wait // 60 + 1))
    runs = {d: t for d, t in runs.items() if isinstance(t, (int, float)) and t > time.time() - 86400}
    runs[domain] = int(time.time())
    bk._save('user-runs.json', runs)
    return jobs.spawn('backupv2', 'user_backup_run', {'repo_id': repo['id'], 'domain': domain})


def user_backup_run(job_id, repo_id, domain):
    repo, domain = _user_repo(repo_id), _user_site(domain)

    def body(job):
        databases = _databases(domain)
        defaults = bk.mysql_defaults_file() if databases else None
        try:
            with bk.repo_lock(repo['id']):
                result = bk.backup_site(repo, domain, ['files', 'db'], databases, _hostname(), log=job.log,
                                        defaults_file=defaults, extra_tags=[bk.USER_TAG])
                job.log('%s: %s' % (domain, '; '.join('%s %s' % kv for kv in result.items())))
                job.log(bk.owner_retention(repo, domain))
        finally:
            if defaults:
                os.unlink(defaults)
        return result

    return jobs.run_job(job_id, [('Back up %s to %s' % (domain, repo['id']), body)])


def user_restore(repo_id, snapshot, domain, kind, include='', database=''):
    """Start an in-place restore of the site's own snapshot (files, or one of its databases)."""
    repo, domain = _user_repo(repo_id), _user_site(domain)
    if kind not in ('files', 'db'):
        raise BackupError('Invalid restore request.')
    if kind == 'db' and database not in _databases(domain):
        raise BackupError('Database %s does not belong to %s.' % (database, domain))
    item = bk.snapshot_for_site(repo, snapshot, domain, kind, database)
    return jobs.spawn('backupv2', 'user_restore_run', {'repo_id': repo['id'], 'snapshot': item['full_id'],
                                                        'domain': domain, 'kind': kind, 'include': include or '',
                                                        'database': database or ''})


def user_restore_run(job_id, repo_id, snapshot, domain, kind, include='', database=''):
    repo, domain = _user_repo(repo_id), _user_site(domain)

    def body(job):
        with bk.repo_lock(repo['id']):
            item = bk.snapshot_for_site(repo, snapshot, domain, kind, database)  # re-check under the lock
            if kind == 'db':
                if database not in _databases(domain):
                    raise BackupError('Database %s does not belong to %s.' % (database, domain))
                defaults = bk.mysql_defaults_file()
                try:
                    return bk.restore_database(repo, item['full_id'], database, defaults_file=defaults, log=job.log,
                                               hostname=_hostname(), site=domain)
                finally:
                    os.unlink(defaults)
            return bk.restore_files_as_owner(repo, item['full_id'], domain, _site_user(domain), include or None,
                                             log=job.log, hostname=_hostname())

    return jobs.run_job(job_id, [('Restore %s from %s' % (domain, snapshot[:8]), body)])


ACTIONS = {
    'overview': overview,
    'save_repo': save_repo,
    'export_key': lambda repo_id: {'key': bk.export_key(repo_id)},
    'ssh_key': lambda: {'public_key': bk.ssh_public_key()},
    'save_policy': save_policy,
    'delete_policy': delete_policy,
    'run_policy': run_policy,
    'run_now': lambda policy_id: jobs.spawn('backupv2', 'run_policy', {'policy_id': policy_id}),
    'snapshots': lambda repo_id, domain='': {'snapshots': bk.snapshots(bk.get_repo(repo_id), domain or None)},
    'ls': lambda repo_id, snapshot, path='/': {'entries': bk.list_files(bk.get_repo(repo_id), snapshot, path)},
    'restore': restore,
    'restore_run': restore_run,
    'check': lambda repo_id: jobs.spawn('backupv2', 'check_run', {'repo_id': repo_id}),
    'check_run': check_run,
    'job': lambda job_id: jobs.status(job_id),
    'user_overview': user_overview,
    'user_snapshots': user_snapshots,
    'user_ls': user_ls,
    'user_backup': user_backup,
    'user_backup_run': user_backup_run,
    'user_restore': user_restore,
    'user_restore_run': user_restore_run,
}
