"""Root-side Backup V2 actions (dispatched by universalAddons/runner.py)."""
import os
import socket
import subprocess

from universalAddons import jobs
from universalAddons.backupv2 import service as bk
from universalAddons.backupv2.service import BackupError

CRON_FILE = '/etc/cron.d/cyberpanel-universal-backup'


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
        body = 'To: %s\nSubject: [CyberPanel] Backup policy %s had errors on %s\n\n%s\n' % (
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
            with bk.repo_lock(repo['id']):
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
}
