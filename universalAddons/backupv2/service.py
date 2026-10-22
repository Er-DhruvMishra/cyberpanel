"""Backup V2: encrypted, deduplicated, incremental site backups with restic.

Fixes, by design, the defects found in the official module:
- every repository is encrypted with its own random key (root-only key file);
- one lock per repository, so runs never overlap;
- retention runs after every backup, for every schedule;
- `restic check` verifies the repository after backups (subset of data);
- restores are previewable (dry-run listing), can target another directory, can restore a
  single path or only a database, and a safety snapshot is taken before restoring in place;
- no shell anywhere: argv lists only; the MySQL password goes in a 0600 defaults file;
- repository/policy settings are validated and secrets live only in root-only files.

Units backed up per site (each tagged `site:<domain>` plus the unit tag):
  files  /home/<domain>            tag files
  db     mysqldump of each site DB tag db:<name> (streamed via --stdin, no temp dump on disk)
  mail   /home/vmail/<domain>      tag mail
  config /usr/local/lsws/conf/vhosts/<domain> + acme/letsencrypt certs   tag config
"""
import contextlib
import fcntl
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time

CONFIG_DIR = '/etc/cyberpanel/universal-backup'
LOCK_DIR = '/run/lock'
RESTIC = 'restic'
SSH_KEY = '/root/.ssh/cyberpanel_backup_ed25519'
UNITS = ('files', 'db', 'mail', 'config')
SCHEDULES = ('hourly', 'daily', 'weekly', 'manual')

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,31}$')
HOST_RE = re.compile(r'^[A-Za-z0-9.-]{1,253}$')
USER_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
PATH_RE = re.compile(r'^/[A-Za-z0-9._/ -]{0,1023}$')
DBNAME_RE = re.compile(r'^[A-Za-z0-9_]{1,64}$')
SNAP_RE = re.compile(r'^[0-9a-f]{8,64}$')
BUCKET_RE = re.compile(r'^[a-z0-9][a-z0-9.-]{1,62}$')
REMOTE_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
SITES_ROOT = '/home'
FORBIDDEN_LOCAL = ('/proc', '/sys', '/dev', '/boot', '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64')


class BackupError(ValueError):
    pass


# ----------------------------------------------------------------------------- storage

def _path(*parts, config_dir=None):
    return os.path.join(config_dir or CONFIG_DIR, *parts)


def _load(name, config_dir=None):
    try:
        with open(_path(name, config_dir=config_dir)) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _save(name, data, config_dir=None):
    directory = config_dir or CONFIG_DIR
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary = _path(name + '.tmp', config_dir=config_dir)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(temporary, _path(name, config_dir=config_dir))


def _write_secret(path, content):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(content)


# ----------------------------------------------------------------------------- repositories

def validate_repo(spec):
    if not isinstance(spec, dict):
        raise BackupError('Invalid repository.')
    repo_id = str(spec.get('id', '')).strip().lower()
    if not ID_RE.match(repo_id):
        raise BackupError('Repository id: lowercase letters, digits and dashes.')
    kind = spec.get('type')
    clean = {'id': repo_id, 'type': kind, 'name': str(spec.get('name') or repo_id)[:80]}
    if kind == 'local':
        path = os.path.normpath(str(spec.get('path', '')))
        if not PATH_RE.match(path) or any(path == p or path.startswith(p + '/') for p in FORBIDDEN_LOCAL) \
                or path in ('/', '/home', '/root'):
            raise BackupError('Choose a dedicated local directory, e.g. /backup/restic.')
        clean['path'] = path
    elif kind == 'sftp':
        host, user, path = str(spec.get('host', '')), str(spec.get('user', '')), str(spec.get('path', ''))
        try:
            port = int(spec.get('port', 22))
        except (TypeError, ValueError):
            raise BackupError('Invalid SSH port.')
        if not HOST_RE.match(host) or not USER_RE.match(user) or not PATH_RE.match(path) or not 0 < port < 65536:
            raise BackupError('Enter a valid SFTP host, user, port and absolute path.')
        clean.update(host=host, user=user, port=port, path=path)
    elif kind == 's3':
        endpoint = str(spec.get('endpoint', 's3.amazonaws.com')).strip()
        endpoint = re.sub(r'^https?://', '', endpoint).rstrip('/')
        bucket, prefix = str(spec.get('bucket', '')), str(spec.get('prefix', '')).strip('/')
        if not HOST_RE.match(endpoint) or not BUCKET_RE.match(bucket) or (prefix and not re.match(r'^[A-Za-z0-9._/-]{1,200}$', prefix)):
            raise BackupError('Enter a valid S3 endpoint, bucket and optional prefix.')
        clean.update(endpoint=endpoint, bucket=bucket, prefix=prefix,
                     region=re.sub(r'[^a-z0-9-]', '', str(spec.get('region', '')).lower())[:32])
    elif kind == 'rclone':
        remote, path = str(spec.get('remote', '')), str(spec.get('path', '')).strip('/')
        if not REMOTE_RE.match(remote) or (path and not re.match(r'^[A-Za-z0-9._/ -]{1,200}$', path)):
            raise BackupError('Enter an rclone remote name (from `rclone config`) and a path.')
        clean.update(remote=remote, path=path)
    else:
        raise BackupError('Repository type must be local, sftp, s3 or rclone.')
    return clean


def repository_url(repo):
    kind = repo['type']
    if kind == 'local':
        return repo['path']
    if kind == 'sftp':
        return 'sftp:%s@%s:%s' % (repo['user'], repo['host'], repo['path'])
    if kind == 's3':
        return 's3:https://%s/%s%s' % (repo['endpoint'], repo['bucket'], '/' + repo['prefix'] if repo['prefix'] else '')
    return 'rclone:%s:%s' % (repo['remote'], repo['path'])


def restic_base(repo, config_dir=None):
    """(argv prefix, env) for running restic against repo."""
    env = dict(os.environ, RESTIC_REPOSITORY=repository_url(repo),
               RESTIC_PASSWORD_FILE=_path('keys', repo['id'] + '.key', config_dir=config_dir),
               RESTIC_CACHE_DIR='/var/cache/restic')
    secrets_ = _load(os.path.join('env', repo['id'] + '.json'), config_dir)
    env.update({k: v for k, v in secrets_.items() if k in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY')})
    if repo.get('region'):
        env['AWS_DEFAULT_REGION'] = repo['region']
    argv = [RESTIC]
    if repo['type'] == 'sftp':
        argv += ['-o', 'sftp.command=ssh %s@%s -p %d -i %s -o BatchMode=yes -o StrictHostKeyChecking=accept-new -s sftp'
                 % (repo['user'], repo['host'], repo['port'], SSH_KEY)]
    return argv, env


def save_repo(spec, access_key='', secret_key='', config_dir=None):
    repo = validate_repo(spec)
    repos = _load('repos.json', config_dir)
    key_path = _path('keys', repo['id'] + '.key', config_dir=config_dir)
    if not os.path.exists(key_path):
        _write_secret(key_path, secrets.token_urlsafe(48) + '\n')
    if repo['type'] == 's3':
        existing = _load(os.path.join('env', repo['id'] + '.json'), config_dir)
        access_key = access_key or existing.get('AWS_ACCESS_KEY_ID', '')
        secret_key = secret_key or existing.get('AWS_SECRET_ACCESS_KEY', '')
        if not re.match(r'^[A-Za-z0-9]{8,128}$', access_key) or not re.match(r'^[A-Za-z0-9/+=]{8,256}$', secret_key):
            raise BackupError('Enter the S3 access key and secret key.')
        os.makedirs(_path('env', config_dir=config_dir), mode=0o700, exist_ok=True)
        _save(os.path.join('env', repo['id'] + '.json'),
              {'AWS_ACCESS_KEY_ID': access_key, 'AWS_SECRET_ACCESS_KEY': secret_key}, config_dir)
    repos[repo['id']] = repo
    _save('repos.json', repos, config_dir)
    return repo


def get_repo(repo_id, config_dir=None):
    repo = _load('repos.json', config_dir).get(repo_id)
    if not repo:
        raise BackupError('Unknown repository %r.' % repo_id)
    return repo


def list_repos(config_dir=None):
    return sorted(_load('repos.json', config_dir).values(), key=lambda r: r['id'])


def export_key(repo_id, config_dir=None):
    """The repository password. Without it the backups cannot be restored on a new server."""
    get_repo(repo_id, config_dir)
    with open(_path('keys', repo_id + '.key', config_dir=config_dir)) as handle:
        return handle.read().strip()


# ----------------------------------------------------------------------------- running restic

def run(argv, env=None, runner=subprocess.run, timeout=24 * 3600, stdin=None, input=None):
    try:
        out = runner(argv, env=env, stdin=stdin, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     universal_newlines=input is not None or stdin is None, timeout=timeout)
    except FileNotFoundError:
        return 127, '%s is not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s timed out' % argv[0]
    output = out.stdout if isinstance(out.stdout, str) else (out.stdout or b'').decode('utf-8', 'replace')
    return out.returncode, output or ''


@contextlib.contextmanager
def repo_lock(repo_id, lock_dir=None):
    os.makedirs(lock_dir or LOCK_DIR, exist_ok=True)
    handle = open(os.path.join(lock_dir or LOCK_DIR, 'cp-ua-backup-%s.lock' % repo_id), 'w')
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError('Another backup or restore is running on repository %s.' % repo_id)
        yield
    finally:
        handle.close()


def init_repo(repo, runner=subprocess.run, config_dir=None):
    argv, env = restic_base(repo, config_dir)
    code, out = run(argv + ['cat', 'config'], env, runner, timeout=300)
    if code == 0:
        return {'initialised': False, 'detail': 'Repository already exists.'}
    code, out = run(argv + ['init'], env, runner, timeout=600)
    if code != 0:
        raise BackupError('restic init failed: ' + out.strip()[-1500:])
    return {'initialised': True, 'detail': out.strip()[-500:]}


def mysql_defaults_file(password_file='/etc/cyberpanel/mysqlPassword'):
    """Write a private my.cnf-style file with the panel's MySQL root credentials; caller deletes it."""
    with open(password_file) as handle:
        raw = handle.read()
    try:
        data = json.loads(raw)
        user, password = data['mysqluser'], data['mysqlpassword']
        host, port = data.get('mysqlhost', 'localhost'), str(data.get('mysqlport', '3306'))
    except (ValueError, KeyError, TypeError):
        user, password, host, port = 'root', raw.split('\n', 1)[0], 'localhost', '3306'
    fd, path = tempfile.mkstemp(prefix='cp-ua-my-', suffix='.cnf')
    with os.fdopen(fd, 'w') as handle:
        handle.write('[client]\nuser=%s\npassword="%s"\nhost=%s\nport=%s\n' % (
            user, password.replace('\\', '\\\\').replace('"', '\\"'), host, port))
    os.chmod(path, 0o600)
    return path


def unit_sources(domain, unit):
    if unit == 'files':
        return [os.path.join(SITES_ROOT, domain)]
    if unit == 'mail':
        return ['/home/vmail/%s' % domain]
    if unit == 'config':
        return ['/usr/local/lsws/conf/vhosts/%s' % domain, '/etc/letsencrypt/live/%s' % domain]
    return []


def backup_site(repo, domain, units, databases, hostname, runner=subprocess.run, log=None, config_dir=None,
                defaults_file=None, popen=subprocess.Popen):
    """Back up one site into repo. Returns per-unit results; raises on the first hard failure."""
    if not DOMAIN_RE.match(domain):
        raise BackupError('Invalid domain %r.' % domain)
    argv, env = restic_base(repo, config_dir)
    base_tags = ['--tag', 'site:%s' % domain, '--host', hostname]
    results = {}
    for unit in units:
        if unit not in UNITS:
            raise BackupError('Unknown unit %r.' % unit)
        if unit == 'db':
            for name in databases:
                if not DBNAME_RE.match(name):
                    raise BackupError('Invalid database name %r.' % name)
                results['db:' + name] = _backup_database(argv, env, base_tags, name, defaults_file, popen, log)
            continue
        sources = [path for path in unit_sources(domain, unit) if os.path.exists(path)]
        if not sources:
            results[unit] = 'skipped (nothing to back up)'
            continue
        home = os.path.join(SITES_ROOT, domain)
        excludes = ['--exclude', home + '/backup', '--exclude', home + '/.cache',
                    '--exclude-caches'] if unit == 'files' else []
        code, out = run(argv + ['backup', '--json', '--tag', unit] + base_tags + excludes + sources, env, runner)
        if log:
            log('%s %s: exit %d' % (domain, unit, code))
        if code not in (0, 3):  # 3 = some files unreadable, snapshot still created
            raise BackupError('%s backup of %s failed: %s' % (unit, domain, _last_error(out)))
        results[unit] = _summary(out) + (' (some files could not be read)' if code == 3 else '')
    return results


def _backup_database(argv, env, base_tags, name, defaults_file, popen, log):
    dump = popen(['mysqldump', '--defaults-extra-file=' + defaults_file, '--single-transaction', '--quick',
                  '--routines', '--triggers', '--events', '--hex-blob', name],
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    backup = popen(argv + ['backup', '--json', '--stdin', '--stdin-filename', 'db/%s.sql' % name,
                           '--tag', 'db', '--tag', 'db:%s' % name] + base_tags,
                   stdin=dump.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    dump.stdout.close()
    out, _ = backup.communicate()
    dump_error = dump.stderr.read().decode('utf-8', 'replace')
    dump.wait()
    if log:
        log('database %s: dump exit %d, restic exit %d' % (name, dump.returncode, backup.returncode))
    if dump.returncode != 0:
        raise BackupError('mysqldump of %s failed: %s' % (name, dump_error.strip()[-500:]))
    if backup.returncode != 0:
        raise BackupError('restic could not store %s: %s' % (name, _last_error(out.decode('utf-8', 'replace'))))
    return _summary(out.decode('utf-8', 'replace'))


def _summary(output):
    for line in reversed(output.splitlines()):
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if data.get('message_type') == 'summary':
            return 'snapshot %s, %d new files, %s added' % (data.get('snapshot_id', '')[:8], data.get('files_new', 0),
                                                            human(data.get('data_added', 0)))
    return 'done'


def _last_error(output):
    lines = [l for l in output.splitlines() if l.strip() and not l.startswith('{')]
    return (lines[-1] if lines else output.strip())[-500:]


def human(size):
    size = float(size or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size < 1024 or unit == 'TB':
            return ('%d %s' if unit == 'B' else '%.1f %s') % (size, unit)
        size /= 1024


def retention_args(policy):
    keep = policy.get('keep', {})
    args = []
    for key, flag in (('last', '--keep-last'), ('hourly', '--keep-hourly'), ('daily', '--keep-daily'),
                      ('weekly', '--keep-weekly'), ('monthly', '--keep-monthly')):
        value = keep.get(key)
        if value:
            args += [flag, str(int(value))]
    return args or ['--keep-last', '7']


def apply_retention(repo, domain, policy, runner=subprocess.run, config_dir=None):
    argv, env = restic_base(repo, config_dir)
    code, out = run(argv + ['forget', '--prune', '--group-by', 'host,tags', '--tag', 'site:%s' % domain]
                    + retention_args(policy), env, runner)
    if code != 0:
        raise BackupError('Retention failed for %s: %s' % (domain, _last_error(out)))
    return 'retention applied'


def check_repo(repo, runner=subprocess.run, config_dir=None, subset='2%'):
    argv, env = restic_base(repo, config_dir)
    code, out = run(argv + ['check', '--read-data-subset=%s' % subset], env, runner)
    return {'ok': code == 0, 'output': out.strip()[-3000:]}


# ----------------------------------------------------------------------------- policies

def validate_policy(spec, repos):
    if not isinstance(spec, dict):
        raise BackupError('Invalid policy.')
    policy_id = str(spec.get('id', '')).strip().lower()
    if not ID_RE.match(policy_id):
        raise BackupError('Policy id: lowercase letters, digits and dashes.')
    if spec.get('repo') not in repos:
        raise BackupError('Choose a repository.')
    sites = spec.get('sites', 'all')
    if sites != 'all':
        if not isinstance(sites, list) or not sites or not all(isinstance(s, str) and DOMAIN_RE.match(s) for s in sites):
            raise BackupError('Choose "all" sites or a list of domains.')
    units = spec.get('units', list(UNITS))
    if not isinstance(units, list) or not units or any(u not in UNITS for u in units):
        raise BackupError('Choose what to back up: files, db, mail, config.')
    schedule = spec.get('schedule', 'daily')
    if schedule not in SCHEDULES:
        raise BackupError('Schedule must be hourly, daily, weekly or manual.')
    try:
        hour = int(spec.get('hour', 2))
        keep = {k: int(v) for k, v in (spec.get('keep') or {}).items() if k in ('last', 'hourly', 'daily', 'weekly', 'monthly')}
    except (TypeError, ValueError):
        raise BackupError('Hour and retention values must be numbers.')
    if not 0 <= hour <= 23 or any(not 0 <= v <= 1000 for v in keep.values()):
        raise BackupError('Hour must be 0-23 and retention values 0-1000.')
    return {'id': policy_id, 'repo': spec['repo'], 'sites': sites if sites == 'all' else sorted(set(sites)),
            'units': [u for u in UNITS if u in units], 'schedule': schedule, 'hour': hour,
            'keep': keep or {'daily': 7, 'weekly': 4, 'monthly': 6}, 'check': spec.get('check', True) is not False,
            'notify': spec.get('notify', True) is not False}


def cron_lines(policies, python='/usr/local/CyberCP/bin/python',
               runner_path='/usr/local/CyberCP/universalAddons/runner.py'):
    from universalAddons.privileged import encode_args
    lines = ['# CyberPanel Universal Backup V2 (managed; edit in the panel)']
    for policy in policies:
        minute = sum(ord(c) for c in policy['id']) % 60  # spread start times
        timing = {'hourly': '%d * * * *' % minute, 'daily': '%d %d * * *' % (minute, policy['hour']),
                  'weekly': '%d %d * * 0' % (minute, policy['hour'])}.get(policy['schedule'])
        if timing:
            lines.append('%s root %s %s backupv2 run_policy %s >/dev/null 2>&1' % (
                timing, python, runner_path, encode_args({'policy_id': policy['id']})))
    return '\n'.join(lines) + '\n'


# ----------------------------------------------------------------------------- snapshots & restore

def snapshots(repo, domain=None, runner=subprocess.run, config_dir=None):
    argv, env = restic_base(repo, config_dir)
    command = argv + ['snapshots', '--json']
    if domain:
        if not DOMAIN_RE.match(domain):
            raise BackupError('Invalid domain.')
        command += ['--tag', 'site:%s' % domain]
    code, out = run(command, env, runner, timeout=600)
    if code != 0:
        raise BackupError('Could not list snapshots: ' + _last_error(out))
    try:
        items = json.loads(out[out.index('['):]) if '[' in out else []
    except ValueError:
        raise BackupError('Unexpected restic output.')
    result = []
    for item in items:
        tags = item.get('tags') or []
        site = next((t[5:] for t in tags if t.startswith('site:')), '')
        unit = next((t for t in tags if t in UNITS), '')
        database = next((t[3:] for t in tags if t.startswith('db:')), '')
        result.append({'id': item.get('short_id') or item.get('id', '')[:8], 'full_id': item.get('id', ''),
                       'time': item.get('time', '')[:19], 'site': site, 'unit': unit, 'database': database,
                       'paths': item.get('paths', []), 'tags': tags})
    return sorted(result, key=lambda s: s['time'], reverse=True)


def list_files(repo, snapshot, path='/', runner=subprocess.run, config_dir=None, limit=2000):
    if not SNAP_RE.match(snapshot or ''):
        raise BackupError('Invalid snapshot id.')
    if not PATH_RE.match(path or '/'):
        raise BackupError('Invalid path.')
    argv, env = restic_base(repo, config_dir)
    code, out = run(argv + ['ls', '--json', snapshot, path or '/'], env, runner, timeout=600)
    if code != 0:
        raise BackupError('Could not list snapshot: ' + _last_error(out))
    entries = []
    for line in out.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get('struct_type') == 'node':
            entries.append({'path': item.get('path'), 'type': item.get('type'), 'size': item.get('size', 0)})
            if len(entries) >= limit:
                break
    return entries


def restore_files(repo, snapshot, domain, target='original', include=None, runner=subprocess.run, config_dir=None,
                  log=None, hostname='localhost'):
    """Restore files from a snapshot. In-place restores take a safety snapshot first."""
    if not SNAP_RE.match(snapshot or ''):
        raise BackupError('Invalid snapshot id.')
    if include and not PATH_RE.match(include):
        raise BackupError('Invalid path to restore.')
    argv, env = restic_base(repo, config_dir)
    if target == 'original':
        destination = '/'
        if include:
            sources = [include] if os.path.exists(include) else []
        else:
            sources = [p for p in unit_sources(domain, 'files') if os.path.exists(p)]
        if sources:
            code, out = run(argv + ['backup', '--json', '--tag', 'pre-restore', '--tag', 'site:%s' % domain,
                                    '--host', hostname] + sources, env, runner)
            if code not in (0, 3):
                raise BackupError('Safety snapshot failed, restore not started: ' + _last_error(out))
            if log:
                log('safety snapshot: ' + _summary(out))
    else:
        destination = os.path.normpath(str(target))
        if not PATH_RE.match(destination) or destination in ('/', '/home') or \
                any(destination == p or destination.startswith(p + '/') for p in FORBIDDEN_LOCAL):
            raise BackupError('Choose an empty restore directory such as /home/restore-%s.' % domain)
        os.makedirs(destination, mode=0o700, exist_ok=True)
    command = argv + ['restore', snapshot, '--target', destination]
    if include:
        command += ['--include', include]
    code, out = run(command, env, runner)
    if code != 0:
        raise BackupError('Restore failed: ' + _last_error(out))
    if target == 'original' and os.path.isdir(os.path.join(SITES_ROOT, domain)):
        _fix_ownership(domain, include)
    return {'restored_to': destination, 'path': include or '(whole snapshot)'}


def _fix_ownership(domain, include=None):
    """Restic restores numeric owners; re-assert the site owner on the site's files."""
    import pwd
    home = os.path.join(SITES_ROOT, domain)
    try:
        owner = os.stat(home)
        pwd.getpwuid(owner.st_uid)
    except (OSError, KeyError):
        return
    subprocess.call(['chown', '-R', '--no-dereference', '%d:%d' % (owner.st_uid, owner.st_gid),
                     include if include and include.startswith(home + '/') else os.path.join(home, 'public_html')],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def restore_database(repo, snapshot, database, runner=subprocess.run, config_dir=None, defaults_file=None,
                     popen=subprocess.Popen, log=None, hostname='localhost', site=''):
    """Replace a database with its dump from snapshot, after dumping the current one to the repo."""
    if not SNAP_RE.match(snapshot or '') or not DBNAME_RE.match(database or ''):
        raise BackupError('Invalid snapshot or database.')
    argv, env = restic_base(repo, config_dir)
    tags = ['--tag', 'site:%s' % site] if site else []
    _backup_database(argv, env, tags + ['--tag', 'pre-restore', '--host', hostname], database, defaults_file,
                     popen, log)
    dump = popen(argv + ['dump', snapshot, '/db/%s.sql' % database], stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, env=env)
    load = popen(['mysql', '--defaults-extra-file=' + defaults_file, database], stdin=dump.stdout,
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    dump.stdout.close()
    out, _ = load.communicate()
    dump_error = dump.stderr.read().decode('utf-8', 'replace')
    dump.wait()
    if dump.returncode != 0:
        raise BackupError('Could not read the dump from the snapshot: ' + dump_error.strip()[-500:])
    if load.returncode != 0:
        raise BackupError('MySQL import failed (a pre-restore copy was saved): ' +
                          out.decode('utf-8', 'replace').strip()[-500:])
    return {'database': database, 'restored_from': snapshot}


def ssh_public_key(key_path=None, runner=subprocess.run):
    """Create (once) and return the SSH public key used for SFTP repositories."""
    key_path = key_path or SSH_KEY
    if not os.path.exists(key_path):
        os.makedirs(os.path.dirname(key_path), mode=0o700, exist_ok=True)
        code, out = run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'cyberpanel-backup', '-f', key_path],
                        runner=runner, timeout=60)
        if code != 0:
            raise BackupError('ssh-keygen failed: ' + out)
    with open(key_path + '.pub') as handle:
        return handle.read().strip()
