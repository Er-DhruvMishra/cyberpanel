"""Microsoft SQL Server (Express edition) with per-site databases.

Footprint and safety choices
- Express edition (free; 10 GB per database, Microsoft's smallest server edition), with the
  memory cap set at install time (default 1 GB) so it cannot starve the web stack.
- Listens on 127.0.0.1 only. Apps on the server connect locally; nothing is exposed.
- Installation requires the administrator to accept Microsoft's licence terms explicitly.
- Preflight refuses hosts below Microsoft's minimums (2 GB RAM, 6 GB disk, x86-64).
- The sa password is random, stored root-only, and never shown in the panel.
- Each database gets its own login that owns only that database and cannot see other
  databases (DENY VIEW ANY DATABASE). Ownership is recorded per site and checked on every
  action.
- Passwords and SQL never appear on a command line: sqlcmd reads the password from the
  SQLCMDPASSWORD environment variable and SQL from a private temporary file.
"""
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import tempfile

STATE_DIR = '/etc/cyberpanel/mssql'
SQLCMD = '/opt/mssql-tools18/bin/sqlcmd'
MSSQL_CONF = '/opt/mssql/bin/mssql-conf'
DATA_DIR = '/var/opt/mssql'
MIN_RAM_MB = 2000
MIN_DISK_MB = 6144
EULA_URL = 'https://go.microsoft.com/fwlink/?LinkId=2104078'

NAME_RE = re.compile(r'^[a-z][a-z0-9_]{1,30}$')
DB_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]{1,63}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


class SQLError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=600, env=None):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=env)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- platform

def repo_for(family, version):
    """(kind, url, product) of Microsoft's package repository for an OS profile."""
    version = int(version)
    if family == 'rhel':
        if version == 8:
            return 'rpm', 'https://packages.microsoft.com/config/rhel/8/mssql-server-2022.repo', '2022'
        if version in (9, 10):
            return 'rpm', 'https://packages.microsoft.com/config/rhel/%d/mssql-server-2025.repo' % version, '2025'
    if family == 'debian':
        if version in (20, 22):
            return 'deb', 'https://packages.microsoft.com/config/ubuntu/%d.04/mssql-server-2022.list' % version, '2022'
        if version == 24:
            return 'deb', 'https://packages.microsoft.com/config/ubuntu/24.04/mssql-server-2025.list', '2025'
    raise SQLError('Microsoft does not publish SQL Server for this operating system.')


def tools_repo_for(family, version):
    version = int(version)
    if family == 'rhel':
        return 'https://packages.microsoft.com/config/rhel/%d/prod.repo' % version
    return 'https://packages.microsoft.com/config/ubuntu/%d.04/prod.list' % version


TOOLS_REPO_ID = 'cp-microsoft-prod'
TOOLS_REPO_FILE = '/etc/yum.repos.d/cp-microsoft-prod.repo'


def tools_repo_text(version):
    return ('[%s]\nname=Microsoft production packages for RHEL %d (CyberPanel)\n'
            'baseurl=https://packages.microsoft.com/rhel/%d/prod/\nenabled=1\ngpgcheck=1\n'
            'gpgkey=https://packages.microsoft.com/keys/microsoft.asc\n' % (TOOLS_REPO_ID, int(version), int(version)))


def write_tools_repo(version, path=TOOLS_REPO_FILE):
    with open(path + '.tmp', 'w') as handle:
        handle.write(tools_repo_text(version))
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)


PROTECT_DROPIN = '/etc/systemd/system/mssql-server.service.d/cyberpanel-memory.conf'


def protect_dropin_text(memory_limit_mb, unified=None):
    """systemd drop-in so SQL Server, not MariaDB or the web stack, gives way when RAM runs out.

    OOMScoreAdjust makes the kernel pick sqlservr first; the cgroup ceiling (SQL Server's own
    memory limit plus room for its process overhead) keeps it from pushing everything into swap.
    """
    if unified is None:
        unified = os.path.exists('/sys/fs/cgroup/cgroup.controllers')
    ceiling = int(memory_limit_mb) + 512
    key = 'MemoryMax' if unified else 'MemoryLimit'
    return ('# Managed by CyberPanel Universal (SQL Server). Changes are overwritten.\n'
            '[Service]\nOOMScoreAdjust=500\n%s=%dM\n' % (key, ceiling))


def write_protect_dropin(memory_limit_mb, path=PROTECT_DROPIN):
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path + '.tmp', 'w') as handle:
        handle.write(protect_dropin_text(memory_limit_mb))
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)


def total_ram_mb(meminfo='/proc/meminfo'):
    with open(meminfo) as handle:
        for line in handle:
            if line.startswith('MemTotal:'):
                return int(line.split()[1]) // 1024
    return 0


def disk_free_mb(path=DATA_DIR):
    while not os.path.exists(path):
        path = os.path.dirname(path)
    return shutil.disk_usage(path).free // (1024 * 1024)


def preflight(profile, machine, ram_mb, disk_mb, installed):
    """List of {'id','ok','detail'} checks; installation is allowed only if all are ok."""
    checks = []
    try:
        kind, url, product = repo_for(profile['family'], profile['version'])
        checks.append({'id': 'os', 'ok': True, 'detail': 'SQL Server %s packages are available for this OS.' % product})
    except SQLError as exc:
        checks.append({'id': 'os', 'ok': False, 'detail': str(exc)})
    checks.append({'id': 'arch', 'ok': machine in ('x86_64', 'amd64'),
                   'detail': 'SQL Server on Linux requires x86-64 (this server: %s).' % machine})
    checks.append({'id': 'ram', 'ok': ram_mb >= MIN_RAM_MB,
                   'detail': '%d MB of RAM (Microsoft requires at least 2 GB).' % ram_mb})
    checks.append({'id': 'disk', 'ok': disk_mb >= MIN_DISK_MB,
                   'detail': '%.1f GB free for %s (Microsoft requires at least 6 GB).' % (disk_mb / 1024.0, DATA_DIR)})
    checks.append({'id': 'installed', 'ok': not installed, 'detail': 'SQL Server is already installed.' if installed
                   else 'SQL Server is not installed yet.'})
    return checks


def default_memory_limit_mb(ram_mb):
    """Leave most of the RAM to the web stack: 1/3 of RAM, between 512 MB and 4 GB."""
    return max(512, min(4096, ram_mb // 3))


# ----------------------------------------------------------------------------- secrets

def strong_password(length=24):
    """Meets SQL Server's complexity policy (upper, lower, digit, symbol) and avoids quoting issues."""
    symbols = '!#%*+-=?@^_'
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password) and any(c in symbols for c in password)):
            return password


def validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise SQLError('Passwords must be 12-128 characters.')
    if any(ord(c) < 32 for c in password) or "'" in password or ']' in password:
        raise SQLError('Passwords cannot contain quotes, ] or control characters.')
    classes = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                   any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
    if classes < 3:
        raise SQLError('Use at least three of: lowercase, uppercase, digits, symbols.')
    return password


def _private_write(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(path + '.tmp', path)


def _load(path, default):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def sa_password(state_dir=None):
    data = _load(os.path.join(state_dir or STATE_DIR, 'sa.json'), {})
    if not data.get('password'):
        raise SQLError('SQL Server is not set up by the panel.')
    return data['password']


def registry(state_dir=None):
    return _load(os.path.join(state_dir or STATE_DIR, 'databases.json'), {})


def save_registry(data, state_dir=None):
    _private_write(os.path.join(state_dir or STATE_DIR, 'databases.json'), data)


# ----------------------------------------------------------------------------- SQL

def quote_ident(name):
    if not DB_RE.match(name or ''):
        raise SQLError('Invalid name %r.' % name)
    return '[%s]' % name


def quote_string(value):
    return "N'%s'" % value.replace("'", "''")


def sqlcmd(sql, password, runner=subprocess.run, sqlcmd_path=SQLCMD, database='master'):
    """Run SQL as sa through a private file; the password travels in SQLCMDPASSWORD."""
    fd, path = tempfile.mkstemp(prefix='cp-mssql-', suffix='.sql')
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(sql)
        env = dict(os.environ, SQLCMDPASSWORD=password)
        code, out = run([sqlcmd_path, '-S', '127.0.0.1', '-U', 'sa', '-d', database, '-C', '-b', '-h', '-1', '-W',
                         '-s', '|', '-i', path], runner, timeout=300, env=env)
    finally:
        os.unlink(path)
    if code != 0:
        raise SQLError('SQL Server reported an error: %s' % out.strip()[-500:])
    return out


def create_sql(db, password):
    q = quote_ident(db)
    return '\n'.join([
        'SET NOCOUNT ON;',
        'CREATE DATABASE %s;' % q,
        'CREATE LOGIN %s WITH PASSWORD = %s, CHECK_POLICY = ON, DEFAULT_DATABASE = %s;' % (q, quote_string(password), q),
        'DENY VIEW ANY DATABASE TO %s;' % q,
        'ALTER AUTHORIZATION ON DATABASE::%s TO %s;' % (q, q),
        'GO',
    ]) + '\n'


def drop_sql(db):
    q = quote_ident(db)
    return '\n'.join([
        'SET NOCOUNT ON;',
        "IF DB_ID(%s) IS NOT NULL BEGIN ALTER DATABASE %s SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
        "DROP DATABASE %s; END;" % (quote_string(db), q, q),
        "IF SUSER_ID(%s) IS NOT NULL DROP LOGIN %s;" % (quote_string(db), q),
        'GO',
    ]) + '\n'


def password_sql(db, password):
    return 'ALTER LOGIN %s WITH PASSWORD = %s;\nGO\n' % (quote_ident(db), quote_string(password))


def database_name(site_user, name):
    """Site-prefixed name, as CyberPanel does for MySQL: <siteuser>_<name>."""
    name = (name or '').strip().lower()
    if not NAME_RE.match(name):
        raise SQLError('Database name: 2-31 lowercase letters, digits or _, starting with a letter.')
    prefix = re.sub(r'[^a-z0-9]', '', (site_user or '').lower())[:16] or 'site'
    return '%s_%s' % (prefix, name)


def connection_string(db, password):
    return ('Server=127.0.0.1,1433;Database=%s;User Id=%s;Password=%s;Encrypt=True;'
            'TrustServerCertificate=True;' % (db, db, password))


def sizes(password, runner=subprocess.run):
    out = sqlcmd('SET NOCOUNT ON; SELECT DB_NAME(database_id), CAST(SUM(size) * 8 / 1024 AS int) '
                 'FROM sys.master_files GROUP BY database_id;\nGO\n', password, runner)
    result = {}
    for line in out.splitlines():
        parts = [p.strip() for p in line.split('|')]
        if len(parts) == 2 and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
    return result
