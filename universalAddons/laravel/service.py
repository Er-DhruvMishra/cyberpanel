"""Laravel Toolkit: detect apps, run whitelisted artisan/composer commands, scheduler, queue worker,
.env editing and logs. Root side; everything that touches the app runs as the site user.

Security model
- Commands: only the names in ARTISAN / COMPOSER, each with fixed arguments plus a few typed
  options (booleans, a bounded integer, a token of safe characters). build_command() is the only
  way to make an argv; the web layer calls it too, so bad requests never reach the runner.
- The app directory is a validated path below the site's document root; its real path must stay
  in the site's home. Files are read with siteinfo.read_owned (no links, site user's files only).
- .env values leave the server only for SAFE_ENV_KEYS; every other value is masked. Edits change
  one key, keep a timestamped backup, and are written by the site user.
- The queue worker is a systemd unit running as the site user with the Universal Apps sandbox
  (no capabilities, read-only system, only the app directory writable) and a memory limit.
"""
import hashlib
import json
import os
import re
import time

from universalAddons import siteinfo
from universalAddons.siteinfo import SiteError

STATE_FILE = '/etc/cyberpanel/universal-laravel.json'
UNIT_DIR = '/etc/systemd/system'
COMPOSER_PATHS = ('/usr/local/bin/composer', '/usr/bin/composer')
COMPOSER_TARGET = '/usr/local/bin/composer'
COMPOSER_INSTALLER_URL = 'https://getcomposer.org/installer'
COMPOSER_SIG_URL = 'https://composer.github.io/installer.sig'
CRON_MARKER = 'cp-ua-laravel %s'
SKIP_DIRS = {'vendor', 'node_modules', '.git', 'storage', 'bootstrap', 'resources', 'cache', '.cache', 'wp-content',
             'wp-includes', 'wp-admin', '.well-known', 'cgi-bin'}
SCAN_DEPTH = 2
DEFAULT_FILES = {'index.html', '.htaccess', '.well-known', 'cgi-bin'}
HTACCESS_BEGIN = '# BEGIN IndiansCloud Laravel public/'
HTACCESS_END = '# END IndiansCloud Laravel public/'
ENV_KEY_RE = re.compile(r'^[A-Z][A-Z0-9_]{0,63}$')
SAFE_ENV_KEYS = ('APP_NAME', 'APP_ENV', 'APP_DEBUG', 'APP_URL', 'APP_LOCALE', 'APP_FALLBACK_LOCALE', 'APP_TIMEZONE',
                 'LOG_CHANNEL', 'LOG_STACK', 'LOG_LEVEL', 'LOG_DEPRECATIONS_CHANNEL', 'DB_CONNECTION', 'DB_HOST',
                 'DB_PORT', 'BROADCAST_DRIVER', 'BROADCAST_CONNECTION', 'CACHE_DRIVER', 'CACHE_STORE',
                 'FILESYSTEM_DISK', 'QUEUE_CONNECTION', 'SESSION_DRIVER', 'SESSION_LIFETIME', 'MAIL_MAILER',
                 'MAIL_HOST', 'MAIL_PORT', 'REDIS_HOST', 'REDIS_PORT', 'VITE_APP_NAME')
SECRET_HINT = re.compile(r'KEY|SECRET|PASSWORD|PASS|TOKEN|CREDENTIAL|PRIVATE|DSN|AUTH', re.I)
MAX_ENV_BACKUPS = 10
SECRET_TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{8,64}$')

# name -> (fixed artisan arguments, needs confirmation, {option: kind})
ARTISAN = {
    'migrate': (['migrate', '--force'], True, {'seed': 'flag:--seed'}),
    'migrate:status': (['migrate:status'], False, {}),
    'cache:clear': (['cache:clear'], False, {}),
    'config:clear': (['config:clear'], False, {}),
    'config:cache': (['config:cache'], False, {}),
    'route:clear': (['route:clear'], False, {}),
    'route:cache': (['route:cache'], False, {}),
    'view:clear': (['view:clear'], False, {}),
    'view:cache': (['view:cache'], False, {}),
    'optimize': (['optimize'], False, {}),
    'optimize:clear': (['optimize:clear'], False, {}),
    'storage:link': (['storage:link'], False, {}),
    'queue:restart': (['queue:restart'], False, {}),
    'down': (['down'], True, {'secret': 'token:--secret=', 'retry': 'int:--retry=:1:86400'}),
    'up': (['up'], False, {}),
}
COMPOSER = {
    'install': (['install', '--no-dev', '--no-interaction', '--prefer-dist', '--optimize-autoloader'], True, {}),
    'update': (['update', '--no-dev', '--no-interaction', '--prefer-dist', '--with-all-dependencies'], True, {}),
    'dump-autoload': (['dump-autoload'], False, {'optimize': 'flag:--optimize'}),
}
TOOLS = {'artisan': ARTISAN, 'composer': COMPOSER}


class LaravelError(SiteError):
    pass


# ----------------------------------------------------------------------------- commands

def build_command(tool, name, options=None, confirmed=False):
    """argv (after the PHP binary and artisan/composer) for a whitelisted command, or ValueError."""
    table = TOOLS.get(tool) if isinstance(tool, str) else None
    if table is None or not isinstance(name, str) or name not in table:
        raise LaravelError('Unknown command.')
    fixed, needs_confirm, allowed = table[name]
    if needs_confirm and confirmed is not True:
        raise LaravelError('Confirm %s %s first.' % (tool, name))
    options = options or {}
    if not isinstance(options, dict):
        raise LaravelError('Invalid options.')
    argv = list(fixed)
    for key, value in sorted(options.items()):
        kind = allowed.get(key)
        if kind is None:
            raise LaravelError('Unknown option %r for %s.' % (str(key)[:40], name))
        parts = kind.split(':')
        if parts[0] == 'flag':
            if value not in (True, False):
                raise LaravelError('Option %s must be true or false.' % key)
            if value:
                argv.append(parts[1])
        elif parts[0] == 'int':
            low, high = int(parts[2]), int(parts[3])
            if value in (None, ''):
                continue
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise LaravelError('Option %s must be a whole number from %d to %d.' % (key, low, high))
            argv.append('%s%d' % (parts[1], value))
        elif parts[0] == 'token':
            if value in (None, ''):
                continue
            if not isinstance(value, str) or not SECRET_TOKEN_RE.match(value):
                raise LaravelError('Option %s: 8-64 letters, digits, - or _.' % key)
            argv.append(parts[1] + value)
    if tool == 'artisan':
        argv += ['--no-interaction', '--no-ansi']
    else:
        argv += ['--no-ansi']
    return argv


def command_catalogue():
    """What the page offers: names, whether they need confirmation, and their options."""
    return {tool: [{'name': name, 'confirm': spec[1], 'options': sorted(spec[2])} for name, spec in table.items()]
            for tool, table in TOOLS.items()}


def find_composer(exists=os.path.isfile):
    for path in COMPOSER_PATHS:
        if exists(path):
            return path
    return ''


# ----------------------------------------------------------------------------- detection

def _framework_required(text):
    try:
        data = json.loads(text or '')
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get('require'), dict):
        return None
    constraint = data['require'].get('laravel/framework')
    return constraint if isinstance(constraint, str) else None


def is_laravel(site, directory):
    """The laravel/framework constraint when `directory` holds artisan + a composer.json requiring it."""
    artisan = os.path.join(directory, 'artisan')
    try:
        os.close(siteinfo.open_owned(site, artisan))
    except (OSError, SiteError):
        return None
    try:
        text = siteinfo.read_owned(site, os.path.join(directory, 'composer.json'), 512 * 1024)
    except (OSError, SiteError):
        return None
    return _framework_required(text)


def scan(site, depth=SCAN_DEPTH):
    """Laravel apps in the document root and its subdirectories: [{'path': rel, 'constraint': ...}]."""
    found = []

    def visit(directory, rel, level):
        constraint = is_laravel(site, directory)
        if constraint is not None:
            found.append({'path': rel, 'constraint': constraint})
            return  # an app's own subdirectories are not separate apps
        if level >= depth:
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if entry.name in SKIP_DIRS or entry.name.startswith('.') or not entry.is_dir(follow_symlinks=False):
                continue
            if not siteinfo.REL_RE.match(entry.name):
                continue
            visit(entry.path, (rel + '/' + entry.name) if rel else entry.name, level + 1)

    try:
        site.inside(site.docroot)
    except SiteError:
        return []
    visit(site.docroot, '', 0)
    return found


def app_dir(site, rel):
    """Absolute real path of the app at `rel` below the document root; it must be a Laravel app."""
    path = site.path(rel)
    real = site.inside(path)
    if not siteinfo.ABS_RE.match(real):
        raise LaravelError('The app path contains unsupported characters.')
    if is_laravel(site, real) is None:
        raise LaravelError('No Laravel app (artisan + composer.json requiring laravel/framework) at %s.' % (rel or
                                                                                                          'the document root'))
    return real


def framework_version(site, directory):
    text = None
    try:
        text = siteinfo.read_owned(site, os.path.join(directory, 'vendor', 'laravel', 'framework', 'src', 'Illuminate',
                                                      'Foundation', 'Application.php'), 64 * 1024)
    except (OSError, SiteError):
        pass
    match = re.search(r"const\s+VERSION\s*=\s*'([^']{1,40})'", text or '')
    return match.group(1) if match else ''


def parse_env(text):
    """[(key, value)] from a .env file, in order; comments and malformed lines are skipped."""
    pairs = []
    for line in (text or '').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('export '):
            stripped = stripped[7:].lstrip()
        key, sep, value = stripped.partition('=')
        key = key.strip()
        if not sep or not ENV_KEY_RE.match(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
            if stripped.partition('=')[2].strip().startswith('"'):
                value = value.replace('\\"', '"').replace('\\\\', '\\')
        elif ' #' in value:
            value = value.split(' #', 1)[0].rstrip()
        pairs.append((key, value))
    return pairs


def is_safe_key(key):
    return key in SAFE_ENV_KEYS and not SECRET_HINT.search(key)


def masked_env(text):
    """What the browser may see of a .env: every key, values only for safe keys."""
    rows = []
    for key, value in parse_env(text):
        if is_safe_key(key):
            rows.append({'key': key, 'value': value, 'masked': False})
        else:
            rows.append({'key': key, 'value': '', 'masked': True, 'set': value != ''})
    return rows


def read_env(site, directory):
    try:
        return siteinfo.read_owned(site, os.path.join(directory, '.env'), 256 * 1024)
    except (OSError, SiteError):
        return None


def _truthy(value):
    return str(value).strip().strip('"\'').lower() in ('1', 'true', 'yes', 'on')


def info(site, rel, runner=None, unit_state=None, cron=None):
    directory = app_dir(site, rel)
    env = dict(parse_env(read_env(site, directory) or ''))
    app_env = env.get('APP_ENV', '')
    debug = _truthy(env.get('APP_DEBUG', 'false'))
    warnings = []
    if debug and app_env in ('production', 'prod', ''):
        warnings.append('APP_DEBUG is on in production: error pages show code, configuration and secrets to visitors.')
    if not siteinfo.exists_nofollow(os.path.join(directory, 'vendor')):
        warnings.append('vendor/ is missing: run composer install.')
    if not siteinfo.exists_nofollow(os.path.join(directory, '.env')):
        warnings.append('There is no .env file.')
    worker = worker_for(site, directory)
    return {
        'domain': site.domain, 'path': rel, 'dir': directory,
        'laravel': framework_version(site, directory), 'constraint': is_laravel(site, directory),
        'php': site.php, 'php_version': siteinfo.php_version(site.php),
        'app_env': app_env, 'app_debug': debug,
        'maintenance': siteinfo.exists_nofollow(os.path.join(directory, 'storage', 'framework', 'down')),
        'scheduler': (cron or siteinfo.has_cron_line)(site, CRON_MARKER % directory),
        'worker': dict(worker, unit=(unit_state or siteinfo.unit_state)(unit_name(worker['id']))) if worker.get('enabled')
        else {'enabled': False, 'id': worker['id']},
        'public': public_state(site, directory),
        'warnings': warnings,
    }


# ----------------------------------------------------------------------------- scheduler

def scheduler_line(site, directory):
    if not siteinfo.ABS_RE.match(directory) or not siteinfo.ABS_RE.match(site.php):
        raise LaravelError('Unsupported path for cron.')
    return '* * * * * cd %s && %s artisan schedule:run >> /dev/null 2>&1' % (directory, site.php)


def set_scheduler(site, directory, enable, runner=None):
    kwargs = {'runner': runner} if runner else {}
    siteinfo.set_cron_line(site, CRON_MARKER % directory, scheduler_line(site, directory), enable, **kwargs)
    return {'scheduler': bool(enable)}


# ----------------------------------------------------------------------------- queue worker

def worker_id(domain, directory):
    return hashlib.sha256(('%s\0%s' % (domain, directory)).encode()).hexdigest()[:12]


def unit_name(wid):
    if not re.match(r'^[0-9a-f]{12}$', wid or ''):
        raise LaravelError('Invalid worker.')
    return 'cp-laravel-%s.service' % wid


def load_state(path=None):
    try:
        with open(path or STATE_FILE) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(data, path=None):
    path = path or STATE_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(path + '.tmp', path)


def worker_for(site, directory, state=None):
    wid = worker_id(site.domain, directory)
    record = (state if state is not None else load_state()).get('workers', {}).get(wid)
    if record and record.get('domain') == site.domain and record.get('dir') == directory:
        return dict(record, id=wid, enabled=True)
    return {'id': wid, 'enabled': False}


def render_worker_unit(worker, version=239, unified=False):
    """systemd unit for `php artisan queue:work` as the site user, with the Universal Apps sandbox."""
    for key in ('dir', 'php'):
        if not siteinfo.ABS_RE.match(worker[key]):
            raise LaravelError('Unsafe path in the worker unit.')
    if not siteinfo.USER_RE.match(worker['user']) or not siteinfo.DOMAIN_RE.match(worker['domain']):
        raise LaravelError('Invalid worker.')
    memory = int(worker['memory_mb'])
    queue = worker.get('queue') or 'default'
    if not re.match(r'^[A-Za-z0-9_,-]{1,100}$', queue):
        raise LaravelError('Invalid queue name.')
    # Let the worker stop itself just under the cgroup limit, so systemd restarts it cleanly.
    exec_start = '%s %s/artisan queue:work --queue=%s --sleep=3 --tries=3 --max-time=3600 --memory=%d --no-ansi' % (
        worker['php'], worker['dir'], queue, max(32, memory * 8 // 10))
    lines = [
        '# Managed by IndiansCloud (Laravel Toolkit). Changes are overwritten.',
        '[Unit]',
        'Description=IndiansCloud Laravel queue worker for %s (%s)' % (worker['domain'], worker['dir']),
        'After=network.target mariadb.service mysqld.service redis.service',
        '',
        '[Service]',
        'Type=simple',
        'User=%s' % worker['user'],
        'Group=%s' % worker['user'],
        'WorkingDirectory=%s' % worker['dir'],
        'ExecStart=%s' % exec_start,
        'Environment="HOME=%s"' % worker['home'],
        'Environment="PATH=%s:/usr/local/bin:/usr/bin:/bin"' % os.path.dirname(worker['php']),
        'Restart=always',
        'RestartSec=5',
        'TimeoutStopSec=60',
        'KillSignal=SIGTERM',
        'UMask=0027',
        # --- sandbox (as Universal Apps' render_unit); MySQL's socket directory stays reachable.
        'NoNewPrivileges=yes',
        'CapabilityBoundingSet=',
        'AmbientCapabilities=',
        'PrivateTmp=yes',
        'PrivateDevices=yes',
        'ProtectSystem=strict',
        'ReadWritePaths=%s' % worker['dir'],
        'ProtectKernelTunables=yes',
        'ProtectKernelModules=yes',
        'ProtectControlGroups=yes',
        'RestrictRealtime=yes',
        'RestrictNamespaces=yes',
        'LockPersonality=yes',
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
        'SystemCallArchitectures=native',
        'SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap',
        'SystemCallErrorNumber=EPERM',
        'InaccessiblePaths=-/etc/cyberpanel -/usr/local/CyberCP -/usr/local/lscp -/root '
        '-/etc/letsencrypt -/etc/opendkim -/etc/pdns -/home/vmail -/etc/shadow -/etc/gshadow',
    ]
    if version >= 242:
        lines += ['RestrictSUIDSGID=yes', 'ProtectHostname=yes']
    if version >= 244:
        lines.append('ProtectKernelLogs=yes')
    lines.append(('MemoryMax=%dM' if unified else 'MemoryLimit=%dM') % memory)
    lines += ['CPUQuota=100%', 'TasksMax=64', 'LimitNOFILE=4096', '', '[Install]', 'WantedBy=multi-user.target', '']
    return '\n'.join(lines)


# ----------------------------------------------------------------------------- public/ as the web root

def vhost_conf(site, vhosts=siteinfo.VHOSTS):
    return os.path.join(vhosts, site.vhost, 'vhost.conf')


APACHE_CONF_DIRS = ('/etc/httpd/conf.d', '/etc/apache2/sites-enabled')


def apache_conf(site, dirs=APACHE_CONF_DIRS):
    for directory in dirs:
        path = os.path.join(directory, site.vhost + '.conf')
        if os.path.isfile(path):
            return path
    return None


_DOCROOT_LINE = re.compile(r'^([ \t]*docRoot[ \t]+)(\S+)[ \t]*$', re.M)
_APACHE_DOCROOT = re.compile(r'^([ \t]*DocumentRoot[ \t]+)("?)([^\s"]+)\2', re.M)


def replace_docroot(text, new_root):
    """vhost.conf text with its docRoot set to new_root (the edit ACLManager.ReplaceDocRoot makes)."""
    matches = _DOCROOT_LINE.findall(text)
    if len(matches) != 1:
        raise LaravelError('vhost.conf has %d docRoot lines; expected one.' % len(matches))
    return _DOCROOT_LINE.sub(lambda m: m.group(1) + new_root, text), matches[0][1]


def replace_apache_docroot(text, new_root):
    return _APACHE_DOCROOT.sub(lambda m: m.group(1) + m.group(2) + new_root + m.group(2), text)


def current_docroot(site, vhosts=siteinfo.VHOSTS):
    try:
        with open(vhost_conf(site, vhosts)) as handle:
            matches = _DOCROOT_LINE.findall(handle.read())
    except OSError:
        return None
    if len(matches) != 1:
        return None
    return matches[0][1].replace('$VH_ROOT', site.home).replace('$VH_NAME', site.vhost)


def htaccess_block():
    return ('%s\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule ^(?!public/)(.*)$ public/$1 [L]\n'
            '</IfModule>\n%s\n' % (HTACCESS_BEGIN, HTACCESS_END))


def strip_block(text):
    pattern = re.compile(r'%s\n.*?%s\n?' % (re.escape(HTACCESS_BEGIN), re.escape(HTACCESS_END)), re.S)
    return pattern.sub('', text or '')


def with_block(text):
    return htaccess_block() + strip_block(text).lstrip('\n')


def public_state(site, directory, vhosts=siteinfo.VHOSTS):
    """How the web server reaches public/: 'vhost' (document root), 'htaccess' (rewrite), or None."""
    public = os.path.join(directory, 'public')
    root = current_docroot(site, vhosts)
    if root and os.path.normpath(root) in (public, os.path.realpath(public)):
        return 'vhost'
    try:
        text = siteinfo.read_owned(site, os.path.join(directory, '.htaccess'), 64 * 1024) or ''
    except (OSError, SiteError):
        text = ''
    return 'htaccess' if HTACCESS_BEGIN in text else None


def choose_method(site, directory, requested='auto'):
    """'vhost' when the app is the site's document root and the vhost can be edited, else 'htaccess'."""
    at_root = os.path.realpath(site.docroot) == directory
    if requested == 'vhost':
        if not at_root:
            raise LaravelError('The document root can only move to public/ for an app at the document root; '
                               'use the .htaccess rewrite for an app in a subdirectory.')
        return 'vhost'
    if requested == 'htaccess':
        return 'htaccess'
    if requested != 'auto':
        raise LaravelError('Unknown method.')
    return 'vhost' if at_root and current_docroot(site) else 'htaccess'


# ----------------------------------------------------------------------------- logs, backups

def log_tail(site, directory, lines=200):
    logs = os.path.join(directory, 'storage', 'logs')
    name = 'laravel.log'
    if not siteinfo.exists_nofollow(os.path.join(logs, name)):
        try:
            daily = sorted(n for n in os.listdir(logs) if re.match(r'^laravel-\d{4}-\d{2}-\d{2}\.log$', n))
        except OSError:
            daily = []
        if not daily:
            return {'file': '', 'lines': []}
        name = daily[-1]
    text = siteinfo.read_owned(site, os.path.join(logs, name), 512 * 1024, tail=True) or ''
    return {'file': 'storage/logs/' + name, 'lines': text.splitlines()[-lines:]}


def env_with(text, key, value):
    """The .env text with `key` set to `value` (added at the end when missing)."""
    if not ENV_KEY_RE.match(key or ''):
        raise LaravelError('Invalid key: use A-Z, 0-9 and _.')
    if not isinstance(value, str) or len(value) > 4096 or any(c in value for c in '\r\n\x00'):
        raise LaravelError('The value must be one line of at most 4096 characters.')
    if value == '' or re.match(r'^[A-Za-z0-9_./:@+,-]+$', value):
        rendered = value
    else:
        rendered = '"%s"' % value.replace('\\', '\\\\').replace('"', '\\"')
    line = '%s=%s' % (key, rendered)
    pattern = re.compile(r'^(export[ \t]+)?%s[ \t]*=.*$' % re.escape(key), re.M)
    if pattern.search(text or ''):
        return pattern.sub(lambda m: line, text, count=1)
    base = text or ''
    if base and not base.endswith('\n'):
        base += '\n'
    return base + line + '\n'


def backup_name(now=None):
    return '.env.backup-' + time.strftime('%Y%m%d-%H%M%S', time.localtime(now))
