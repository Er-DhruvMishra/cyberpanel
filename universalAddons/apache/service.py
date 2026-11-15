"""Apache Manager: run a site through OpenLiteSpeed -> Apache httpd -> PHP-FPM, for full .htaccess support.

An independent, free implementation. It does not use or touch CyberPanel's licensed Apache Manager.

Modes
- "ols" (the default): the site is served by OpenLiteSpeed and its lsphp handler, exactly as CyberPanel set it up.
- "apache": OpenLiteSpeed keeps ports 80/443, TLS termination, the site's certificate and the
  /.well-known/acme-challenge/ context, and reverse-proxies every other request over plain HTTP to Apache on
  127.0.0.1:<port>. Apache serves the site's public_html with `AllowOverride All` and hands .php to the
  site's own PHP-FPM pool over a unix socket. The pool runs as the site user, with open_basedir set to the
  site home.

Files this module writes (and only these)
- /etc/httpd/conf.d/cp-ua-00-apache.conf   Listen 127.0.0.1:<port>, small MPM event sizing, RemoteIP,
                                            and a catch-all vhost that refuses unknown Host headers.
- /etc/httpd/conf.d/cp-ua-<site>.conf       the site's VirtualHost on 127.0.0.1:<port>.
- <fpm conf dir>/cp-ua-<site>.conf          the site's PHP-FPM pool (remi: /etc/opt/remi/phpXY/php-fpm.d).
- vhost.conf of the site: one `# BEGIN cp-ua-apache` ... `# END cp-ua-apache` block placed before vhssl.
- /etc/yum.repos.d/cp-ua-remi-safe.repo     only when the admin installs a PHP-FPM version; restricted with
                                            includepkgs to the chosen versions, like the host's php56 repo.

Safety model
- Preview first: every change is a plan of (path, before, after) with a token; apply recomputes the plan
  and refuses if anything changed since.
- Apply: probe the site (scheme, status, page title, redirect target), back up every file, write
  atomically, validate (OpenLiteSpeed brace structure, `httpd -t`, `php-fpm -t`), reload php-fpm, then
  httpd, then restart OpenLiteSpeed gracefully (reverse order when switching back), and probe again. Any
  failure or a different answer restores every file and reloads all three services.
"""
import difflib
import hashlib
import json
import os
import re
import subprocess
import time
from collections import OrderedDict

STATE_FILE = '/etc/cyberpanel/universal-apache.json'
STATE_DIR = '/var/lib/cyberpanel-universal'
BACKUP_DIR = os.path.join(STATE_DIR, 'apache-backups')
LOCK_FILE = os.path.join(STATE_DIR, 'apache.lock')
VHOSTS = '/usr/local/lsws/conf/vhosts'
HTTPD = '/usr/sbin/httpd'
HTTPD_ROOT = '/etc/httpd'
CONF_D = '/etc/httpd/conf.d'
BASE_CONF_NAME = 'cp-ua-00-apache.conf'
HTTPD_LOG_DIR = '/var/log/httpd'
REPO_FILE = '/etc/yum.repos.d/cp-ua-remi-safe.repo'
REMI_KEY = '/etc/pki/rpm-gpg/RPM-GPG-KEY-remi2018'
ACME_LOCATION = '/usr/local/lsws/Example/html/.well-known/acme-challenge'

MARK_BEGIN = '# BEGIN cp-ua-apache (managed by CyberPanel; do not edit)'
MARK_END = '# END cp-ua-apache'
HANDLER = 'cpua_apache'
MANAGED = '# Managed by CyberPanel Universal (Apache Manager). Changes are overwritten.'

DEFAULT_PORT = 8086
PORT_CANDIDATES = tuple(range(8086, 8100))
# Ports OpenLiteSpeed, the panel or common services use; the backend never listens on them.
RESERVED_PORTS = {80, 443, 7080, 8080, 8081, 8082, 8083, 8090, 8091, 3306, 9000, 9001}
PHP_VERSIONS = ('56', '70', '71', '72', '73', '74', '80', '81', '82', '83', '84', '85')
# Extensions installed next to remi's phpXY-php-fpm (skipped if a version does not ship one).
REMI_EXTENSIONS = ('mysqlnd', 'gd', 'mbstring', 'xml', 'intl', 'opcache', 'pecl-zip', 'soap', 'bcmath', 'process')
# Library packages from remi-safe that remi's PHP builds depend on (parallel-installable names only).
REMI_DEPENDENCIES = ('remi-libzip*', 'gd3php*', 'libicu[0-9]*', 'oniguruma5php*', 'libsodium[0-9]*', 'libxslt-remi*')

MIN_AVAILABLE_MB = 600           # refuse an install below this MemAvailable unless confirmed
DNF_PEAK_MB = 400                # dnf resolving EL8 + EPEL + remi metadata, transient
HTTPD_MB = 35                    # parent + 2 event children at idle
FPM_MASTER_MB = 20               # one php-fpm master per PHP version
FPM_CHILD_MB = 60                # typical WordPress worker RSS with opcache shared

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
ALIAS_RE = re.compile(r'^(\*\.)?(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
VERSION_RE = re.compile(r'^\d{2}$')
LSPHP_PATH_RE = re.compile(r'^/usr/local/lsws/lsphp(\d{2})/bin/lsphp$')

PM_MODES = ('ondemand', 'dynamic', 'static')
POOL_KEYS = ('pm', 'max_children', 'start_servers', 'min_spare_servers', 'max_spare_servers', 'max_requests',
             'memory_limit_mb')


class ApacheError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=120):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


def validate_domain(domain):
    domain = (domain or '').strip().lower() if isinstance(domain, str) else ''
    if not DOMAIN_RE.match(domain):
        raise ApacheError('Invalid site.')
    return domain


def validate_versions(versions):
    if not isinstance(versions, list) or len(versions) > len(PHP_VERSIONS):
        raise ApacheError('Choose the PHP versions to install.')
    clean = []
    for version in versions:
        version = str(version).replace('.', '')
        if version not in PHP_VERSIONS:
            raise ApacheError('Unsupported PHP version %s.' % version)
        if version not in clean:
            clean.append(version)
    return sorted(clean)


def dotted(version):
    return '%s.%s' % (version[0], version[1:])


# ----------------------------------------------------------------------------- host memory

def meminfo(path='/proc/meminfo'):
    values = {}
    try:
        with open(path) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0].endswith(':') and parts[1].isdigit():
                    values[parts[0][:-1]] = int(parts[1]) // 1024
    except OSError:
        pass
    return {'total_mb': values.get('MemTotal', 0) or 1024, 'available_mb': values.get('MemAvailable', 0),
            'swap_free_mb': values.get('SwapFree', 0), 'cores': os.cpu_count() or 1}


# ----------------------------------------------------------------------------- PHP-FPM pool policy

def pool_bounds(total_mb, memory_limit_mb=None):
    """Upper bounds derived from RAM: in the worst case every child of one pool reaches memory_limit,
    and one pool may never be allowed to claim more than half of the RAM that way."""
    memory_max = max(64, min(1024, int(total_mb * 0.25) // 32 * 32))
    limit = memory_limit_mb or 128
    children_max = max(1, min(50, (total_mb // 2) // max(limit, 32)))
    return {'memory_limit_mb': (32, memory_max), 'max_children': (1, children_max), 'max_requests': (0, 100000),
            'start_servers': (1, children_max), 'min_spare_servers': (1, children_max),
            'max_spare_servers': (1, children_max)}


def default_pool(total_mb):
    memory = min(256, pool_bounds(total_mb)['memory_limit_mb'][1])
    children = min(5, pool_bounds(total_mb, memory)['max_children'][1])
    return OrderedDict([('pm', 'ondemand'), ('max_children', children), ('start_servers', 1),
                        ('min_spare_servers', 1), ('max_spare_servers', min(2, children)), ('max_requests', 500),
                        ('memory_limit_mb', memory)])


def _int(value, label):
    if isinstance(value, bool):
        raise ApacheError('%s must be a whole number.' % label)
    if isinstance(value, str) and re.match(r'^\s*\d{1,6}\s*$', value):
        value = int(value)
    if not isinstance(value, int):
        raise ApacheError('%s must be a whole number.' % label)
    return value


def validate_pool(data, total_mb):
    """Clean pool settings; missing keys take this host's defaults."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ApacheError('Pool settings must be an object.')
    unknown = sorted(set(data) - set(POOL_KEYS))
    if unknown:
        raise ApacheError('Unknown pool setting %s.' % unknown[0])
    pool = default_pool(total_mb)
    if data.get('pm') not in (None, ''):
        if data['pm'] not in PM_MODES:
            raise ApacheError('pm must be ondemand, dynamic or static.')
        pool['pm'] = data['pm']
    labels = {'max_children': 'pm.max_children', 'start_servers': 'pm.start_servers',
              'min_spare_servers': 'pm.min_spare_servers', 'max_spare_servers': 'pm.max_spare_servers',
              'max_requests': 'pm.max_requests', 'memory_limit_mb': 'memory_limit (MB)'}
    for key in labels:
        if data.get(key) not in (None, ''):
            pool[key] = _int(data[key], labels[key])
    low, high = pool_bounds(total_mb)['memory_limit_mb']
    if not low <= pool['memory_limit_mb'] <= high:
        raise ApacheError('memory_limit (MB) must be between %d and %d on this server.' % (low, high))
    bounds = pool_bounds(total_mb, pool['memory_limit_mb'])
    for key, label in labels.items():
        low, high = bounds[key]
        if key in ('start_servers', 'min_spare_servers', 'max_spare_servers') and pool['pm'] != 'dynamic':
            pool[key] = max(1, min(pool[key], pool['max_children']))  # unused by ondemand/static; keep it sane
            continue
        if not low <= pool[key] <= high:
            if key == 'max_children':
                raise ApacheError('pm.max_children must be between 1 and %d: with memory_limit %d MB, more children '
                                  'could use more than half of this server\'s %d MB RAM.'
                                  % (high, pool['memory_limit_mb'], total_mb))
            raise ApacheError('%s must be between %d and %d.' % (label, low, high))
    if pool['pm'] == 'dynamic':
        if pool['min_spare_servers'] > pool['max_spare_servers']:
            raise ApacheError('pm.min_spare_servers cannot be above pm.max_spare_servers.')
        if not pool['min_spare_servers'] <= pool['start_servers'] <= pool['max_spare_servers']:
            raise ApacheError('pm.start_servers must be between pm.min_spare_servers and pm.max_spare_servers.')
        if pool['max_spare_servers'] > pool['max_children']:
            raise ApacheError('pm.max_spare_servers cannot be above pm.max_children.')
    return pool


def pool_ram(pool):
    """(idle MB, typical peak MB, worst case MB) of one pool."""
    idle = {'ondemand': 0, 'dynamic': pool['start_servers'], 'static': pool['max_children']}[pool['pm']] * 25
    return {'idle_mb': idle, 'peak_mb': pool['max_children'] * min(FPM_CHILD_MB, pool['memory_limit_mb']),
            'worst_mb': pool['max_children'] * pool['memory_limit_mb']}


# ----------------------------------------------------------------------------- PHP-FPM installations

def fpm_layout(version, kind='remi'):
    if kind == 'system':
        return {'version': version, 'kind': 'system', 'binary': '/usr/sbin/php-fpm', 'conf': '/etc/php-fpm.conf',
                'pool_dir': '/etc/php-fpm.d', 'run_dir': '/run/php-fpm', 'service': 'php-fpm', 'package': 'php-fpm'}
    return {'version': version, 'kind': 'remi', 'binary': '/opt/remi/php%s/root/usr/sbin/php-fpm' % version,
            'conf': '/etc/opt/remi/php%s/php-fpm.conf' % version, 'pool_dir': '/etc/opt/remi/php%s/php-fpm.d' % version,
            'run_dir': '/var/opt/remi/php%s/run/php-fpm' % version, 'service': 'php%s-php-fpm' % version,
            'package': 'php%s-php-fpm' % version}


def system_fpm_version(runner=subprocess.run):
    code, out = run(['rpm', '-q', '--qf', '%{VERSION}', 'php-fpm'], runner, timeout=30)
    match = re.match(r'^(\d+)\.(\d+)\.', out.strip())
    return match.group(1) + match.group(2) if code == 0 and match else ''


def installed_fpm(exists=os.path.exists, runner=subprocess.run):
    """{version: layout} of every PHP-FPM this module can use. remi wins over the AppStream php-fpm."""
    found = {}
    system = system_fpm_version(runner) if exists('/usr/sbin/php-fpm') else ''
    if system in PHP_VERSIONS:
        found[system] = fpm_layout(system, 'system')
    for version in PHP_VERSIONS:
        layout = fpm_layout(version)
        if exists(layout['binary']) and exists(layout['pool_dir']):
            found[version] = layout
    return found


# ----------------------------------------------------------------------------- httpd facts

def httpd_run_identity(runner=subprocess.run, httpd_conf=None):
    """(user, group) Apache drops to. CyberPanel's own Apache setup uses nobody:nobody, which is also the
    group of every public_html, so this is read from the live configuration, never assumed."""
    code, out = run([HTTPD, '-t', '-D', 'DUMP_RUN_CFG'], runner, timeout=60)
    user = re.search(r'^User: name="([^"]+)"', out, re.M)
    group = re.search(r'^Group: name="([^"]+)"', out, re.M)
    if user and group:
        return user.group(1), group.group(1)
    try:
        with open(httpd_conf or os.path.join(HTTPD_ROOT, 'conf/httpd.conf')) as handle:
            text = handle.read()
    except OSError:
        text = ''
    user = re.findall(r'^\s*User\s+(\S+)', text, re.M)
    group = re.findall(r'^\s*Group\s+(\S+)', text, re.M)
    return (user[-1] if user else 'apache'), (group[-1] if group else 'apache')


def httpd_listens(httpd_root=None, skip=(BASE_CONF_NAME,)):
    """[(address, port)] of every Listen directive outside our own base file."""
    root = httpd_root or HTTPD_ROOT
    paths = [os.path.join(root, 'conf', 'httpd.conf')]
    for directory in ('conf.modules.d', 'conf.d'):
        try:
            paths += [os.path.join(root, directory, n) for n in sorted(os.listdir(os.path.join(root, directory)))
                      if n.endswith('.conf') and n not in skip]
        except OSError:
            pass
    found = []
    for path in paths:
        try:
            with open(path) as handle:
                for line in handle:
                    match = re.match(r'^\s*Listen\s+(?:\[?([0-9a-fA-F:.]*?)\]?:)?(\d+)\b', line)
                    if match:
                        found.append((match.group(1) or '*', int(match.group(2))))
        except OSError:
            continue
    return found


def port_in_use(port):
    import socket
    probe = socket.socket()
    try:
        probe.bind(('127.0.0.1', port))
        return False
    except OSError:
        return True
    finally:
        probe.close()


def choose_port(listens, in_use=port_in_use, preferred=None):
    taken = {port for address, port in listens}
    for port in ([preferred] if preferred else []) + list(PORT_CANDIDATES):
        if port and port not in taken and port not in RESERVED_PORTS and not in_use(port):
            return port
    raise ApacheError('No free internal port between %d and %d.' % (PORT_CANDIDATES[0], PORT_CANDIDATES[-1]))


def validate_port(port, listens):
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 < port < 65536 or port in RESERVED_PORTS:
        raise ApacheError('The internal Apache port must be a free high port (not 80/443 or a panel port).')
    if port in {p for a, p in listens}:
        raise ApacheError('Apache already listens on port %d elsewhere in its configuration.' % port)
    return port


# ----------------------------------------------------------------------------- rendering

def base_conf_path(conf_d=None):
    return os.path.join(conf_d or CONF_D, BASE_CONF_NAME)


def site_conf_path(domain, conf_d=None):
    return os.path.join(conf_d or CONF_D, 'cp-ua-%s.conf' % domain)


def pool_name(domain):
    return 'cp-ua-%s' % domain


def pool_path(domain, layout):
    return os.path.join(layout['pool_dir'], '%s.conf' % pool_name(domain))


def socket_path(domain, layout):
    return os.path.join(layout['run_dir'], '%s.sock' % pool_name(domain))


def render_base_conf(port):
    validate_port(port, [])
    return '\n'.join([
        MANAGED,
        '# Internal backend for OpenLiteSpeed: plain HTTP on the loopback interface only.',
        '# OpenLiteSpeed keeps ports 80/443, TLS and the certificates.',
        'Listen 127.0.0.1:%d' % port,
        '',
        '# Sized for a small server: at most 2 processes x 16 threads. Overrides conf.modules.d/00-mpm.conf.',
        '<IfModule mpm_event_module>',
        '    StartServers             1',
        '    ServerLimit              2',
        '    ThreadsPerChild          16',
        '    MinSpareThreads          8',
        '    MaxSpareThreads          24',
        '    MaxRequestWorkers        32',
        '    MaxConnectionsPerChild   2000',
        '</IfModule>',
        '',
        '# The client address comes from OpenLiteSpeed; trust it from the loopback only.',
        '<IfModule remoteip_module>',
        '    RemoteIPHeader X-Forwarded-For',
        '    RemoteIPInternalProxy 127.0.0.1',
        '</IfModule>',
        '',
        '# First vhost on the port = the default: refuse Host names no managed site claims.',
        '<VirtualHost 127.0.0.1:%d>' % port,
        '    ServerName cp-ua-default.invalid',
        '    ErrorLog "%s/cp-ua-default-error_log"' % HTTPD_LOG_DIR,
        '    CustomLog "/dev/null" common',
        '    <Location "/">',
        '        Require all denied',
        '    </Location>',
        '</VirtualHost>',
        '',
    ])


def render_site_conf(site, port, layout):
    """The site's Apache VirtualHost on the internal port. site = {domain, user, home, docroot, aliases}."""
    domain = validate_domain(site['domain'])
    validate_port(port, [])
    docroot = site['docroot']
    if not re.match(r'^/home/%s/[A-Za-z0-9._/-]+$' % re.escape(domain), docroot) or '..' in docroot:
        raise ApacheError('Unexpected document root %s.' % docroot)
    aliases = [a for a in site.get('aliases', []) if ALIAS_RE.match(a) and a != domain]
    sock = socket_path(domain, layout)
    lines = [
        MANAGED,
        '# %s: OpenLiteSpeed (TLS) -> Apache 127.0.0.1:%d -> PHP-FPM %s pool %s'
        % (domain, port, dotted(layout['version']), pool_name(domain)),
        '<VirtualHost 127.0.0.1:%d>' % port,
        '    ServerName %s' % domain,
    ]
    if aliases:
        lines.append('    ServerAlias %s' % ' '.join(aliases))
    lines += [
        '    DocumentRoot "%s"' % docroot,
        '    ErrorLog "%s/cp-ua-%s-error_log"' % (HTTPD_LOG_DIR, domain),
        '    # OpenLiteSpeed already writes the access log of this site.',
        '    CustomLog "/dev/null" common',
        '    # TLS ends at OpenLiteSpeed; tell PHP the original scheme.',
        '    SetEnvIf X-Forwarded-Proto "^https$" HTTPS=on',
        '    SetEnvIfNoCase ^Authorization$ "(.+)" HTTP_AUTHORIZATION=$1',
        '',
        '    <Directory "%s">' % docroot,
        '        Options SymLinksIfOwnerMatch',
        '        # Every .htaccess directive type is allowed; Options may not re-enable FollowSymLinks or CGI.',
        '        AllowOverride All Options=Indexes,MultiViews,SymLinksIfOwnerMatch',
        '        Require all granted',
        '        DirectoryIndex index.php index.html index.htm',
        '    </Directory>',
        '',
        '    # PHP runs in this site\'s own PHP-FPM pool, as the site user.',
        '    <FilesMatch "\\.php$">',
        '        SetHandler "proxy:unix:%s|fcgi://%s/"' % (sock, pool_name(domain)),
        '    </FilesMatch>',
        '    <FilesMatch "\\.(phar|phtml)$">',
        '        Require all denied',
        '    </FilesMatch>',
        '    <FilesMatch "^(\\.env|\\.user\\.ini|\\.htpasswd|wp-config\\.php\\.bak)$">',
        '        Require all denied',
        '    </FilesMatch>',
        '    <DirectoryMatch "/\\.(git|svn|hg)">',
        '        Require all denied',
        '    </DirectoryMatch>',
        '</VirtualHost>',
        '',
    ]
    return '\n'.join(lines)


def render_pool(site, pool, layout, run_user, run_group):
    """The site's PHP-FPM pool: runs as the site user; the socket belongs to Apache's run user."""
    domain = validate_domain(site['domain'])
    for name in (site['user'], run_user, run_group):
        if not USER_RE.match(name or ''):
            raise ApacheError('Invalid user or group name %r.' % name)
    home = '/home/%s' % domain
    lines = [
        '; ' + MANAGED[2:],
        '; Site %s, PHP %s. Tune it from Universal Add-ons > Apache Manager.' % (domain, dotted(layout['version'])),
        '[%s]' % pool_name(domain),
        'user = %s' % site['user'],
        'group = %s' % site['user'],
        'listen = %s' % socket_path(domain, layout),
        'listen.owner = %s' % run_user,
        'listen.group = %s' % run_group,
        'listen.mode = 0660',
        'pm = %s' % pool['pm'],
        'pm.max_children = %d' % pool['max_children'],
    ]
    if pool['pm'] == 'dynamic':
        lines += ['pm.start_servers = %d' % pool['start_servers'],
                  'pm.min_spare_servers = %d' % pool['min_spare_servers'],
                  'pm.max_spare_servers = %d' % pool['max_spare_servers']]
    if pool['pm'] == 'ondemand':
        lines.append('pm.process_idle_timeout = 10s')
    lines += [
        'pm.max_requests = %d' % pool['max_requests'],
        'request_terminate_timeout = 300',
        'chdir = /',
        'security.limit_extensions = .php',
        'php_admin_value[open_basedir] = %s/:/tmp/' % home,
        'php_admin_value[memory_limit] = %dM' % pool['memory_limit_mb'],
        'php_admin_value[upload_tmp_dir] = /tmp',
        'php_admin_value[session.save_path] = /tmp',
        'php_admin_value[sys_temp_dir] = /tmp',
        '',
    ]
    return '\n'.join(lines)


def render_vhost_block(port, add_acme):
    validate_port(port, [])
    parts = [MARK_BEGIN,
             'extprocessor %s {\n  type                    proxy\n  address                 127.0.0.1:%d\n'
             '  maxConns                32\n  pcKeepAliveTimeout      60\n  initTimeout             120\n'
             '  retryTimeout            0\n  respBuffer              0\n}' % (HANDLER, port),
             # OpenLiteSpeed forwards the original Host header and adds X-Forwarded-For and, for TLS requests,
             # X-Forwarded-Proto: https. Rewrites are off here: Apache reads .htaccess itself.
             'context / {\n  type                    proxy\n  handler                 %s\n'
             '  addDefaultCharset       off\n\n  rewrite  {\n    enable                  0\n  }\n}' % HANDLER]
    if add_acme:
        # Longer prefixes win in OpenLiteSpeed: Let's Encrypt HTTP-01 challenges stay on OpenLiteSpeed.
        parts.append('context /.well-known/acme-challenge {\n  location                %s\n  allowBrowse             1\n\n'
                     '  rewrite  {\n    enable                  0\n  }\n  addDefaultCharset       off\n}' % ACME_LOCATION)
    parts.append(MARK_END)
    return '\n\n'.join(parts) + '\n'


# ----------------------------------------------------------------------------- vhost.conf editing

def strip_block(text):
    return re.sub(r'\n?' + re.escape(MARK_BEGIN) + r'.*?' + re.escape(MARK_END) + r'[^\n]*\n?', '\n', text, flags=re.S)


def block_present(text):
    return MARK_BEGIN in text and MARK_END in text


def check_braces(text):
    """Structural brace balance (a line ending in '{' opens, a line that is just '}' closes; braces inside
    values such as "%{Referer}i" are not structure). Raises ApacheError."""
    from universalAddons.limits.service import LimitsError, blocks
    try:
        blocks(text)
    except LimitsError as exc:
        raise ApacheError('vhost.conf: %s' % exc)
    return True


def braces_balanced(text):
    try:
        return check_braces(text)
    except ApacheError:
        return False


def has_acme_context(text):
    return bool(re.search(r'^\s*context\s+/\.well-known/acme-challenge/?\s*\{', strip_block(text), re.M))


def conflicts(text):
    """Things outside our block that would clash with it."""
    outside = strip_block(text)
    found = []
    if re.search(r'^\s*context\s+/\s*\{', outside, re.M):
        found.append('a "context /" (another module or a manual edit; .htaccess translations are not needed under Apache)')
    if re.search(r'^\s*(extprocessor|context)\s+%s\b' % HANDLER, outside, re.M):
        found.append('a block named %s' % HANDLER)
    return found


def apply_block(text, port):
    """vhost text with exactly one managed block, placed before vhssl as CyberPanel and the other modules do."""
    check_braces(text)
    clashes = conflicts(text)
    if clashes:
        raise ApacheError('vhost.conf already has %s; remove it first.' % '; '.join(clashes))
    base = strip_block(text).rstrip('\n') + '\n'
    block = render_vhost_block(port, add_acme=not has_acme_context(base))
    match = re.search(r'^vhssl\s*\{', base, re.M)
    result = base[:match.start()] + block + '\n' + base[match.start():] if match else base + '\n' + block
    result = re.sub(r'\n{3,}', '\n\n', result)
    check_braces(result)
    return result


def remove_block(text):
    result = re.sub(r'\n{3,}', '\n\n', strip_block(text).rstrip('\n') + '\n')
    check_braces(result)
    return result


def parse_vhost(text, domain, user):
    """PHP version (from the site's lsphp extprocessor), docroot and host aliases of a CyberPanel vhost."""
    from universalAddons.limits.service import LimitsError, parse_extprocessor
    try:
        handler = parse_extprocessor(strip_block(text), user)
    except LimitsError as exc:
        raise ApacheError(str(exc))
    match = LSPHP_PATH_RE.match(handler['path'])
    if not match:
        raise ApacheError('Could not tell the PHP version from the site handler path %r.' % handler['path'])
    values = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in ('docRoot', 'vhAliases') and parts[0] not in values:
            values[parts[0]] = parts[1].strip()
    home = '/home/%s' % domain
    docroot = values.get('docRoot', '$VH_ROOT/public_html').replace('$VH_ROOT', home).replace('$VH_NAME', domain).rstrip('/')
    aliases = []
    for alias in re.split(r'[\s,]+', values.get('vhAliases', '').replace('$VH_NAME', domain)):
        alias = alias.strip().lower()
        if alias and ALIAS_RE.match(alias) and alias not in aliases:
            aliases.append(alias)
    return {'php': match.group(1), 'docroot': docroot, 'aliases': aliases, 'home': home}


def vhost_path(domain, vhosts=None):
    return os.path.join(vhosts or VHOSTS, domain, 'vhost.conf')


# ----------------------------------------------------------------------------- plans

def _read(path):
    try:
        with open(path) as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def _change(path, after, role, fpm=None):
    return {'path': path, 'role': role, 'before': _read(path), 'after': after, 'fpm': fpm}


def unified_diff(before, after, path):
    return ''.join(difflib.unified_diff((before or '').splitlines(keepends=True), (after or '').splitlines(keepends=True),
                                        fromfile=path if before is not None else '/dev/null',
                                        tofile=path if after is not None else '/dev/null', n=2))


def site_facts(site, vhosts=None):
    """site = {domain, user} -> plus php, docroot, aliases, home, vhost text and mode."""
    domain = validate_domain(site['domain'])
    if not USER_RE.match(site.get('user') or ''):
        raise ApacheError('The site has no valid Linux user.')
    text = _read(vhost_path(domain, vhosts))
    if text is None:
        raise ApacheError('No OpenLiteSpeed vhost.conf for this site.')
    facts = dict(site, domain=domain, vhost=text, mode='apache' if block_present(text) else 'ols')
    facts.update(parse_vhost(text, domain, site['user']))
    return facts


def plan(site, mode, pool, port, layouts, run_user, run_group, vhosts=None, conf_d=None):
    """Files to change for mode 'apache' (switch or re-render), 'ols' (switch back) or 'tune' (pool only).

    Nothing is written. layouts = installed_fpm(); pool = validate_pool(...)."""
    facts = site_facts(site, vhosts)
    domain = facts['domain']
    layout = layouts.get(facts['php'])
    vpath = vhost_path(domain, vhosts)
    result = {'domain': domain, 'user': facts['user'], 'mode': mode, 'current_mode': facts['mode'], 'php': facts['php'],
              'docroot': facts['docroot'], 'pool': pool, 'port': port, 'warnings': [], 'changes': []}
    if mode in ('apache', 'tune'):
        if not layout:
            raise ApacheError('PHP-FPM %s is not installed; install it first (the site uses lsphp%s).'
                              % (dotted(facts['php']), facts['php']))
        if mode == 'tune' and facts['mode'] != 'apache':
            raise ApacheError('The site is not served by Apache; its pool settings are used when you switch it.')
        if not port:
            raise ApacheError('The Apache backend is not configured yet; run the prerequisite job first.')
        result['fpm'] = layout
        changes = [_change(pool_path(domain, layout), render_pool(facts, pool, layout, run_user, run_group), 'pool', layout)]
        if mode == 'apache':
            changes.insert(0, _change(vpath, apply_block(facts['vhost'], port), 'vhost'))
            changes.insert(1, _change(site_conf_path(domain, conf_d), render_site_conf(facts, port, layout), 'httpd'))
            # Pools of the same site left behind under another PHP version would keep a second socket alive.
            for version, other in sorted(layouts.items()):
                if version != facts['php'] and os.path.exists(pool_path(domain, other)):
                    changes.append(_change(pool_path(domain, other), None, 'stale pool', other))
        result['changes'] = changes
        result['ram'] = pool_ram(pool)
    elif mode == 'ols':
        changes = [_change(vpath, remove_block(facts['vhost']), 'vhost'),
                   _change(site_conf_path(domain, conf_d), None, 'httpd')]
        for version, other in sorted(layouts.items()):
            changes.append(_change(pool_path(domain, other), None, 'pool', other))
        result['changes'] = changes
        result['fpm'] = layout
    else:
        raise ApacheError('Invalid mode.')
    result['changes'] = [c for c in result['changes'] if c['before'] != c['after']]
    result['changed'] = bool(result['changes'])
    result['diff'] = ''.join(unified_diff(c['before'], c['after'], c['path']) for c in result['changes'])
    result['token'] = plan_token(result)
    return result


def docroot_warning(docroot, run_group_gid, stat=os.stat):
    try:
        info = stat(docroot)
    except OSError:
        return 'The document root %s does not exist.' % docroot
    if info.st_gid != run_group_gid and not info.st_mode & 0o005:
        return ('Apache (group id %d) cannot read %s: static files would answer 403. IndiansCloud normally gives '
                'public_html to the nobody group.' % (run_group_gid, docroot))
    return ''


def plan_token(result):
    digest = hashlib.sha256(('%s\0%s\0' % (result['domain'], result['mode'])).encode('utf-8'))
    for change in result['changes']:
        digest.update(('%s\0%s\0%s\0' % (change['path'], change['before'], change['after'])).encode('utf-8'))
    return digest.hexdigest()[:32]


def public_plan(result):
    keep = {k: v for k, v in result.items() if k != 'changes'}
    keep['files'] = [{'path': c['path'], 'role': c['role'],
                      'action': 'create' if c['before'] is None else ('delete' if c['after'] is None else 'modify')}
                     for c in result['changes']]
    return keep


# ----------------------------------------------------------------------------- health probe

PROBE_MARK = '@@CPUA-PROBE@@'


def page_fingerprint(body):
    """What must stay the same: the page <title> (whitespace collapsed), else the start of the visible text."""
    match = re.search(r'<title[^>]*>(.*?)</title>', body or '', re.S | re.I)
    if match:
        return 'title:' + ' '.join(match.group(1).split())[:200]
    text = re.sub(r'<[^>]+>|\d+', ' ', body or '')
    return 'text:' + ' '.join(text.split())[:120]


def probe(domain, runner=subprocess.run, nonce=None):
    """{scheme, status, fingerprint, redirect} of the front page through 127.0.0.1, HTTPS first.

    A random query string keeps any page cache from answering instead of the backend."""
    nonce = nonce or os.urandom(4).hex()
    for scheme, port in (('https', '443'), ('http', '80')):
        code, out = run(['curl', '-sS', '-k', '--compressed', '--max-time', '25', '-o', '-',
                         '-w', '\n' + PROBE_MARK + '%{http_code} %{redirect_url}', '-H', 'Cache-Control: no-cache',
                         '--resolve', '%s:%s:127.0.0.1' % (domain, port), '%s://%s/?cp_ua_probe=%s' % (scheme, domain, nonce)],
                        runner, timeout=45)
        body, _, tail = out.rpartition('\n' + PROBE_MARK)
        parts = tail.strip().split(' ', 1)
        status = parts[0] if parts and parts[0].isdigit() else '000'
        if code == 0 and status != '000':
            redirect = re.sub(r'cp_ua_probe=[0-9a-f]+&?', '', parts[1] if len(parts) > 1 else '').rstrip('?&')
            return {'scheme': scheme, 'status': status, 'fingerprint': page_fingerprint(body[:262144]),
                    'redirect': redirect}
    return {'scheme': '', 'status': '000', 'fingerprint': '', 'redirect': ''}


def describe(answer):
    text = '%s %s' % (answer.get('scheme', ''), answer.get('status', ''))
    if answer.get('redirect'):
        text += ' -> %s' % answer['redirect']
    return text.strip() + (' [%s]' % answer['fingerprint'][:60] if answer.get('fingerprint') else '')


# ----------------------------------------------------------------------------- apply / rollback

class Services:
    """The system side of an apply, replaceable in tests."""

    def __init__(self, runner=subprocess.run):
        self.runner = runner

    def probe(self, domain):
        return probe(domain, self.runner)

    def httpd_test(self):
        code, out = run([HTTPD, '-t'], self.runner, timeout=60)
        return code == 0, out.strip()[-1500:]

    def fpm_test(self, layout):
        code, out = run([layout['binary'], '-t', '-y', layout['conf']], self.runner, timeout=60)
        return code == 0, out.strip()[-1500:]

    def _systemctl(self, verb, unit):
        return run(['systemctl', verb, unit], self.runner, timeout=120)

    def active(self, unit):
        code, out = self._systemctl('is-active', unit)
        return out.strip() == 'active'

    def reload_or_start(self, unit):
        if self.active(unit):
            code, out = self._systemctl('reload', unit)
        else:
            code, out = run(['systemctl', 'enable', '--now', unit], self.runner, timeout=120)
        if code != 0:
            return False
        for _ in range(10):
            if self.active(unit):
                return True
            time.sleep(1)
        return False

    def restart_ols(self):
        from universalAddons.htaccess import service as hs
        return hs.restart(self.runner)


def write_file(path, text):
    from universalAddons.htaccess import service as hs
    if text is None:
        if os.path.exists(path):
            os.unlink(path)
        return
    hs._write_atomic(path, text)


def apply_plan(result, services=None, backup_root=None, log=None, sleep=time.sleep, attempts=3):
    """Write a plan, validate, reload in order, compare the site's answer; restore everything on any failure."""
    from universalAddons.htaccess import service as hs
    services = services or Services()
    say = log or (lambda text: None)
    changes = result['changes']
    if not changes:
        return {'applied': False, 'domain': result['domain']}
    domain = result['domain']
    touches = {c['role'] for c in changes}
    fpms = OrderedDict()
    for change in changes:
        if change.get('fpm'):
            fpms[change['fpm']['service']] = change['fpm']
    before = services.probe(domain)
    say('%s answers %s before the change' % (domain, describe(before)))
    if before['status'] == '000':
        raise ApacheError('%s does not answer at all right now; refusing to change it without a baseline.' % domain)
    for change in changes:
        if _read(change['path']) != change['before']:
            raise ApacheError('%s changed since the preview; preview again.' % change['path'])
    saved = hs._backup([c['path'] for c in changes], backup_root or BACKUP_DIR)
    say('backed up %d file(s)' % len(saved))
    to_ols = result['mode'] == 'ols'

    def reload_steps():
        """php-fpm, then httpd, then OpenLiteSpeed. Switching back runs them in reverse, so OpenLiteSpeed
        stops proxying before Apache and the pool go away."""
        steps = [('php-fpm (%s)' % unit, lambda unit=unit: services.reload_or_start(unit)) for unit in fpms]
        if 'httpd' in touches:
            steps.append(('httpd', lambda: services.reload_or_start('httpd')))
        if 'vhost' in touches:
            steps.append(('OpenLiteSpeed (graceful restart)', services.restart_ols))
        return list(reversed(steps)) if to_ols else steps

    try:
        for change in changes:
            write_file(change['path'], change['after'])
            say('%s %s' % ('removed' if change['after'] is None else 'wrote', change['path']))
            if change['role'] == 'vhost':
                written = _read(change['path']) or ''
                if written != change['after']:
                    raise ApacheError('%s did not read back as written.' % change['path'])
                check_braces(written)
        if 'httpd' in touches:
            ok, output = services.httpd_test()
            say('httpd -t: %s' % (output.splitlines()[-1] if output else ('ok' if ok else 'failed')))
            if not ok:
                raise ApacheError('httpd -t failed: %s' % output[-500:])
        for unit, fpm in fpms.items():
            ok, output = services.fpm_test(fpm)
            say('php-fpm -t (%s): %s' % (unit, output.splitlines()[-1] if output else ('ok' if ok else 'failed')))
            if not ok:
                raise ApacheError('php-fpm -t failed for %s: %s' % (unit, output[-500:]))
        for title, step in reload_steps():
            say('reloading %s' % title)
            if not step():
                raise ApacheError('%s did not come back after the reload.' % title)
        after = before
        for attempt in range(attempts):
            sleep(3)
            after = services.probe(domain)
            if after == before:
                break
        say('%s answers %s after the change' % (domain, describe(after)))
        if after != before:
            raise ApacheError('Health check failed: %s answered %s instead of %s.' % (domain, describe(after), describe(before)))
    except Exception as exc:
        hs._restore(saved)
        say('rollback: restored %d file(s); reloading the services again' % len(saved))
        for title, step in reload_steps():
            try:
                step()
            except Exception as again:  # keep restoring the rest
                say('%s: %s' % (title, again))
        raise ApacheError('%s Everything was rolled back.' % exc)
    return {'applied': True, 'domain': domain, 'mode': result['mode'], 'answer': after}


# ----------------------------------------------------------------------------- install helpers

def repo_text(versions):
    validate_versions(list(versions))
    include = ' '.join(['php%s-*' % v for v in versions] + list(REMI_DEPENDENCIES))
    return '\n'.join([
        '# Written by CyberPanel Universal (Apache Manager) for PHP-FPM of the listed versions only.',
        '# includepkgs keeps remi from replacing any system package.',
        '[cp-ua-remi-safe]',
        'name=Remi safe (PHP-FPM %s only, CyberPanel Universal)' % ', '.join(dotted(v) for v in versions),
        'mirrorlist=https://rpms.remirepo.net/enterprise/8/safe/x86_64/httpsmirror',
        'enabled=1',
        'gpgcheck=1',
        'gpgkey=file://%s' % REMI_KEY,
        'includepkgs=%s' % include,
        '',
    ])


def install_packages(version):
    return ['php%s-php-fpm' % version], ['php%s-php-%s' % (version, ext) for ext in REMI_EXTENSIONS]


def install_plan(versions, layouts, httpd_installed, httpd_active, mem):
    """What the install job would do and what it costs in RAM."""
    missing = [v for v in versions if v not in layouts]
    packages = ([] if httpd_installed else ['httpd'])
    for version in missing:
        required, optional = install_packages(version)
        packages += required + optional
    steady = (0 if httpd_active else HTTPD_MB) + FPM_MASTER_MB * len(missing)
    warnings = []
    if mem['available_mb'] < MIN_AVAILABLE_MB:
        warnings.append('Only %d MB RAM is available; dnf alone needs about %d MB while it runs. Confirm to continue '
                        'anyway, or free memory first.' % (mem['available_mb'], DNF_PEAK_MB))
    return {'versions': versions, 'missing': missing, 'packages': packages, 'repo': REPO_FILE if missing else '',
            'repo_text': repo_text(missing) if missing else '', 'ram_steady_mb': steady, 'ram_transient_mb': DNF_PEAK_MB,
            'available_mb': mem['available_mb'], 'needs_confirm': mem['available_mb'] < MIN_AVAILABLE_MB,
            'warnings': warnings,
            'per_site_note': 'Each site switched to Apache adds its own pool: ondemand idles at 0 MB and peaks at about '
                             'max_children x %d MB.' % FPM_CHILD_MB}


def www_pool_ondemand(text):
    """remi's stock www pool starts 5 workers per version; switch it to ondemand (idle = no workers)."""
    if re.search(r'^\s*pm\s*=\s*ondemand\s*$', text, re.M):
        return text
    return re.sub(r'^(\s*)pm\s*=\s*\w+\s*$', r'\1pm = ondemand ; set by CyberPanel Universal (Apache Manager) to save RAM',
                  text, count=1, flags=re.M)


# ----------------------------------------------------------------------------- state and status

def load_state(path=None):
    try:
        with open(path or STATE_FILE) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    state = {'port': None, 'sites': {}}
    if isinstance(data, dict):
        port = data.get('port')
        if isinstance(port, int) and not isinstance(port, bool) and 1024 < port < 65536:
            state['port'] = port
        for domain, entry in (data.get('sites') or {}).items() if isinstance(data.get('sites'), dict) else ():
            if DOMAIN_RE.match(domain) and isinstance(entry, dict):
                state['sites'][domain] = entry
    return state


def save_state(state, path=None):
    path = path or STATE_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = '%s.tmp.%d' % (path, os.getpid())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write('\n')
    os.replace(temporary, path)


def pool_workers(proc='/proc'):
    """{pool name: worker count} from php-fpm process titles (root: /proc is hidepid=2)."""
    counts = {}
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return counts
    for pid in pids:
        try:
            with open(os.path.join(proc, pid, 'cmdline'), 'rb') as handle:
                title = handle.read(200).replace(b'\0', b' ').decode('utf-8', 'replace').strip()
        except OSError:
            continue
        match = re.match(r'^php-fpm: pool (\S+)', title)
        if match:
            counts[match.group(1)] = counts.get(match.group(1), 0) + 1
    return counts
