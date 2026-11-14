"""Roundcube webmail: a free, independent installer and manager (no licence gate involved).

Layout
- Code: /usr/local/cp-roundcube/<version>, root-owned and read-only, with `current` -> <version>.
  config/config.inc.php is root:<site group> 0640; temp/ and logs/ belong to the site user, 0700.
  The installer/ directory is removed after extraction.
- Database: MariaDB `cp_roundcube` with its own user `cp_roundcube`@localhost and a random
  password. Root credentials come from /etc/cyberpanel/mysqlPassword through a private
  defaults file; every statement that carries a password goes to mysql on stdin, never argv.
- Secrets (DB password, des_key) also live in /etc/cyberpanel/roundcube/secrets.json (root 0600)
  so the config can be rewritten when the site changes. They are never logged or returned.

Serving
- CyberPanel vhosts are `restrained`: OpenLiteSpeed refuses contexts that point outside $VH_ROOT.
  So the chosen site gets a root-owned "web mirror" at $VH_ROOT/cp-roundcube-web: an index.php
  stub that sets INSTALL_PATH to the real release and includes it, plus copies of the static
  assets (skins, plugin assets, program/js, program/resources) with an extension allowlist.
  No PHP other than the stub and no configuration ever lands in the mirror.
- The site's vhost.conf gets a `# BEGIN cp-ua-roundcube` ... `# END cp-ua-roundcube` block:
  deny contexts for config/ temp/ logs/ SQL/ bin/ (and installer/ vendor/), and the /webmail-rc/
  context mapped to the mirror. PHP runs through the vhost's own lsphp script handler, as the
  site user; a context phpIniOverride widens open_basedir to include the release.
- Writes are atomic with a backup; OpenLiteSpeed restarts gracefully (lswsctrl restart sends
  SIGUSR1); the URL is health-checked and the previous vhost restored if anything fails.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import string
import subprocess
import tarfile
import tempfile

# Pinned release (Roundcube 1.6 LTS). SHA256 as published on roundcube.net/download and as the
# GitHub release asset digest of roundcubemail-1.6.21-complete.tar.gz.
VERSION = '1.6.21'
SHA256 = '31b42871e7237c2aa30e4bfaab5e943401cc42e8a4948653abe801504855d5e2'
TARBALL = 'roundcubemail-%s-complete.tar.gz' % VERSION
DOWNLOAD_URL = 'https://github.com/roundcube/roundcubemail/releases/download/%s/%s' % (VERSION, TARBALL)
RELEASES_API = 'https://api.github.com/repos/roundcube/roundcubemail/releases?per_page=50'
BRANCH = '1.6.'

ROOT = '/usr/local/cp-roundcube'
STATE_DIR = '/etc/cyberpanel/roundcube'
VHOSTS = '/usr/local/lsws/conf/vhosts'
HTTPD_CONFIG = '/usr/local/lsws/conf/httpd_config.conf'
DB_NAME = 'cp_roundcube'
DB_USER = 'cp_roundcube'
URL_PREFIX = '/webmail-rc/'
MIRROR_NAME = 'cp-roundcube-web'
MIRROR_MARKER = '.cp-ua-roundcube'
MARK_BEGIN = '# BEGIN cp-ua-roundcube (managed by CyberPanel; do not edit)'
MARK_END = '# END cp-ua-roundcube'
DENY_DIRS = ('config', 'temp', 'logs', 'SQL', 'bin', 'installer', 'vendor')
REQUIRED_EXTENSIONS = ('dom', 'intl', 'mbstring', 'pdo_mysql', 'openssl', 'fileinfo', 'json', 'zip')
MIN_PHP = (7, 3)
PRODUCT_NAME = 'Webmail'

PUBLIC_TREES = ('skins', 'plugins', 'program/js', 'program/resources')
STATIC_EXTENSIONS = {'.js', '.css', '.map', '.png', '.gif', '.jpg', '.jpeg', '.svg', '.ico', '.webp', '.tiff',
                     '.woff', '.woff2', '.ttf', '.eot', '.wav', '.mp3', '.pdf', '.html'}

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
VERSION_RE = re.compile(r'^\d{1,2}\.\d{1,2}\.\d{1,3}$')
SAFE_PATH_RE = re.compile(r'^/[A-Za-z0-9._/-]+$')


class RoundcubeError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=300, stdin=None, input_text=None):
    """Run argv (never a shell). stdin: an open file; input_text: text fed to stdin."""
    kwargs = {'stdout': subprocess.PIPE, 'stderr': subprocess.STDOUT, 'universal_newlines': True, 'timeout': timeout}
    if input_text is not None:
        kwargs['input'] = input_text
    else:
        kwargs['stdin'] = stdin if stdin is not None else subprocess.DEVNULL
    try:
        out = runner(argv, **kwargs)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


def validate_domain(domain):
    domain = str(domain or '').strip().lower()
    if not DOMAIN_RE.match(domain):
        raise RoundcubeError('Invalid site.')
    return domain


# ----------------------------------------------------------------------------- secrets / state

def random_token(length, alphabet=string.ascii_letters + string.digits):
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def new_secrets():
    # Alphanumeric only: nothing to escape in SQL, PHP or a DSN.
    return {'db_password': random_token(32), 'des_key': random_token(24)}


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


def load_state(state_dir=None):
    return _load(os.path.join(state_dir or STATE_DIR, 'state.json'), {})


def save_state(data, state_dir=None):
    _private_write(os.path.join(state_dir or STATE_DIR, 'state.json'), data)


def load_secrets(state_dir=None):
    data = _load(os.path.join(state_dir or STATE_DIR, 'secrets.json'), {})
    if not data.get('db_password') or not data.get('des_key'):
        raise RoundcubeError('Roundcube is not set up by the panel.')
    return data


def save_secrets(data, state_dir=None):
    _private_write(os.path.join(state_dir or STATE_DIR, 'secrets.json'),
                   {'db_password': data['db_password'], 'des_key': data['des_key']})


def redact(text, secret_values):
    """Remove secret values from text that may reach a log or a response."""
    text = str(text)
    for value in secret_values:
        if value:
            text = text.replace(value, '********')
    return text


# ----------------------------------------------------------------------------- download / verify / extract

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(path, expected=None):
    expected = expected or SHA256
    actual = sha256_file(path)
    if actual != expected:
        raise RoundcubeError('Checksum mismatch for %s: expected %s, got %s. The download was discarded.'
                             % (os.path.basename(path), expected, actual))
    return actual


def download(url, target, opener=None, timeout=120, max_bytes=64 * 1024 * 1024):
    import urllib.request
    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(url, headers={'User-Agent': 'cp-ua-roundcube'})
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    total = 0
    with os.fdopen(fd, 'wb') as out, opener(request, timeout=timeout) as response:
        for chunk in iter(lambda: response.read(256 * 1024), b''):
            total += len(chunk)
            if total > max_bytes:
                raise RoundcubeError('The download is larger than expected.')
            out.write(chunk)
    return total


def _inside(base, path):
    base = os.path.normpath(base)
    path = os.path.normpath(path)
    return path == base or path.startswith(base + os.sep)


def safe_members(archive, top):
    """Validate every member of the release tarball; return them. Raises on anything unsafe."""
    members = []
    for member in archive.getmembers():
        name = member.name
        if name.startswith('/') or '\\' in name or '..' in name.split('/'):
            raise RoundcubeError('Unsafe path in archive: %s' % name)
        if not (name == top or name.startswith(top + '/')):
            raise RoundcubeError('Unexpected entry outside %s/: %s' % (top, name))
        if member.islnk() or member.isdev() or member.isfifo():
            raise RoundcubeError('Unsupported entry type in archive: %s' % name)
        if member.issym():
            target = os.path.join(os.path.dirname(name), member.linkname)
            if member.linkname.startswith('/') or not _inside(top, target):
                raise RoundcubeError('Symlink escapes the release: %s -> %s' % (name, member.linkname))
        elif not (member.isfile() or member.isdir()):
            raise RoundcubeError('Unsupported entry type in archive: %s' % name)
        members.append(member)
    return members


def extract_release(tarball, destination, version=VERSION, chown=True):
    """Extract the verified tarball into destination (must not exist), root-owned, no setuid/world-write."""
    if os.path.lexists(destination):
        raise RoundcubeError('%s already exists.' % destination)
    top = 'roundcubemail-%s' % version
    parent = os.path.dirname(destination)
    staging = tempfile.mkdtemp(prefix='.staging-', dir=parent)
    try:
        with tarfile.open(tarball, 'r:gz') as archive:
            members = safe_members(archive, top)
            for member in members:
                target = os.path.join(staging, member.name)
                if member.isdir():
                    os.makedirs(target, mode=0o755, exist_ok=True)
                elif member.issym():
                    os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
                    os.symlink(member.linkname, target)
                else:
                    os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
                    source = archive.extractfile(member)
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as out:
                        shutil.copyfileobj(source, out)
                    os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
        release = os.path.join(staging, top)
        if not os.path.isfile(os.path.join(release, 'index.php')):
            raise RoundcubeError('The archive does not look like a Roundcube release.')
        shutil.rmtree(os.path.join(release, 'installer'), ignore_errors=True)
        for directory, dirs, files in os.walk(release):
            os.chmod(directory, 0o755)
            for name in dirs + files:
                path = os.path.join(directory, name)
                if chown:
                    os.lchown(path, 0, 0)
        if chown:
            os.lchown(release, 0, 0)
        os.rename(release, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return destination


def point_current(root, version):
    link = os.path.join(root, 'current')
    temporary = link + '.tmp'
    if os.path.lexists(temporary):
        os.unlink(temporary)
    os.symlink(version, temporary)
    os.replace(temporary, link)
    return link


def installed_version(root=ROOT):
    try:
        target = os.readlink(os.path.join(root, 'current'))
    except OSError:
        return None
    target = os.path.basename(target.rstrip('/'))
    return target if VERSION_RE.match(target) and os.path.isfile(os.path.join(root, target, 'index.php')) else None


# ----------------------------------------------------------------------------- mail server detection

def parse_doveconf(values):
    """values: {'ssl','protocols'} from `doveconf -h`. Returns the dovecot facts we use."""
    protocols = (values.get('protocols') or '').split()
    return {'ssl': (values.get('ssl') or 'no').strip(), 'sieve': 'sieve' in protocols}


def choose_imap(dovecot, port_open):
    """IMAP for Roundcube on this host. Certificate checks are pointless on 127.0.0.1 (the
    per-domain certificates never name it), so they are disabled in the config instead."""
    if dovecot['ssl'] in ('yes', 'required') and port_open(993):
        return 'ssl://127.0.0.1:993'
    if dovecot['ssl'] in ('yes', 'required'):
        return 'tls://127.0.0.1:143'
    return '127.0.0.1:143'


def parse_postconf_services(text):
    """Names of the inet services in `postconf -M` output (e.g. submission, smtps)."""
    names = set()
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == 'inet':
            names.add(parts[0].split('/')[0])
    return names


def choose_smtp(services):
    if 'submission' in services:
        return 'tls://127.0.0.1:587'
    if 'smtps' in services:
        return 'ssl://127.0.0.1:465'
    raise RoundcubeError('Postfix has no submission (587) or smtps (465) service for authenticated mail.')


def port_is_open(port, host='127.0.0.1', timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ----------------------------------------------------------------------------- OpenLiteSpeed vhost

def _blocks(text, keyword):
    """Yield (name, body) of top-level `keyword name {` blocks."""
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r'^\s*%s\s+(\S+)\s*\{\s*$' % re.escape(keyword), lines[index])
        if not match:
            index += 1
            continue
        depth, body = 1, []
        index += 1
        while index < len(lines) and depth > 0:
            depth += lines[index].count('{') - lines[index].count('}')
            if depth > 0:
                body.append(lines[index])
            index += 1
        yield match.group(1), '\n'.join(body)


def _value(body, key):
    match = re.search(r'^\s*%s\s+(.+?)\s*$' % re.escape(key), body, re.M)
    return match.group(1) if match else None


def parse_vhost_declaration(httpd_text, domain):
    """vhRoot and restrained of `virtualhost <domain>` in httpd_config.conf."""
    for name, body in _blocks(httpd_text, 'virtualhost'):
        if name == domain:
            root = (_value(body, 'vhRoot') or '').replace('$VH_NAME', domain).rstrip('/')
            if not SAFE_PATH_RE.match(root or '') or '..' in root.split('/'):
                raise RoundcubeError('Unexpected vhRoot for %s.' % domain)
            return {'vh_root': root, 'restrained': (_value(body, 'restrained') or '0') == '1'}
    raise RoundcubeError('OpenLiteSpeed has no virtual host %s.' % domain)


def parse_php_handler(vhost_text):
    """The lsapi handler that runs .php for this vhost: name, lsphp path, user and group."""
    text = strip_block(vhost_text)
    handler = None
    for match in re.finditer(r'^\s*scripthandler\s*\{(.*?)^\s*\}', text, re.M | re.S):
        found = re.search(r'^\s*add\s+lsapi:(\S+)\s+([\w, ]+)$', match.group(1), re.M)
        if found and 'php' in [s.strip() for s in found.group(2).split(',')]:
            handler = found.group(1)
    if not handler:
        raise RoundcubeError('The vhost has no lsapi handler for PHP.')
    for name, body in _blocks(text, 'extprocessor'):
        if name == handler:
            path = _value(body, 'path') or ''
            user, group = _value(body, 'extUser'), _value(body, 'extGroup')
            match = re.match(r'^/usr/local/lsws/(lsphp\d{2})/bin/lsphp$', path)
            if not match:
                raise RoundcubeError('The vhost PHP handler is not a standard lsphp (%s).' % path)
            if not user or not USER_RE.match(user) or not group or not USER_RE.match(group):
                raise RoundcubeError('The vhost PHP handler has no valid extUser/extGroup.')
            return {'handler': handler, 'lsphp': match.group(1), 'path': path, 'user': user, 'group': group,
                    'php_cli': '/usr/local/lsws/%s/bin/php' % match.group(1)}
    raise RoundcubeError('The vhost defines no extprocessor %s.' % handler)


def has_ssl(vhost_text):
    return bool(re.search(r'^vhssl\s*\{', vhost_text, re.M))


def mirror_dir(vh_root):
    return os.path.join(vh_root, MIRROR_NAME)


def render_vhost_block(vh_root, release_dir):
    mirror = mirror_dir(vh_root) + '/'
    parts = [MARK_BEGIN]
    for name in DENY_DIRS:
        parts.append('context %s%s/ {\n  location                %s\n  allowBrowse             0\n}'
                     % (URL_PREFIX, name, mirror))
    basedir = '/tmp:%s:%s/' % (vh_root, os.path.dirname(release_dir.rstrip('/')))
    # rewrite disabled: the site's own .htaccess is loaded vhost-wide (autoLoadHtaccess) and a
    # catch-all "missing file -> index.php" rule would otherwise hand /webmail-rc/ to the site's app.
    parts.append('context %s {\n  location                %s\n  allowBrowse             1\n'
                 '  indexFiles              index.php\n  addDefaultCharset       off\n\n'
                 '  rewrite  {\n    enable                0\n  }\n\n'
                 '  phpIniOverride  {\nphp_admin_value open_basedir "%s"\n  }\n}' % (URL_PREFIX, mirror, basedir))
    parts.append(MARK_END)
    return '\n\n'.join(parts) + '\n'


def strip_block(text):
    pattern = re.compile(r'\n?' + re.escape(MARK_BEGIN) + r'.*?' + re.escape(MARK_END) + r'\n?', re.S)
    return pattern.sub('\n', text)


def brace_balanced(text):
    depth = 0
    for line in text.splitlines():
        depth += line.count('{') - line.count('}')
        if depth < 0:
            return False
    return depth == 0


def conflicts(vhost_text):
    text = strip_block(vhost_text)
    return [m.group(0).rstrip(' {') for m in re.finditer(r'^context\s+%s\S*\s*\{' % re.escape(URL_PREFIX.rstrip('/')),
                                                         text, re.M)]


def apply_block(vhost_text, vh_root, release_dir):
    """Return vhost text with exactly one managed block, placed before vhssl like CyberPanel does."""
    if not brace_balanced(vhost_text):
        raise RoundcubeError('vhost.conf has unbalanced braces; refusing to edit it.')
    clashes = conflicts(vhost_text)
    if clashes:
        raise RoundcubeError('vhost.conf already defines %s; remove it first.' % ', '.join(clashes))
    base = strip_block(vhost_text).rstrip('\n') + '\n'
    block = render_vhost_block(vh_root, release_dir)
    match = re.search(r'^vhssl\s*\{', base, re.M)
    text = base[:match.start()] + block + '\n' + base[match.start():] if match else base + '\n' + block
    text = re.sub(r'\n{3,}', '\n\n', text)
    if not brace_balanced(text):
        raise RoundcubeError('The generated vhost has unbalanced braces; nothing was changed.')
    return text


def remove_block(vhost_text):
    text = re.sub(r'\n{3,}', '\n\n', strip_block(vhost_text).rstrip('\n') + '\n')
    if not brace_balanced(text):
        raise RoundcubeError('vhost.conf has unbalanced braces; refusing to edit it.')
    return text


def block_present(vhost_text):
    return MARK_BEGIN in vhost_text and MARK_END in vhost_text


# ----------------------------------------------------------------------------- web mirror

def render_stub(release_dir):
    if not SAFE_PATH_RE.match(release_dir):
        raise RoundcubeError('Invalid release path.')
    return ("<?php\n// Managed by CyberPanel Universal (Roundcube). Changes are overwritten.\n"
            "define('INSTALL_PATH', '%s/');\ninclude INSTALL_PATH . 'index.php';\n" % release_dir.rstrip('/'))


def is_static(relative):
    ext = os.path.splitext(relative)[1].lower()
    if ext not in STATIC_EXTENSIONS:
        return False
    return not (ext == '.html' and '/templates/' in '/' + relative)


def build_mirror(release_dir, target, chown=True):
    """(Re)create the web mirror: the stub plus static assets only. Refuses a foreign directory."""
    if os.path.lexists(target):
        if os.path.islink(target) or not os.path.isfile(os.path.join(target, MIRROR_MARKER)):
            raise RoundcubeError('%s exists and was not created by the panel; move it away first.' % target)
    parent = os.path.dirname(target)
    staging = tempfile.mkdtemp(prefix='.cp-roundcube-web-', dir=parent)
    try:
        os.chmod(staging, 0o755)
        count = 0
        for tree in PUBLIC_TREES:
            source_root = os.path.join(release_dir, tree)
            for directory, dirs, files in os.walk(source_root):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(directory, d))]
                for name in files:
                    source = os.path.join(directory, name)
                    relative = os.path.relpath(source, release_dir)
                    if os.path.islink(source) or not is_static(relative):
                        continue
                    destination = os.path.join(staging, relative)
                    os.makedirs(os.path.dirname(destination), mode=0o755, exist_ok=True)
                    shutil.copyfile(source, destination)
                    os.chmod(destination, 0o644)
                    count += 1
        for name, text in (('index.php', render_stub(release_dir)), (MIRROR_MARKER, 'managed by CyberPanel\n')):
            with open(os.path.join(staging, name), 'w') as handle:
                handle.write(text)
            os.chmod(os.path.join(staging, name), 0o644)
        for directory, dirs, files in os.walk(staging):
            os.chmod(directory, 0o755)
            if chown:
                for name in dirs + files:
                    os.lchown(os.path.join(directory, name), 0, 0)
        if chown:
            os.lchown(staging, 0, 0)
        if os.path.lexists(target):
            old = target + '.old-%d' % os.getpid()
            os.rename(target, old)
            os.rename(staging, target)
            shutil.rmtree(old, ignore_errors=True)
        else:
            os.rename(staging, target)
    finally:
        if os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)
    return count


def remove_mirror(target):
    if os.path.isdir(target) and not os.path.islink(target) and os.path.isfile(os.path.join(target, MIRROR_MARKER)):
        shutil.rmtree(target)
        return True
    return False


# ----------------------------------------------------------------------------- config.inc.php

def php_string(value):
    return "'%s'" % str(value).replace('\\', '\\\\').replace("'", "\\'")


def render_config(secret, imap_host, smtp_host, domain, force_https, sieve=False, product_name=PRODUCT_NAME):
    plugins = ['archive', 'zipdownload'] + (['managesieve'] if sieve else [])
    no_verify = "[\n  'ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true],\n]"
    lines = [
        '<?php',
        '// Managed by CyberPanel Universal (Roundcube). Changes are overwritten.',
        '$config = [];',
        '$config[\'db_dsnw\'] = %s;' % php_string('mysql://%s:%s@localhost/%s' % (DB_USER, secret['db_password'], DB_NAME)),
        '$config[\'imap_host\'] = %s;' % php_string(imap_host),
        # Local connections only: the mail certificates name the public hostnames, not 127.0.0.1.
        '$config[\'imap_conn_options\'] = %s;' % no_verify,
        '$config[\'smtp_host\'] = %s;' % php_string(smtp_host),
        '$config[\'smtp_user\'] = \'%u\';',
        '$config[\'smtp_pass\'] = \'%p\';',
        '$config[\'smtp_conn_options\'] = %s;' % no_verify,
        '$config[\'des_key\'] = %s;' % php_string(secret['des_key']),
        '$config[\'product_name\'] = %s;' % php_string(product_name),
        '$config[\'skin\'] = \'elastic\';',
        '$config[\'plugins\'] = [%s];' % ', '.join(php_string(p) for p in plugins),
        '$config[\'enable_installer\'] = false;',
        '$config[\'support_url\'] = \'\';',
        '$config[\'ip_check\'] = true;',
        '$config[\'login_rate_limit\'] = 3;',
        '$config[\'force_https\'] = %s;' % ('true' if force_https else 'false'),
        '$config[\'trusted_host_patterns\'] = [%s];' % ', '.join(php_string(h) for h in (domain, 'www.' + domain)),
        '$config[\'log_driver\'] = \'file\';',
    ]
    if sieve:
        lines += ['$config[\'managesieve_host\'] = \'tls://127.0.0.1:4190\';',
                  '$config[\'managesieve_conn_options\'] = %s;' % no_verify]
    return '\n'.join(lines) + '\n'


def write_config(release_dir, text, group_gid, chown=True):
    path = os.path.join(release_dir, 'config', 'config.inc.php')
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(text)
    if chown:
        os.chown(path + '.tmp', 0, group_gid)
    os.chmod(path + '.tmp', 0o640)
    os.replace(path + '.tmp', path)
    return path


def set_runtime_ownership(release_dir, uid, gid, chown=True):
    """temp/ and logs/ belong to the PHP user only; everything else stays root's."""
    for name in ('temp', 'logs'):
        path = os.path.join(release_dir, name)
        os.makedirs(path, mode=0o700, exist_ok=True)
        if chown:
            os.chown(path, uid, gid)
        os.chmod(path, 0o700)


# ----------------------------------------------------------------------------- PHP checks

def parse_php_modules(text):
    modules = set()
    for line in (text or '').splitlines():
        line = line.strip()
        if line and not line.startswith('['):
            modules.add(line.lower().replace(' ', '_'))
    return modules


def php_report(version_text, modules_text):
    modules = parse_php_modules(modules_text)
    missing = [ext for ext in REQUIRED_EXTENSIONS if ext not in modules]
    match = re.match(r'^(\d+)\.(\d+)', (version_text or '').strip())
    version = (int(match.group(1)), int(match.group(2))) if match else None
    return {'version': (version_text or '').strip()[:20], 'missing': missing,
            'version_ok': bool(version and version >= MIN_PHP), 'ok': not missing and bool(version and version >= MIN_PHP)}


def check_php(php_cli, runner=subprocess.run):
    code, version = run([php_cli, '-r', 'echo PHP_VERSION;'], runner, timeout=30)
    code2, modules = run([php_cli, '-m'], runner, timeout=30)
    if code != 0 or code2 != 0:
        return {'version': '', 'missing': list(REQUIRED_EXTENSIONS), 'version_ok': False, 'ok': False,
                'error': '%s could not run.' % php_cli}
    return php_report(version, modules)


# ----------------------------------------------------------------------------- database

def quote_sql(value):
    if not re.match(r'^[A-Za-z0-9_]+$', value or ''):
        raise RoundcubeError('Unsafe SQL value.')
    return "'%s'" % value


def create_db_sql(password):
    return '\n'.join([
        'CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;' % DB_NAME,
        "CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY %s;" % (DB_USER, quote_sql(password)),
        "ALTER USER '%s'@'localhost' IDENTIFIED BY %s;" % (DB_USER, quote_sql(password)),
        "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';" % (DB_NAME, DB_USER),
        'FLUSH PRIVILEGES;',
    ]) + '\n'


def drop_db_sql():
    return "DROP DATABASE IF EXISTS `%s`;\nDROP USER IF EXISTS '%s'@'localhost';\nFLUSH PRIVILEGES;\n" % (DB_NAME, DB_USER)


TABLES_SQL = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '%s';" % DB_NAME
USER_SQL = "SELECT COUNT(*) FROM mysql.user WHERE user = '%s' AND host = 'localhost';" % DB_USER


def mysql(sql, defaults, runner=subprocess.run, database=None, timeout=120):
    """Run SQL as the panel's MySQL root user; SQL (and any password in it) goes on stdin."""
    argv = ['mysql', '--defaults-extra-file=' + defaults, '-N', '-B'] + ([database] if database else [])
    code, out = run(argv, runner, timeout=timeout, input_text=sql)
    if code != 0:
        raise RoundcubeError('MySQL error: %s' % out.strip()[-300:])
    return out


def load_schema(path, defaults, runner=subprocess.run):
    with open(path) as handle:
        code, out = run(['mysql', '--defaults-extra-file=' + defaults, DB_NAME], runner, timeout=300, stdin=handle)
    if code != 0:
        raise RoundcubeError('Loading the Roundcube schema failed: %s' % out.strip()[-300:])


# ----------------------------------------------------------------------------- releases

def _version_key(tag):
    return tuple(int(p) for p in tag.split('.'))


def latest_in_branch(releases, branch=BRANCH):
    tags = [r.get('tag_name', '') for r in releases if not r.get('prerelease') and not r.get('draft')]
    tags = [t for t in tags if t.startswith(branch) and VERSION_RE.match(t)]
    return max(tags, key=_version_key) if tags else None


def upgrade_report(installed, latest):
    newer = bool(installed and latest and _version_key(latest) > _version_key(installed))
    return {'installed': installed, 'latest': latest, 'pinned': VERSION, 'update_available': newer,
            'release_url': 'https://github.com/roundcube/roundcubemail/releases/tag/%s' % latest if latest else None}


# ----------------------------------------------------------------------------- health check

def health_check(domain, ssl, runner=subprocess.run):
    scheme, port = ('https', '443') if ssl else ('http', '80')
    code, out = run(['curl', '-sS', '-k', '--max-time', '20', '-w', '\n%{http_code}', '--resolve',
                     '%s:%s:127.0.0.1' % (domain, port), '%s://%s%s' % (scheme, domain, URL_PREFIX)], runner, timeout=40)
    body, _, status = out.rpartition('\n')
    ok = code == 0 and status.strip() == '200' and 'rcmloginuser' in body
    return ok, status.strip()[-3:] or '000'


def deny_check(domain, ssl, runner=subprocess.run):
    """Every denied directory must answer 403 (or 404), never 200."""
    scheme, port = ('https', '443') if ssl else ('http', '80')
    results = {}
    for name in DENY_DIRS:
        code, out = run(['curl', '-sS', '-k', '--max-time', '10', '-o', '/dev/null', '-w', '%{http_code}', '--resolve',
                         '%s:%s:127.0.0.1' % (domain, port), '%s://%s%s%s/' % (scheme, domain, URL_PREFIX, name)],
                        runner, timeout=20)
        results[name] = out.strip()[-3:]
    return results
