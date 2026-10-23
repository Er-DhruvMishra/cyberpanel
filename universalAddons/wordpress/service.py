"""WordPress Manager Pro: discovery, safe updates, staging/push, hardening, performance, login.

Fixes, by design, the defects found in the official WP manager:
- WP-CLI always runs as the site's own Linux user with the site's PHP (never as root);
- staging push mirrors files (rsync --delete) and takes an automatic snapshot of production
  first; search-replace keeps the URL scheme (no https -> http downgrade);
- the WP-Cron toggle is real: DISABLE_WP_CRON plus a system cron job for the site user;
- one-time logins use a single-use, 60-second token and leave no extra admin account;
- password protection is not touched here (it belongs to the .htaccess module);
- every value that reaches WP-CLI is validated; argv lists only, no shell.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time

VHOSTS = '/usr/local/lsws/conf/vhosts'
WP_CLI = '/usr/bin/wp'
WP_CLI_URL = 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'
WP_CLI_SHA512_URL = WP_CLI_URL + '.sha512'
SNAPSHOT_DIRNAME = '.cp-wp-snapshots'
MU_LOGIN = 'cp-ua-onetime-login.php'

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,99}$')
SNAP_ID_RE = re.compile(r'^\d{8}-\d{6}-[0-9a-f]{4}$')


class WPError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=1800, env=None, cwd=None, input=None):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=env, cwd=cwd, input=input)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- site context

class Site:
    """A WordPress install: domain, Linux user, document root, PHP binary."""

    def __init__(self, domain, user, docroot, php):
        if not DOMAIN_RE.match(domain) or not USER_RE.match(user):
            raise WPError('Invalid site.')
        if not docroot.startswith('/home/') or '..' in docroot.split('/'):
            raise WPError('WordPress must live under /home.')
        self.domain, self.user, self.docroot, self.php = domain, user, os.path.normpath(docroot), php

    @property
    def home(self):
        return '/home/' + self.docroot.split('/')[2]

    def wp(self, *args, runner=subprocess.run, timeout=1800, input=None):
        """Run WP-CLI as the site user. Returns (code, output). Secrets go through `input` (--prompt)."""
        for arg in args:
            if not isinstance(arg, str) or '\x00' in arg:
                raise WPError('Invalid WP-CLI argument.')
        argv = ['sudo', '-u', self.user, '-H', '--', self.php, WP_CLI, '--path=' + self.docroot, '--skip-themes',
                '--no-color'] + list(args)
        return run(argv, runner, timeout=timeout, input=input)

    def wp_ok(self, *args, runner=subprocess.run, timeout=1800, input=None):
        code, out = self.wp(*args, runner=runner, timeout=timeout, input=input)
        if code != 0:
            raise WPError('wp %s failed: %s' % (' '.join(args[:2]), _clean(out)[-800:]))
        return out

    def wp_json(self, *args, runner=subprocess.run):
        out = self.wp_ok(*(args + ('--format=json',)), runner=runner)
        start = min([i for i in (out.find('['), out.find('{')) if i >= 0] or [0])
        try:
            return json.loads(out[start:])
        except ValueError:
            raise WPError('Unexpected WP-CLI output: ' + _clean(out)[-300:])


def _clean(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text or '').strip()


def _last(text):
    """Last non-empty output line ('' when WP-CLI printed nothing, e.g. a constant set to false)."""
    lines = [line for line in _clean(text).splitlines() if line.strip()]
    return lines[-1].strip() if lines else ''


def php_for_vhost(domain, vhosts=VHOSTS):
    """CLI php that matches the lsphp the site's vhost uses (fallback: /usr/bin/php)."""
    try:
        with open(os.path.join(vhosts, domain, 'vhost.conf')) as handle:
            match = re.search(r'/usr/local/lsws/(lsphp\d+)/bin/lsphp', handle.read())
    except OSError:
        match = None
    if match:
        candidate = '/usr/local/lsws/%s/bin/php' % match.group(1)
        if os.path.exists(candidate):
            return candidate
    return '/usr/bin/php'


def find_installs(docroots):
    """docroots: list of (domain, user, docroot, vhost_domain). Return those that hold WordPress."""
    found = []
    for domain, user, docroot, vhost_domain in docroots:
        in_docroot = os.path.isfile(os.path.join(docroot, 'wp-config.php'))
        # WordPress also allows wp-config.php one level above the document root.
        above = os.path.isfile(os.path.join(os.path.dirname(docroot), 'wp-config.php')) and \
            os.path.isfile(os.path.join(docroot, 'wp-load.php'))
        if in_docroot or above:
            found.append({'domain': domain, 'user': user, 'docroot': docroot, 'vhost': vhost_domain})
    return found


# ----------------------------------------------------------------------------- info

def info(site, runner=subprocess.run):
    data = {'domain': site.domain, 'docroot': site.docroot}
    code, out = site.wp('core', 'version', runner=runner)
    if code != 0:
        raise WPError('This does not look like a working WordPress install: ' + _clean(out)[-400:])
    data['version'] = _last(out)
    data['siteurl'] = _last(site.wp_ok('option', 'get', 'siteurl', runner=runner))
    data['core_updates'] = site.wp_json('core', 'check-update', runner=runner) if \
        site.wp('core', 'check-update', '--format=count', runner=runner)[1].strip() not in ('', '0') else []
    try:
        data['plugins'] = site.wp_json('plugin', 'list',
                                       '--fields=name,status,version,update,update_version,auto_update', runner=runner)
    except WPError:  # WP-CLI < 2.7 has no auto_update field
        data['plugins'] = site.wp_json('plugin', 'list', '--fields=name,status,version,update,update_version',
                                       runner=runner)
    data['themes'] = site.wp_json('theme', 'list', '--fields=name,status,version,update,update_version',
                                  runner=runner)
    flags = {}
    for constant in ('WP_DEBUG', 'DISALLOW_FILE_EDIT', 'DISABLE_WP_CRON'):
        code, out = site.wp('config', 'get', constant, '--type=constant', runner=runner)
        flags[constant] = code == 0 and _last(out).lower() in ('1', 'true')
    data['flags'] = flags
    data['maintenance'] = os.path.exists(os.path.join(site.docroot, '.maintenance'))
    data['indexing'] = _clean(site.wp_ok('option', 'get', 'blog_public', runner=runner)).endswith('1')
    return data


# ----------------------------------------------------------------------------- snapshots

def _snapshot_root(site):
    return os.path.join(site.home, SNAPSHOT_DIRNAME)


def snapshot(site, label='manual', runner=subprocess.run):
    """Copy wp-content + wp-config.php and export the database, as the site user."""
    snap_id = time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(2)
    directory = os.path.join(_snapshot_root(site), snap_id)
    code, out = run(['sudo', '-u', site.user, 'mkdir', '-p', '-m', '0700', directory], runner)
    if code != 0:
        raise WPError('Could not create snapshot directory: ' + out)
    site.wp_ok('db', 'export', os.path.join(directory, 'database.sql'), runner=runner)
    code, out = run(['sudo', '-u', site.user, 'tar', '-C', site.docroot, '-czf', os.path.join(directory, 'files.tar.gz'),
                     '--exclude=./wp-content/cache', '--exclude=./wp-content/litespeed', '.'], runner, timeout=3600)
    if code not in (0, 1):  # 1 = files changed while reading
        raise WPError('Could not archive the site files: ' + out[-500:])
    meta = json.dumps({'label': label, 'created': int(time.time()), 'docroot': site.docroot})
    code, out = run_input(['sudo', '-u', site.user, 'tee', os.path.join(directory, 'meta.json')], meta, runner)
    if code != 0:
        raise WPError('Could not write snapshot metadata: ' + out[-300:])
    return snap_id


def list_snapshots(site):
    items = []
    root = _snapshot_root(site)
    if os.path.isdir(root):
        for name in sorted(os.listdir(root), reverse=True):
            if not SNAP_ID_RE.match(name):
                continue
            try:
                with open(os.path.join(root, name, 'meta.json')) as handle:
                    meta = json.load(handle)
            except (OSError, ValueError):
                meta = {}
            if meta.get('docroot', site.docroot) == site.docroot:
                items.append({'id': name, 'label': meta.get('label', ''), 'created': meta.get('created', 0)})
    return items


def rollback(site, snap_id, runner=subprocess.run):
    if not SNAP_ID_RE.match(snap_id or ''):
        raise WPError('Invalid snapshot id.')
    directory = os.path.join(_snapshot_root(site), snap_id)
    if not os.path.isfile(os.path.join(directory, 'files.tar.gz')):
        raise WPError('Snapshot not found.')
    code, out = run(['sudo', '-u', site.user, 'tar', '-C', site.docroot, '-xzf',
                     os.path.join(directory, 'files.tar.gz')], runner, timeout=3600)
    if code != 0:
        raise WPError('Restoring files failed: ' + out[-500:])
    site.wp_ok('db', 'import', os.path.join(directory, 'database.sql'), runner=runner)
    site.wp('cache', 'flush', runner=runner)
    return {'rolled_back_to': snap_id}


def prune_snapshots(site, keep=5):
    removed = []
    for item in list_snapshots(site)[keep:]:
        shutil.rmtree(os.path.join(_snapshot_root(site), item['id']), ignore_errors=True)
        removed.append(item['id'])
    return removed


# ----------------------------------------------------------------------------- health / updates

def health_check(site, url, runner=subprocess.run):
    """Fetch the home page through this server and look for fatal-error markers."""
    match = re.match(r'^(https?)://([^/:]+)(:\d+)?(/.*)?$', url or '')
    if not match:
        raise WPError('Unexpected site URL %r.' % url)
    scheme, host = match.group(1), match.group(2)
    port = '443' if scheme == 'https' else '80'
    code, out = run(['curl', '-sS', '-k', '-L', '--max-redirs', '3', '--max-time', '30', '-o', '/dev/stdout',
                     '-w', '\n%{http_code}', '--resolve', '%s:%s:127.0.0.1' % (host, port), url], runner, timeout=60)
    status = out.strip().splitlines()[-1] if out.strip() else '000'
    body = out[:-len(status)] if status else out
    fatal = any(marker in body for marker in ('There has been a critical error', 'Fatal error</b>',
                                               'Error establishing a database connection'))
    ok = code == 0 and status.isdigit() and int(status) < 500 and not fatal
    return {'ok': ok, 'status': status, 'fatal_marker': fatal}


def safe_update(site, scope, runner=subprocess.run, log=None):
    """Snapshot, update, health-check; roll back automatically if the site broke."""
    if scope not in ('core', 'plugins', 'themes', 'all'):
        raise WPError('Update core, plugins, themes or all.')
    say = log or (lambda text: None)
    url = _last(site.wp_ok('option', 'get', 'home', runner=runner))
    before = health_check(site, url, runner)
    say('health before: HTTP %s' % before['status'])
    snap_id = snapshot(site, 'before %s update' % scope, runner)
    say('snapshot %s taken' % snap_id)
    steps = {'core': [('core', 'update'), ('core', 'update-db')], 'plugins': [('plugin', 'update', '--all')],
             'themes': [('theme', 'update', '--all')]}
    order = ['core', 'plugins', 'themes'] if scope == 'all' else [scope]
    for part in order:
        for args in steps[part]:
            code, out = site.wp(*args, runner=runner)
            say('wp %s: exit %d\n%s' % (' '.join(args), code, _clean(out)[-1500:]))
    after = health_check(site, url, runner)
    say('health after: HTTP %s%s' % (after['status'], ', fatal error page' if after['fatal_marker'] else ''))
    if before['ok'] and not after['ok']:
        rollback(site, snap_id, runner)
        say('site broke after updating; rolled back to %s' % snap_id)
        raise WPError('The update broke the site (HTTP %s); it was rolled back to snapshot %s.' % (
            after['status'], snap_id))
    prune_snapshots(site)
    return {'snapshot': snap_id, 'health': after}


def set_auto_updates(site, kind, enable, runner=subprocess.run):
    if kind not in ('plugin', 'theme'):
        raise WPError('Invalid auto-update kind.')
    return _clean(site.wp_ok(kind, 'auto-updates', 'enable' if enable else 'disable', '--all', runner=runner))


def manage_item(site, kind, action, slug, runner=subprocess.run):
    if kind not in ('plugin', 'theme') or not SLUG_RE.match(slug or ''):
        raise WPError('Invalid item.')
    allowed = {'plugin': ('activate', 'deactivate', 'update', 'delete', 'install'),
               'theme': ('activate', 'update', 'delete', 'install')}
    if action not in allowed[kind]:
        raise WPError('Invalid action.')
    return _clean(site.wp_ok(kind, action, slug, runner=runner))


# ----------------------------------------------------------------------------- settings / hardening

def set_flag(site, flag, enable, runner=subprocess.run, cron_writer=None):
    if flag in ('WP_DEBUG', 'DISALLOW_FILE_EDIT'):
        return site.wp_ok('config', 'set', flag, 'true' if enable else 'false', '--raw', '--type=constant',
                          runner=runner)
    if flag == 'DISABLE_WP_CRON':
        site.wp_ok('config', 'set', flag, 'true' if enable else 'false', '--raw', '--type=constant', runner=runner)
        (cron_writer or write_site_cron)(site, enable, runner)
        return 'WP-Cron %s' % ('runs from system cron every 5 minutes' if enable else 'runs on page loads again')
    if flag == 'indexing':
        return site.wp_ok('option', 'update', 'blog_public', '1' if enable else '0', runner=runner)
    if flag == 'maintenance':
        return site.wp_ok('maintenance-mode', 'activate' if enable else 'deactivate', runner=runner)
    raise WPError('Unknown setting.')


def cron_line(site):
    return '*/5 * * * * %s %s --path=%s cron event run --due-now --quiet >/dev/null 2>&1  # cp-ua-wpcron %s' % (
        site.php, WP_CLI, site.docroot, site.docroot)


def write_site_cron(site, enable, runner=subprocess.run):
    code, current = run(['crontab', '-l', '-u', site.user], runner)
    lines = [l for l in (current.splitlines() if code == 0 else []) if l.strip() and
             not l.endswith('# cp-ua-wpcron %s' % site.docroot)]
    if enable:
        lines.append(cron_line(site))
    code, out = run_input(['crontab', '-u', site.user, '-'], '\n'.join(lines) + '\n', runner)
    if code != 0:
        raise WPError('Could not update the site crontab: ' + out)


def run_input(argv, text, runner=subprocess.run):
    out = runner(argv, input=text, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                 timeout=60)
    return out.returncode, out.stdout or ''


XMLRPC_BLOCK = ('# BEGIN cp-ua xmlrpc\n<IfModule mod_rewrite.c>\nRewriteEngine On\n'
                'RewriteRule ^xmlrpc\\.php$ - [F,L]\n</IfModule>\n# END cp-ua xmlrpc\n')


def set_xmlrpc_block(site, enable, runner=subprocess.run):
    """Insert/remove a marked block at the top of .htaccess (the rest of the file is kept)."""
    path = os.path.join(site.docroot, '.htaccess')
    try:
        with open(path) as handle:
            content = handle.read()
    except OSError:
        content = ''
    content = re.sub(r'# BEGIN cp-ua xmlrpc\n.*?# END cp-ua xmlrpc\n', '', content, flags=re.S)
    if enable:
        content = XMLRPC_BLOCK + content
    code, out = run_input(['sudo', '-u', site.user, 'tee', path], content, runner)
    if code != 0:
        raise WPError('Could not write .htaccess: ' + out[-300:])
    return 'XML-RPC %s' % ('blocked' if enable else 'allowed')


def hardening_report(site, runner=subprocess.run):
    checks = []
    data = info(site, runner)
    admins = site.wp_json('user', 'list', '--role=administrator', '--fields=user_login', runner=runner)
    checks.append({'id': 'file_edit', 'ok': data['flags']['DISALLOW_FILE_EDIT'],
                   'title': 'Theme/plugin editor disabled', 'fix': 'DISALLOW_FILE_EDIT'})
    checks.append({'id': 'debug', 'ok': not data['flags']['WP_DEBUG'], 'title': 'WP_DEBUG off in production',
                   'fix': 'WP_DEBUG'})
    checks.append({'id': 'admin_user', 'ok': not any(a['user_login'].lower() == 'admin' for a in admins),
                   'title': 'No administrator called "admin"', 'fix': None})
    try:
        with open(os.path.join(site.docroot, '.htaccess')) as handle:
            xmlrpc = '# BEGIN cp-ua xmlrpc' in handle.read()
    except OSError:
        xmlrpc = False
    checks.append({'id': 'xmlrpc', 'ok': xmlrpc, 'title': 'XML-RPC blocked', 'fix': 'xmlrpc'})
    config = os.path.join(site.docroot, 'wp-config.php')
    mode = os.stat(config).st_mode & 0o777 if os.path.exists(config) else 0
    checks.append({'id': 'config_perms', 'ok': mode and not mode & 0o007, 'title': 'wp-config.php not world-readable',
                   'fix': 'config_perms', 'detail': '%04o' % mode})
    code, out = site.wp('core', 'verify-checksums', runner=runner)
    checks.append({'id': 'core_checksums', 'ok': code == 0, 'title': 'Core files match WordPress.org checksums',
                   'detail': '' if code == 0 else _clean(out)[-600:], 'fix': None})
    code, out = site.wp('plugin', 'verify-checksums', '--all', runner=runner)
    checks.append({'id': 'plugin_checksums', 'ok': code == 0, 'title': 'Plugin files match WordPress.org checksums',
                   'detail': '' if code == 0 else _clean(out)[-600:], 'fix': None})
    return checks


def apply_fix(site, fix, runner=subprocess.run):
    if fix == 'DISALLOW_FILE_EDIT':
        return set_flag(site, 'DISALLOW_FILE_EDIT', True, runner)
    if fix == 'WP_DEBUG':
        return set_flag(site, 'WP_DEBUG', False, runner)
    if fix == 'xmlrpc':
        return set_xmlrpc_block(site, True, runner)
    if fix == 'config_perms':
        code, out = run(['chmod', '0640', os.path.join(site.docroot, 'wp-config.php')], runner)
        if code != 0:
            raise WPError(out)
        return 'wp-config.php is now 0640'
    if fix == 'salts':
        return site.wp_ok('config', 'shuffle-salts', runner=runner)
    raise WPError('Unknown fix.')


# ----------------------------------------------------------------------------- performance

def enable_lscache(site, runner=subprocess.run):
    return site.wp_ok('plugin', 'install', 'litespeed-cache', '--activate', runner=runner)


def enable_object_cache(site, runner=subprocess.run, which=shutil.which):
    if not which('redis-server') and not os.path.exists('/usr/bin/redis-server'):
        raise WPError('Redis is not installed on this server.')
    site.wp_ok('plugin', 'install', 'redis-cache', '--activate', runner=runner)
    return site.wp_ok('redis', 'enable', runner=runner)


# ----------------------------------------------------------------------------- one-time login

MU_PLUGIN = r"""<?php
/*
 * CyberPanel Universal one-time login (single use, expires after 60 seconds).
 * Installed and removed by the panel; it does nothing without a valid token.
 */
add_action('init', function () {
    if (empty($_GET['cp_ua_login'])) { return; }
    $stored = get_option('cp_ua_login_token');
    delete_option('cp_ua_login_token');
    if (!is_array($stored) || time() > intval($stored['expires'])
        || !hash_equals($stored['hash'], hash('sha256', (string) $_GET['cp_ua_login']))) {
        wp_die('This login link has expired.', 403);
    }
    $user = get_user_by('id', intval($stored['user']));
    if (!$user || !user_can($user, 'manage_options')) { wp_die('Login unavailable.', 403); }
    wp_set_auth_cookie($user->ID, false);
    wp_safe_redirect(admin_url());
    exit;
});
"""


def one_time_login(site, runner=subprocess.run):
    admins = site.wp_json('user', 'list', '--role=administrator', '--fields=ID,user_login', runner=runner)
    if not admins:
        raise WPError('The site has no administrator account.')
    mu_dir = os.path.join(site.docroot, 'wp-content', 'mu-plugins')
    run(['sudo', '-u', site.user, 'mkdir', '-p', mu_dir], runner)
    code, out = run_input(['sudo', '-u', site.user, 'tee', os.path.join(mu_dir, MU_LOGIN)], MU_PLUGIN, runner)
    if code != 0:
        raise WPError('Could not install the login helper: ' + out[-300:])
    token = secrets.token_urlsafe(32)
    value = json.dumps({'hash': hashlib.sha256(token.encode()).hexdigest(), 'expires': int(time.time()) + 60,
                        'user': int(admins[0]['ID'])})
    site.wp_ok('option', 'update', 'cp_ua_login_token', value, '--format=json', runner=runner)
    home = _last(site.wp_ok('option', 'get', 'home', runner=runner)).rstrip('/')
    return {'url': '%s/?cp_ua_login=%s' % (home, token), 'user': admins[0]['user_login'], 'expires_in': 60}


# ----------------------------------------------------------------------------- staging / push

def _db_credentials(site, runner=subprocess.run):
    creds = {}
    for name in ('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'):
        creds[name] = _last(site.wp_ok('config', 'get', name, runner=runner))
    return creds


def clone(source, target, create_database, runner=subprocess.run, log=None, mode='staging'):
    """Copy source WordPress into target's docroot (files + database + URL rewrite).

    `create_database()` returns (name, user, password) of a fresh empty database for the target.
    The source keeps working; the target's wp-config.php gets its own DB credentials.
    """
    say = log or (lambda text: None)
    if source.docroot == target.docroot:
        raise WPError('Source and target are the same.')
    if os.path.isfile(os.path.join(target.docroot, 'wp-config.php')) and mode == 'staging':
        raise WPError('The target already has a WordPress install. Choose an empty site, or push instead.')
    source_url = _last(source.wp_ok('option', 'get', 'home', runner=runner)).rstrip('/')
    scheme = source_url.split('://', 1)[0]
    target_url = '%s://%s' % (scheme, target.domain)
    export = os.path.join(target.home, '.cp-wp-clone-%s.sql' % secrets.token_hex(4))
    try:
        code, out = run(['rsync', '-a', '--delete', '--exclude', 'wp-config.php', '--exclude', '.htaccess',
                         '--exclude', 'wp-content/cache/', source.docroot + '/', target.docroot + '/'], runner, timeout=7200)
        if code != 0:
            raise WPError('Copying files failed: ' + out[-500:])
        run(['chown', '-R', '%s:%s' % (target.user, target.user), target.docroot], runner, timeout=3600)
        say('files copied')
        code, out = run(['sudo', '-u', source.user, '-H', '--', source.php, WP_CLI, '--path=' + source.docroot,
                         'db', 'export', '-'], runner, timeout=3600)
        if code != 0:
            raise WPError('Database export failed: ' + _clean(out)[-500:])
        with open(export, 'w') as handle:
            handle.write(out)
        os.chmod(export, 0o600)
        shutil.chown(export, target.user, target.user)
        name, user, password = create_database()
        config = os.path.join(target.docroot, 'wp-config.php')
        shutil.copy2(os.path.join(source.docroot, 'wp-config.php'), config)
        shutil.chown(config, target.user, target.user)
        for key, value in (('DB_NAME', name), ('DB_USER', user), ('DB_HOST', 'localhost')):
            target.wp_ok('config', 'set', key, value, runner=runner)
        set_config_secret(config, 'DB_PASSWORD', password)
        target.wp_ok('config', 'shuffle-salts', runner=runner)
        target.wp_ok('db', 'import', export, runner=runner)
        say('database imported')
        target.wp_ok('search-replace', source_url, target_url, '--all-tables-with-prefix', '--precise',
                     '--skip-columns=guid', runner=runner)
        for constant in ('WP_HOME', 'WP_SITEURL'):  # hard-coded URLs in wp-config.php
            if target.wp('config', 'has', constant, '--type=constant', runner=runner)[0] == 0:
                target.wp_ok('config', 'set', constant, target_url, '--type=constant', runner=runner)
        if mode == 'staging':
            target.wp_ok('option', 'update', 'blog_public', '0', runner=runner)
        target.wp('cache', 'flush', runner=runner)
        say('URLs rewritten %s -> %s' % (source_url, target_url))
    finally:
        if os.path.exists(export):
            os.unlink(export)
    return {'source': source_url, 'target': target_url}


def set_config_secret(config_path, constant, value):
    """Set a string constant in wp-config.php without putting the value on a command line."""
    escaped = value.replace('\\', '\\\\').replace("'", "\\'")
    with open(config_path) as handle:
        text = handle.read()
    pattern = re.compile(r"define\(\s*['\"]%s['\"]\s*,\s*(['\"]).*?\1\s*\)" % constant)
    if not pattern.search(text):
        raise WPError('%s not found in wp-config.php.' % constant)
    text = pattern.sub(lambda m: "define( '%s', '%s' )" % (constant, escaped), text, count=1)
    with open(config_path, 'w') as handle:
        handle.write(text)


def push(staging, production, runner=subprocess.run, log=None):
    """Publish staging over production: snapshot production, mirror files, replace DB, fix URLs."""
    say = log or (lambda text: None)
    snap_id = snapshot(production, 'before push from %s' % staging.domain, runner)
    say('production snapshot %s taken' % snap_id)
    prod_url = _last(production.wp_ok('option', 'get', 'home', runner=runner)).rstrip('/')
    stage_url = _last(staging.wp_ok('option', 'get', 'home', runner=runner)).rstrip('/')
    export = os.path.join(production.home, '.cp-wp-push-%s.sql' % secrets.token_hex(4))
    try:
        code, out = run(['rsync', '-a', '--delete', '--exclude', 'wp-config.php', '--exclude', '.htaccess',
                         '--exclude', 'wp-content/cache/', staging.docroot + '/', production.docroot + '/'], runner,
                        timeout=7200)
        if code != 0:
            raise WPError('Copying files failed (production snapshot %s): %s' % (snap_id, out[-500:]))
        run(['chown', '-R', '%s:%s' % (production.user, production.user), production.docroot], runner, timeout=3600)
        code, out = run(['sudo', '-u', staging.user, '-H', '--', staging.php, WP_CLI, '--path=' + staging.docroot,
                         'db', 'export', '-'], runner, timeout=3600)
        if code != 0:
            raise WPError('Staging database export failed: ' + _clean(out)[-500:])
        with open(export, 'w') as handle:
            handle.write(out)
        os.chmod(export, 0o600)
        shutil.chown(export, production.user, production.user)
        production.wp_ok('db', 'import', export, runner=runner)
        production.wp_ok('search-replace', stage_url, prod_url, '--all-tables-with-prefix', '--precise',
                         '--skip-columns=guid', runner=runner)
        production.wp_ok('option', 'update', 'blog_public', '1', runner=runner)
        production.wp('cache', 'flush', runner=runner)
        say('pushed %s -> %s' % (stage_url, prod_url))
    except Exception:
        say('push failed; rolling production back to %s' % snap_id)
        rollback(production, snap_id, runner)
        raise
    finally:
        if os.path.exists(export):
            os.unlink(export)
    return {'snapshot': snap_id, 'from': stage_url, 'to': prod_url}


# ----------------------------------------------------------------------------- wp-cli self-update

def update_wp_cli(runner=subprocess.run, target=WP_CLI):
    """Download the latest WP-CLI phar and install it only if its SHA-512 matches."""
    import tempfile
    directory = tempfile.mkdtemp()
    phar = os.path.join(directory, 'wp-cli.phar')
    try:
        for url, path in ((WP_CLI_URL, phar), (WP_CLI_SHA512_URL, phar + '.sha512')):
            code, out = run(['curl', '-fsSL', '-o', path, url], runner, timeout=300)
            if code != 0:
                raise WPError('Download failed: %s' % out[-300:])
        with open(phar + '.sha512') as handle:
            expected = handle.read().split()[0].strip().lower()
        digest = hashlib.sha512()
        with open(phar, 'rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise WPError('WP-CLI checksum mismatch; not installed.')
        os.chmod(phar, 0o755)
        shutil.move(phar, target)
        code, out = run(['/usr/bin/php', target, '--version', '--allow-root'], runner, timeout=60)
        return {'version': _clean(out)}
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# ----------------------------------------------------------------------------- fresh install

ADMIN_USER_RE = re.compile(r'^[A-Za-z0-9._-]{3,60}$')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+=-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$')


def validate_install(title, admin_user, admin_email, locale='en_US'):
    title = (title or '').strip()
    if not title or len(title) > 120 or any(c in title for c in '\n\r\x00'):
        raise WPError('Enter a site title (up to 120 characters).')
    if not ADMIN_USER_RE.match(admin_user or '') or admin_user.lower() == 'admin':
        raise WPError('Choose an administrator name (3-60 letters, digits, . _ -) other than "admin".')
    if not EMAIL_RE.match(admin_email or ''):
        raise WPError('Enter a valid administrator e-mail.')
    if not re.match(r'^[a-z]{2,3}(_[A-Z]{2})?$', locale or ''):
        raise WPError('Invalid locale.')
    return title, admin_user, admin_email, locale


def install_wordpress(site, title, admin_user, admin_email, create_database, locale='en_US', runner=subprocess.run,
                      log=None, scheme='https'):
    """Install WordPress into an empty document root, as the site user.

    The administrator gets a random password that is never stored or shown; the panel offers a
    one-time login link instead, and the administrator sets a password inside WordPress.
    """
    say = log or (lambda text: None)
    title, admin_user, admin_email, locale = validate_install(title, admin_user, admin_email, locale)
    if os.path.exists(os.path.join(site.docroot, 'wp-config.php')):
        raise WPError('WordPress is already installed here.')
    leftovers = [n for n in os.listdir(site.docroot) if n not in ('index.html', '.htaccess', '.well-known', 'cgi-bin')] \
        if os.path.isdir(site.docroot) else []
    if leftovers:
        raise WPError('The document root is not empty (%s). Use an empty site.' % ', '.join(sorted(leftovers)[:5]))
    site.wp_ok('core', 'download', '--locale=' + locale, '--force', runner=runner)
    say('core downloaded')
    name, user, password = create_database()
    site.wp_ok('config', 'create', '--dbname=' + name, '--dbuser=' + user, '--dbhost=localhost', '--skip-check',
               '--prompt=dbpass', runner=runner, input=password + '\n')
    run(['chmod', '0640', os.path.join(site.docroot, 'wp-config.php')], runner)
    admin_password = secrets.token_urlsafe(18)
    site.wp_ok('core', 'install', '--url=%s://%s' % (scheme, site.domain), '--title=' + title,
               '--admin_user=' + admin_user, '--admin_email=' + admin_email, '--skip-email',
               '--prompt=admin_password', runner=runner, input=admin_password + '\n')
    index = os.path.join(site.docroot, 'index.html')
    if os.path.exists(index):
        os.unlink(index)
    say('WordPress installed')
    del admin_password
    return {'url': '%s://%s/wp-admin/' % (scheme, site.domain), 'admin_user': admin_user, 'database': name}
