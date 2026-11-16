"""Root-side Site Tools actions (dispatched by universalAddons/runner.py).

Sites are resolved from the panel database (siteinfo.resolve); requests only name a domain and
a relative path. Site files are read without following links (siteinfo.read_owned) and written
as the site user (siteinfo.write_as / run_as). vhost.conf writes go through the add-ons' shared
writer (htaccess.service: backup, atomic write) followed by the graceful OpenLiteSpeed restart
(lswsctrl restart) and a health check; a failure restores the previous file and restarts again.
"""
import contextlib
import fcntl
import grp
import gzip
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time

from universalAddons import jobs, siteinfo
from universalAddons.sitetools import service as st
from universalAddons.sitetools.service import SiteToolsError

STATE_FILE = '/etc/cyberpanel/universal-sitetools.json'
BACKUP_ROOT = '/var/lib/cyberpanel-universal/sitetools'
VHOSTS = '/usr/local/lsws/conf/vhosts'
WP_ADDON_URL = '/addons/wordpress/'
DB_NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,64}$')
BACKUP_ID_RE = re.compile(r'^\d{8}-\d{6}-[0-9a-f]{4}$')
KEEP_BACKUPS = 5
MAX_HTACCESS = 1024 * 1024


def resolve(domain):
    return siteinfo.resolve(domain)


def restart():
    from universalAddons.htaccess import service as hs
    return hs.restart()


def status(domain):
    from universalAddons.limits import service as ls
    return ls.http_status(domain)[1]


def _broken(before, after):
    bad = lambda s: s == '000' or str(s).startswith('5')
    return bad(after) and not bad(before)


# ----------------------------------------------------------------------------- state

def load_state(path=None):
    try:
        with open(path or STATE_FILE) as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data.setdefault('sites', {})
    data.setdefault('staging', {})
    data.setdefault('changed', {})
    return data


def save_state(data, path=None):
    path = path or STATE_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(temporary, path)


@contextlib.contextmanager
def locked_state(path=None):
    """Load the state under an exclusive lock; it is saved only if the block finishes without error."""
    path = path or STATE_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = load_state(path)
        yield state
        save_state(state, path)


def _site_state(state, domain):
    return state['sites'].setdefault(domain, {})


def _throttle(state, domain, min_interval):
    """Site owners: changes that restart OpenLiteSpeed at most once every min_interval seconds per site."""
    if not min_interval:
        return
    wait = int(state['changed'].get(domain, 0) + min_interval - time.time())
    if wait > 0:
        raise SiteToolsError('This site was changed a moment ago; try again in %d seconds.' % wait)


def _mark_changed(state, domain):
    now = time.time()
    state['changed'] = {d: t for d, t in state['changed'].items() if isinstance(t, (int, float)) and t > now - 86400}
    state['changed'][domain] = int(now)


# ----------------------------------------------------------------------------- writers

def vhost_path(site):
    return os.path.join(VHOSTS, site.vhost, 'vhost.conf')


def read_vhost(site):
    path = vhost_path(site)
    if not os.path.isfile(path):
        raise SiteToolsError('No OpenLiteSpeed vhost for %s.' % site.domain)
    with open(path) as handle:
        return handle.read()


def write_vhost_block(site, markers, body, backup_root=None):
    """Replace our block in vhost.conf: backup, validate, atomic write, graceful restart, health check."""
    from universalAddons.htaccess import service as hs
    path = vhost_path(site)
    before = read_vhost(site)
    after = st.set_vhost_block(before, markers, body)
    if after == before:
        return {'changed': False}
    if not st.braces_balanced(after):
        raise SiteToolsError('The new vhost.conf would not be valid (unbalanced braces); nothing was changed.')
    was = status(site.domain)
    saved = hs._backup([path], os.path.join(backup_root or BACKUP_ROOT, 'vhost'))
    try:
        hs._write_atomic(path, after)
        with open(path) as handle:
            if handle.read() != after:
                raise SiteToolsError('vhost.conf did not read back as written.')
        if not restart():
            raise SiteToolsError('OpenLiteSpeed did not come back after the graceful restart.')
        now = status(site.domain)
        if _broken(was, now):
            raise SiteToolsError('%s answered HTTP %s after the change (HTTP %s before).' % (site.domain, now, was))
    except Exception as exc:
        hs._restore(saved)
        restart()
        raise SiteToolsError('%s The previous vhost.conf was restored.' % exc)
    return {'changed': True, 'status': now}


def _text_backup(domain, name, text, backup_root=None):
    directory = os.path.join(backup_root or BACKUP_ROOT, 'files', domain)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, '%s-%s%s' % (time.strftime('%Y%m%d-%H%M%S'), secrets.token_hex(2), name))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(text if text is not None else '')
    names = sorted(n for n in os.listdir(directory) if n.endswith(name))
    for old in names[:-20]:
        os.unlink(os.path.join(directory, old))
    return path


def read_htaccess(site):
    path = os.path.join(site.docroot, '.htaccess')
    text = siteinfo.read_owned(site, path, max_bytes=MAX_HTACCESS)
    if text is not None and len(text.encode('utf-8', 'replace')) >= MAX_HTACCESS:
        raise SiteToolsError('.htaccess is larger than 1 MB; it is not edited automatically.')
    return text


def write_htaccess_block(site, markers, lines, backup_root=None, runner=subprocess.run):
    """Replace our block in the document root's .htaccess, as the site user, then restart gracefully
    (as the panel's Rewrite Rules page does) and check the site; restore the old file on failure."""
    path = os.path.join(site.docroot, '.htaccess')
    before = read_htaccess(site)
    after = st.set_htaccess_block(before or '', markers, lines)
    if after == (before or ''):
        return {'changed': False}
    _text_backup(site.domain, '.htaccess', before, backup_root)
    was = status(site.domain)
    siteinfo.write_as(site, path, after, mode_like=path if before is not None else None, runner=runner)
    try:
        if not restart():
            raise SiteToolsError('OpenLiteSpeed did not come back after the graceful restart.')
        now = status(site.domain)
        if _broken(was, now):
            raise SiteToolsError('%s answered HTTP %s after the change (HTTP %s before).' % (site.domain, now, was))
    except Exception as exc:
        if before is None:
            siteinfo.run_as(site, ['rm', '-f', '--', path], runner=runner, timeout=30)
        else:
            siteinfo.write_as(site, path, before, mode_like=path, runner=runner)
        restart()
        raise SiteToolsError('%s The previous .htaccess was restored.' % exc)
    return {'changed': True, 'status': now}


# ----------------------------------------------------------------------------- sites and overview

def _django():
    from universalAddons import django_env
    django_env.setup()


def list_sites(domains=None):
    from universalAddons.wordpress.actions import _docroots
    rows = _docroots()
    if domains is not None:
        wanted = {str(d).lower() for d in domains}
        rows = [r for r in rows if r[0] in wanted]
    return {'sites': sorted({r[0] for r in rows})}


def is_wordpress(site):
    from universalAddons.wordpress.service import find_installs
    return bool(find_installs([(site.domain, site.user, site.docroot, site.vhost)]))


def _website(domain):
    _django()
    from websiteFunctions.models import ChildDomains, Websites
    try:
        return Websites.objects.get(domain=domain)
    except Websites.DoesNotExist:
        return ChildDomains.objects.select_related('master').get(domain=domain).master


def panel_databases(domain):
    """Database names the panel records for the website a domain belongs to."""
    _django()
    from databases.models import Databases
    return sorted(d.dbName for d in Databases.objects.filter(website=_website(domain)) if DB_NAME_RE.match(d.dbName))


def _configs(site):
    files = {}
    for rel in st.find_config_files(site.docroot):
        try:
            text = siteinfo.read_owned(site, os.path.join(site.docroot, rel), max_bytes=512 * 1024)
        except (OSError, siteinfo.SiteError):
            continue
        if text is not None:
            files[rel] = text
    return files


def overview(domain, domains=None):
    site = resolve(domain)
    state = load_state()
    info = state['sites'].get(domain, {})
    records = panel_databases(domain)
    used = st.config_db_names(_configs(site))
    auth = []
    for entry in info.get('auth', []):
        try:
            users = [u for u, _ in st.parse_htpasswd(siteinfo.read_owned(site, entry['userfile']) or '')]
        except (OSError, siteinfo.SiteError):
            users = []
        auth.append({'path': entry['path'], 'name': entry.get('name', ''), 'users': users})
    pages = []
    for code in st.ERROR_CODES:
        pages.append({'code': code, 'active': code in info.get('errorpages', []),
                      'file': os.path.isfile(os.path.join(site.docroot, st.ERROR_DIR, code + '.html'))})
    copies = sorted(d for d, p in state['staging'].items() if p.get('live') == domain
                    and (domains is None or d in domains))
    pair = state['staging'].get(domain)
    return {
        'domain': domain, 'docroot': site.docroot, 'wordpress': is_wordpress(site), 'wordpress_url': WP_ADDON_URL,
        'redirects': info.get('redirects', []),
        'hotlink': info.get('hotlink') or {'enabled': False, 'domains': [], 'extensions': st.DEFAULT_EXTENSIONS,
                                           'allow_empty': True, 'redirect': ''},
        'errorpages': pages, 'auth': auth,
        'databases': [{'name': n, 'used': n in used} for n in records],
        'staging': {'live': pair.get('live') if pair else None, 'copies': copies,
                    'dbs': pair.get('dbs', {}) if pair else {}},
        'backups': list_backups(domain),
    }


# ----------------------------------------------------------------------------- redirects / hotlink

def save_redirects(domain, rules, min_interval=0):
    site = resolve(domain)
    rules = st.validate_redirects(rules)
    with locked_state() as state:
        _throttle(state, domain, min_interval)
        result = write_htaccess_block(site, st.REDIRECTS, st.redirect_lines(rules))
        _site_state(state, domain)['redirects'] = rules
        if result['changed']:
            _mark_changed(state, domain)
    return dict(result, redirects=rules)


def save_hotlink(domain, config, min_interval=0):
    site = resolve(domain)
    config = st.validate_hotlink(config, domain)
    with locked_state() as state:
        _throttle(state, domain, min_interval)
        result = write_htaccess_block(site, st.HOTLINK, st.hotlink_lines(config, domain))
        _site_state(state, domain)['hotlink'] = config
        if result['changed']:
            _mark_changed(state, domain)
    return dict(result, hotlink=config)


# ----------------------------------------------------------------------------- error pages

def _page_path(site, code):
    return os.path.join(site.docroot, st.ERROR_DIR, st.validate_code(code) + '.html')


def get_errorpage(domain, code):
    site = resolve(domain)
    text = siteinfo.read_owned(site, _page_path(site, code), max_bytes=st.MAX_PAGE_BYTES)
    return {'code': code, 'html': text if text is not None else st.default_page(code), 'exists': text is not None}


def save_errorpage(domain, code, html, min_interval=0, runner=subprocess.run):
    site = resolve(domain)
    code, html = st.validate_code(code), st.validate_page(html)
    with locked_state() as state:
        info = _site_state(state, domain)
        codes = sorted(set(info.get('errorpages', [])) | {code})
        vhost = read_vhost(site)
        if st.errorpage_conflicts(vhost, [code]):
            raise SiteToolsError('vhost.conf already sets an errorpage %s (by hand, or from an ErrorDocument line '
                                 'translated by the .htaccess add-on); remove it there first.' % code)
        if code not in info.get('errorpages', []):
            _throttle(state, domain, min_interval)
        directory = os.path.join(site.docroot, st.ERROR_DIR)
        siteinfo.run_as(site, ['mkdir', '-p', '--', directory], runner=runner, timeout=30)
        st.safe_dir(site.docroot, st.ERROR_DIR)
        siteinfo.write_as(site, _page_path(site, code), html, runner=runner)
        result = write_vhost_block(site, st.ERRORS, st.errorpage_body(codes))
        info['errorpages'] = codes
        if result['changed']:
            _mark_changed(state, domain)
    return dict(result, codes=codes)


def remove_errorpage(domain, code, delete_file=False, min_interval=0, runner=subprocess.run):
    site = resolve(domain)
    code = st.validate_code(code)
    with locked_state() as state:
        _throttle(state, domain, min_interval)
        info = _site_state(state, domain)
        codes = sorted(set(info.get('errorpages', [])) - {code})
        result = write_vhost_block(site, st.ERRORS, st.errorpage_body(codes))
        info['errorpages'] = codes
        if result['changed']:
            _mark_changed(state, domain)
    if delete_file:
        siteinfo.run_as(site, ['rm', '-f', '--', _page_path(site, code)], runner=runner, timeout=30)
    return dict(result, codes=codes)


# ----------------------------------------------------------------------------- protected directories

def server_group():
    """The group OpenLiteSpeed runs as (nogroup on Debian/Ubuntu, nobody elsewhere), as the panel uses."""
    for name in (('nogroup', 'nobody') if os.path.exists('/etc/lsb-release') else ('nobody', 'nogroup')):
        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            continue
    raise SiteToolsError('Neither the nobody nor the nogroup group exists.')


def write_htpasswd(site, path, entries, runner=subprocess.run):
    """Write the user file as the site user, then let only the web server's group read it (0640)."""
    siteinfo.write_as(site, path, st.render_htpasswd(entries), runner=runner)
    fd = siteinfo.open_owned(site, path)
    try:
        if os.geteuid() == 0:
            os.fchown(fd, -1, server_group())
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)


def _auth_entry(info, rel):
    for entry in info.get('auth', []):
        if entry['path'] == rel:
            return entry
    return None


def protect(domain, path, name, username, password, scheme='bcrypt', min_interval=0, runner=subprocess.run):
    site = resolve(domain)
    rel = st.norm_rel(path)
    st.safe_dir(site.docroot, rel)
    name, username = st.validate_auth_name(name), st.validate_ht_user(username)
    hashed = st.hash_password(password, scheme)
    with locked_state() as state:
        _throttle(state, domain, min_interval)
        info = _site_state(state, domain)
        if _auth_entry(info, rel):
            raise SiteToolsError('/%s is already protected; add users to it instead.' % rel)
        if st.auth_conflicts(read_vhost(site), rel):
            raise SiteToolsError('vhost.conf already has a context for /%s (by hand, or from the .htaccess add-on); '
                                 'it cannot be protected here as well.' % rel)
        realm = st.realm_name(domain, rel)
        entry = {'path': rel, 'realm': realm, 'userfile': st.htpasswd_path(site.home, realm), 'name': name}
        write_htpasswd(site, entry['userfile'], [(username, hashed)], runner)
        entries = info.get('auth', []) + [entry]
        try:
            result = write_vhost_block(site, st.AUTH, st.auth_body(entries, site.docroot))
        except Exception:
            siteinfo.run_as(site, ['rm', '-f', '--', entry['userfile']], runner=runner, timeout=30)
            raise
        info['auth'] = entries
        _mark_changed(state, domain)
    return dict(result, path=rel)


def unprotect(domain, path, min_interval=0, runner=subprocess.run):
    site = resolve(domain)
    rel = st.norm_rel(path)
    with locked_state() as state:
        _throttle(state, domain, min_interval)
        info = _site_state(state, domain)
        entry = _auth_entry(info, rel)
        if not entry:
            raise SiteToolsError('/%s is not protected.' % rel)
        entries = [e for e in info['auth'] if e['path'] != rel]
        result = write_vhost_block(site, st.AUTH, st.auth_body(entries, site.docroot))
        info['auth'] = entries
        _mark_changed(state, domain)
    siteinfo.run_as(site, ['rm', '-f', '--', entry['userfile']], runner=runner, timeout=30)
    return dict(result, path=rel)


def set_user(domain, path, username, password, scheme='bcrypt', runner=subprocess.run):
    """Add a user or change a password. OpenLiteSpeed re-reads the user file itself: no restart."""
    site = resolve(domain)
    rel = st.norm_rel(path)
    username = st.validate_ht_user(username)
    hashed = st.hash_password(password, scheme)
    with locked_state() as state:
        entry = _auth_entry(_site_state(state, domain), rel)
        if not entry:
            raise SiteToolsError('/%s is not protected.' % rel)
        entries = st.parse_htpasswd(siteinfo.read_owned(site, entry['userfile']) or '')
        if len(entries) >= 200 and username not in [u for u, _ in entries]:
            raise SiteToolsError('A directory can have up to 200 users.')
        entries = st.set_ht_user(entries, username, hashed)
        write_htpasswd(site, entry['userfile'], entries, runner)
    return {'users': [u for u, _ in entries]}


def remove_user(domain, path, username, runner=subprocess.run):
    site = resolve(domain)
    rel = st.norm_rel(path)
    username = st.validate_ht_user(username)
    with locked_state() as state:
        entry = _auth_entry(_site_state(state, domain), rel)
        if not entry:
            raise SiteToolsError('/%s is not protected.' % rel)
        entries = st.parse_htpasswd(siteinfo.read_owned(site, entry['userfile']) or '')
        left = st.remove_ht_user(entries, username)
        if not left:
            raise SiteToolsError('That is the last user; remove the protection instead.')
        write_htpasswd(site, entry['userfile'], left, runner)
    return {'users': [u for u, _ in left]}


# ----------------------------------------------------------------------------- MySQL helpers

@contextlib.contextmanager
def mysql_defaults():
    from universalAddons.backupv2.service import mysql_defaults_file
    path = mysql_defaults_file()
    try:
        yield path
    finally:
        os.unlink(path)


def mysql(sql, runner=subprocess.run):
    with mysql_defaults() as defaults:
        out = runner(['mysql', '--defaults-extra-file=' + defaults], input=sql, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, universal_newlines=True, timeout=300)
    if out.returncode != 0:
        raise SiteToolsError('MySQL: ' + (out.stdout or '').strip()[-300:])
    return out.stdout


def dump_command(defaults, db):
    return ['mysqldump', '--defaults-extra-file=' + defaults, '--single-transaction', '--quick', '--skip-lock-tables',
            '--routines', '--triggers', '--no-tablespaces', '--default-character-set=utf8mb4', db]


def copy_database(src_db, dst_db, pairs, popen=subprocess.Popen):
    """mysqldump src | serialized-aware URL replace | mysql dst, streamed line by line (as root)."""
    for name in (src_db, dst_db):
        if not DB_NAME_RE.match(name or ''):
            raise SiteToolsError('Invalid database name.')
    with mysql_defaults() as defaults, tempfile.TemporaryFile() as dump_err, tempfile.TemporaryFile() as load_out:
        dump = popen(dump_command(defaults, src_db), stdout=subprocess.PIPE, stderr=dump_err, stdin=subprocess.DEVNULL)
        load = popen(['mysql', '--defaults-extra-file=' + defaults, '--default-character-set=utf8mb4', dst_db],
                     stdin=subprocess.PIPE, stdout=load_out, stderr=subprocess.STDOUT)
        lines = 0
        try:
            for line in dump.stdout:
                load.stdin.write(st.transform_dump_line(line, pairs))
                lines += 1
        except BrokenPipeError:
            pass
        finally:
            try:
                load.stdin.close()
            except BrokenPipeError:
                pass
            dump.stdout.close()
        load_code, dump_code = load.wait(), dump.wait()
        if dump_code != 0:
            dump_err.seek(0)
            raise SiteToolsError('Exporting %s failed: %s' % (src_db, dump_err.read().decode('utf-8', 'replace')[-400:]))
        if load_code != 0:
            load_out.seek(0)
            raise SiteToolsError('Importing into %s failed: %s' % (dst_db, load_out.read().decode('utf-8', 'replace')[-400:]))
    return lines


# ----------------------------------------------------------------------------- file copies (as the site users)

def _popen_as(site, argv, popen=subprocess.Popen, **kwargs):
    return popen(['timeout', '-k', '10', '7200'] + argv, cwd='/', env=siteinfo.user_env(site), user=site.uid,
                 group=site.gid, extra_groups=[], umask=0o022, **kwargs)


def copy_tree(src, dst, patterns, delete, runner=subprocess.run, popen=subprocess.Popen):
    """Mirror src's document root into dst's. Same Linux user: rsync as that user. Different users:
    tar as the source user piped into tar as the target user (root never touches the files)."""
    if st.nested(src.docroot, dst.docroot):
        raise SiteToolsError('The two document roots are inside each other.')
    if src.user == dst.user:
        argv = ['rsync', '-a', '--no-devices', '--no-specials'] + (['--delete'] if delete else [])
        for item in patterns:
            argv += ['--exclude', item]
        code, out = siteinfo.run_as(dst, argv + [src.docroot + '/', dst.docroot + '/'], runner=runner, timeout=7200)
        if code not in (0, 24):  # 24: files vanished while copying
            raise SiteToolsError('Copying files failed: ' + out.strip()[-500:])
        return 'rsync'
    reader = _popen_as(src, ['tar', '-C', src.docroot, '-cf', '-'] + st.tar_excludes(patterns) + ['.'], popen,
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    writer = _popen_as(dst, ['tar', '-C', dst.docroot, '-xf', '-', '--no-same-owner', '--no-same-permissions'],
                       popen, stdin=reader.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    reader.stdout.close()
    out = writer.communicate()[0] or b''
    if reader.wait() not in (0, 1) or writer.returncode != 0:
        raise SiteToolsError('Copying files failed: ' + out.decode('utf-8', 'replace').strip()[-500:])
    return 'tar'


# ----------------------------------------------------------------------------- backups of a live site

def _backup_dir(domain, backup_id=None):
    base = os.path.join(BACKUP_ROOT, 'backups', domain)
    if backup_id is None:
        return base
    if not BACKUP_ID_RE.match(backup_id or ''):
        raise SiteToolsError('Invalid backup.')
    return os.path.join(base, backup_id)


def list_backups(domain):
    base = _backup_dir(domain)
    items = []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base), reverse=True):
            try:
                with open(os.path.join(base, name, 'meta.json')) as handle:
                    meta = json.load(handle)
            except (OSError, ValueError):
                continue
            if BACKUP_ID_RE.match(name):
                items.append(dict(meta, id=name))
    return items


def make_backup(site, files=True, dbs=(), label='', log=None, popen=subprocess.Popen):
    """Root-only backup of the live site (files as a tar made by the site user, databases dumped)."""
    say = log or (lambda text: None)
    backup_id = time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(2)
    directory = _backup_dir(site.domain, backup_id)
    os.makedirs(directory, mode=0o700)
    os.chmod(os.path.dirname(directory), 0o700)
    if files:
        with open(os.path.join(directory, 'files.tar.gz'), 'wb') as out:
            proc = _popen_as(site, ['tar', '-C', site.docroot, '-czf', '-', '.'], popen, stdout=out,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            if proc.wait() not in (0, 1):
                raise SiteToolsError('Backing up the files of %s failed.' % site.domain)
        say('files of %s backed up' % site.domain)
    for db in dbs:
        if not DB_NAME_RE.match(db):
            raise SiteToolsError('Invalid database name.')
        with mysql_defaults() as defaults, gzip.open(os.path.join(directory, 'db-%s.sql.gz' % db), 'wb') as out:
            dump = popen(dump_command(defaults, db), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL)
            shutil.copyfileobj(dump.stdout, out)
            dump.stdout.close()
            if dump.wait() != 0:
                raise SiteToolsError('Backing up database %s failed.' % db)
        say('database %s backed up' % db)
    with open(os.path.join(directory, 'meta.json'), 'w') as handle:
        json.dump({'created': int(time.time()), 'label': label, 'files': bool(files), 'dbs': list(dbs),
                   'docroot': site.docroot}, handle)
    for old in list_backups(site.domain)[KEEP_BACKUPS:]:
        shutil.rmtree(_backup_dir(site.domain, old['id']), ignore_errors=True)
    return backup_id


def restore_backup(site, backup_id, log=None, popen=subprocess.Popen):
    say = log or (lambda text: None)
    directory = _backup_dir(site.domain, backup_id)
    with open(os.path.join(directory, 'meta.json')) as handle:
        meta = json.load(handle)
    if meta.get('docroot') != site.docroot:
        raise SiteToolsError('That backup belongs to another document root.')
    if meta.get('files'):
        with open(os.path.join(directory, 'files.tar.gz'), 'rb') as source:
            proc = _popen_as(site, ['tar', '-C', site.docroot, '-xzf', '-', '--no-same-owner'], popen, stdin=source,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = proc.communicate()[0] or b''
            if proc.returncode != 0:
                raise SiteToolsError('Restoring files failed: ' + out.decode('utf-8', 'replace')[-400:])
        say('files restored')
    allowed = set(panel_databases(site.domain))
    for db in meta.get('dbs', []):
        if db not in allowed:
            raise SiteToolsError('%s is no longer a database of this site.' % db)
        with mysql_defaults() as defaults, gzip.open(os.path.join(directory, 'db-%s.sql.gz' % db), 'rb') as source, \
                tempfile.TemporaryFile() as output:
            load = popen(['mysql', '--defaults-extra-file=' + defaults, db], stdin=subprocess.PIPE, stdout=output,
                         stderr=subprocess.STDOUT)
            try:
                shutil.copyfileobj(source, load.stdin)
            except BrokenPipeError:
                pass
            load.stdin.close()
            if load.wait() != 0:
                output.seek(0)
                raise SiteToolsError('Restoring %s failed: %s' % (db, output.read().decode('utf-8', 'replace')[-300:]))
        say('database %s restored' % db)
    return {'restored': backup_id}


# ----------------------------------------------------------------------------- staging: clone

def _create_child(source_domain, child_domain, owner_is_admin):
    """Create child_domain under the source's website with the panel's own child-domain code."""
    _django()
    from websiteFunctions.models import ChildDomains, Websites
    from plogical.virtualHostUtilities import virtualHostUtilities
    try:
        website = Websites.objects.get(domain=source_domain)
        php = website.phpSelection
    except Websites.DoesNotExist:
        child = ChildDomains.objects.select_related('master').get(domain=source_domain)
        website, php = child.master, child.phpSelection
    path = '/home/%s/%s' % (website.domain, child_domain)
    status_path = '/home/cyberpanel/' + secrets.token_hex(6)
    result = virtualHostUtilities.createDomain(website.domain, child_domain, php, path, 1, 0,
                                               0 if owner_is_admin else 1, website.admin.userName, 0, status_path)
    if not result or result[0] == 0:
        raise SiteToolsError('Could not create %s: %s' % (child_domain, result[1] if result else 'unknown error'))
    return path


def plan_clone(source, mode='subdomain', label='staging', target=None, databases=None, domains=None):
    """Validate a clone request and work out the target; raises before anything is changed."""
    src = resolve(source)
    if is_wordpress(src):
        raise SiteToolsError('%s runs WordPress: use the WordPress add-on (%s), which clones, stages and pushes '
                             'WordPress safely.' % (source, WP_ADDON_URL))
    if mode == 'subdomain':
        target_domain = st.staging_domain(source, label)
    elif mode == 'site':
        target_domain = str(target or '').strip().lower()
        if not siteinfo.DOMAIN_RE.match(target_domain):
            raise SiteToolsError('Choose the target site.')
        if domains is not None and target_domain not in domains:
            raise PermissionError('You do not manage %s.' % target_domain)
    else:
        raise SiteToolsError('Copy into a staging subdomain or into another site.')
    if target_domain == source:
        raise SiteToolsError('Choose a different target.')
    records = panel_databases(source)
    selected = []
    for name in databases or []:
        if name not in records:
            raise SiteToolsError('%s is not a database of %s in the panel.' % (name, source))
        if name not in selected:
            selected.append(name)
    pair = load_state()['staging'].get(target_domain)
    refresh = bool(pair and pair.get('live') == source)
    exists = True
    try:
        tgt = resolve(target_domain)
    except siteinfo.SiteError:
        if mode == 'site':
            raise SiteToolsError('%s is not a site on this server.' % target_domain)
        exists, tgt = False, None
    if tgt is not None:
        if st.nested(src.docroot, tgt.docroot):
            raise SiteToolsError('The two document roots are inside each other.')
        if not refresh and os.path.isdir(tgt.docroot) and not st.looks_empty(os.listdir(tgt.docroot)):
            raise SiteToolsError('%s is not empty. Copy into an empty site, or into its existing staging copy.'
                                 % target_domain)
    return {'source': source, 'target': target_domain, 'create': not exists, 'refresh': refresh,
            'databases': selected}


def start_clone(source, mode='subdomain', label='staging', target=None, databases=None, exclude_cache=True,
                excludes=None, domains=None, quota=False):
    plan = plan_clone(source, mode, label, target, databases, domains)
    st.excludes(exclude_cache, False, excludes)   # validate now
    return jobs.spawn('sitetools', 'clone_run', dict(plan, exclude_cache=bool(exclude_cache),
                                                     excludes=list(excludes or []), quota=bool(quota)))


def _staging_database(target_domain, existing, quota):
    """A database for the copy: the pair's existing one (new password) or a new one in the panel."""
    if existing:
        password = secrets.token_urlsafe(24)
        mysql("DROP DATABASE IF EXISTS `{0}`;\nCREATE DATABASE `{0}` CHARACTER SET utf8mb4 COLLATE "
              "utf8mb4_unicode_ci;\nALTER USER '{0}'@'localhost' IDENTIFIED BY '{1}';\n".format(existing, password))
        return existing, existing, password
    from universalAddons.wordpress.actions import _create_database_for
    return _create_database_for(target_domain, quota)


def clone_run(job_id, source, target, create, refresh, databases, exclude_cache=True, excludes=None, quota=False):
    data = {}

    def make_target(job):
        if create:
            job.log('creating child domain %s with the panel\'s child-domain code' % target)
            _create_child(source, target, owner_is_admin=not quota)
        data['src'], data['tgt'] = resolve(source), resolve(target)
        return {'target': target, 'docroot': data['tgt'].docroot}

    def files(job):
        how = copy_tree(data['src'], data['tgt'], st.excludes(exclude_cache, False, excludes), delete=True)
        job.log('files copied with %s' % how)

    def dbs(job):
        pair = load_state()['staging'].get(target) if refresh else None
        mapping, db_map = {}, {}
        pairs = st.url_pairs(source, target)
        for name in databases:
            existing = (pair or {}).get('dbs', {}).get(name)
            new_name, user, password = _staging_database(target, existing, quota)
            lines = copy_database(name, new_name, pairs)
            job.log('database %s copied to %s (%d dump lines, URLs moved to %s)' % (name, new_name, lines, target))
            mapping[name] = new_name
            db_map[name] = {'name': new_name, 'user': user, 'password': password}
        data['mapping'], data['db_map'] = mapping, db_map

    def configs(job):
        changed = {}
        tgt = data['tgt']
        for rel, text in _configs(tgt).items():
            new, keys = st.rewrite_config(rel, text, data['db_map'], source, target)
            if new != text:
                siteinfo.write_as(tgt, os.path.join(tgt.docroot, rel), new, mode_like=os.path.join(tgt.docroot, rel))
                changed[rel] = keys
                job.log('%s: %s updated' % (rel, ', '.join(keys)))
        with locked_state() as state:
            old = state['staging'].get(target, {})
            state['staging'][target] = {'live': source, 'dbs': dict(old.get('dbs', {}), **data['mapping']),
                                        'created': old.get('created', int(time.time())), 'refreshed': int(time.time())}
        return {'configs': changed, 'databases': data['mapping'], 'url': 'https://%s/' % target}

    return jobs.run_job(job_id, [('Prepare %s' % target, make_target), ('Copy files from %s' % source, files),
                                 ('Copy databases', dbs), ('Rewrite configuration', configs)])


# ----------------------------------------------------------------------------- staging: push back

def _pair(staging, domains=None):
    pair = load_state()['staging'].get(staging)
    if not pair:
        raise SiteToolsError('%s is not a staging copy made by Site Tools.' % staging)
    if domains is not None and pair['live'] not in domains:
        raise PermissionError('You do not manage %s.' % pair['live'])
    return pair


def start_push(staging, push_files=True, push_db=True, backup_files=True, backup_db=True, exclude_cache=True,
               exclude_uploads=False, excludes=None, domains=None):
    pair = _pair(staging, domains)
    if not push_files and not push_db:
        raise SiteToolsError('Push files, databases or both.')
    st.excludes(exclude_cache, exclude_uploads, excludes, push=True)
    resolve(staging), resolve(pair['live'])
    return jobs.spawn('sitetools', 'push_run', {
        'staging': staging, 'push_files': bool(push_files), 'push_db': bool(push_db),
        'backup_files': bool(backup_files), 'backup_db': bool(backup_db), 'exclude_cache': bool(exclude_cache),
        'exclude_uploads': bool(exclude_uploads), 'excludes': list(excludes or [])})


def push_run(job_id, staging, push_files, push_db, backup_files, backup_db, exclude_cache=True, exclude_uploads=False,
             excludes=None):
    pair = _pair(staging)
    live = pair['live']
    stg, prod = resolve(staging), resolve(live)
    allowed = set(panel_databases(live))
    dbs = {l: s for l, s in pair.get('dbs', {}).items() if l in allowed}
    data = {'backup': None}

    def backup(job):
        if not backup_files and not backup_db:
            job.log('no backup requested')
            return None
        data['backup'] = make_backup(prod, files=backup_files, dbs=list(dbs) if backup_db else [],
                                     label='before push from %s' % staging, log=job.log)
        return {'backup': data['backup']}

    def publish(job):
        try:
            if push_files:
                how = copy_tree(stg, prod, st.excludes(exclude_cache, exclude_uploads, excludes, push=True), delete=True)
                job.log('files pushed with %s (.env, wp-config.php and excluded paths kept)' % how)
            if push_db:
                for live_db, stage_db in sorted(dbs.items()):
                    copy_database(stage_db, live_db, st.url_pairs(staging, live))
                    job.log('database %s -> %s' % (stage_db, live_db))
        except Exception as exc:
            if data['backup']:
                job.log('push failed (%s); restoring backup %s' % (exc, data['backup']))
                restore_backup(prod, data['backup'], log=job.log)
            raise
        return {'status': status(live), 'backup': data['backup']}

    return jobs.run_job(job_id, [('Back up %s' % live, backup), ('Push %s to %s' % (staging, live), publish)])


def start_restore(domain, backup_id):
    resolve(domain)
    _backup_dir(domain, backup_id)
    if backup_id not in [b['id'] for b in list_backups(domain)]:
        raise SiteToolsError('Unknown backup.')
    return jobs.spawn('sitetools', 'restore_run', {'domain': domain, 'backup_id': backup_id})


def restore_run(job_id, domain, backup_id):
    site = resolve(domain)
    return jobs.run_job(job_id, [('Restore %s on %s' % (backup_id, domain),
                                  lambda job: restore_backup(site, backup_id, log=job.log))])


ACTIONS = {
    'list': list_sites,
    'overview': overview,
    'redirects': save_redirects,
    'hotlink': save_hotlink,
    'errorpage_get': get_errorpage,
    'errorpage_save': save_errorpage,
    'errorpage_remove': remove_errorpage,
    'protect': protect,
    'unprotect': unprotect,
    'user_set': set_user,
    'user_remove': remove_user,
    'clone': start_clone,
    'clone_run': clone_run,
    'push': start_push,
    'push_run': push_run,
    'restore': start_restore,
    'restore_run': restore_run,
    'job': lambda job_id: jobs.status(job_id),
}
