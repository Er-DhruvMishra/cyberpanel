"""Rspamd Manager: detection, Postfix milter wiring and managed configuration.

Design rules (each fixes a defect found in the official module):
- Postfix is changed only through `postconf -e` / `postconf -X` with argv lists, never by
  editing main.cf text, and main.cf/master.cf are backed up first.
- `milter_default_action = accept`: if Rspamd is down, mail is delivered unfiltered instead of
  being tempfailed.
- Enabling/disabling filtering adds/removes the milter; it does not merely stop the service.
- Every managed file is validated with `rspamadm configtest`; on failure the previous files
  are restored and nothing is reloaded.
- Settings are validated (numbers, addresses) before they are written.
"""
import json
import os
import re
import shutil
import subprocess
import time

RSPAMD_MILTER = 'inet:127.0.0.1:11332'
LOCAL_D = '/etc/rspamd/local.d'
MAPS_DIR = '/etc/rspamd/local.d/maps'
DKIM_DIR = '/var/lib/rspamd/dkim'
OPENDKIM_KEYS = '/etc/opendkim/keys'
BACKUP_DIR = '/var/lib/cyberpanel-universal/rspamd-backups'
MANAGED_HEADER = '# Managed by CyberPanel Universal Add-ons (Rspamd Manager). Edit in the panel.\n'

EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+=-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')
DOMAIN_RE = re.compile(r'^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')

DEFAULT_SETTINGS = {
    'reject': 15.0,
    'add_header': 6.0,
    'greylist': 4.0,
    'greylisting': True,
    'bayes_autolearn': True,
    'dkim_signing': False,
    'arc_signing': False,
    'allow_list': [],
    'deny_list': [],
}


class RspamdError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=120, input=None):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, input=input)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- Postfix milters

def split_milters(value):
    return [item for item in re.split(r'[\s,]+', (value or '').strip()) if item]


def is_rspamd_milter(item):
    return bool(re.match(r'^inet:(127\.0\.0\.1|localhost|\[::1\]):11332$', item))


def plan_milters(current, enable):
    """Return the new smtpd_milters list. Rspamd goes last so OpenDKIM signs before it scans."""
    items = [m for m in split_milters(current) if not is_rspamd_milter(m)]
    if enable:
        items.append(RSPAMD_MILTER)
    return items


def postfix_plan(postconf_values, enable):
    """Compute the `postconf -e` assignments needed to enable or disable the Rspamd milter."""
    smtpd = plan_milters(postconf_values.get('smtpd_milters', ''), enable)
    changes = {'smtpd_milters': ' '.join(smtpd)}
    non_smtpd = postconf_values.get('non_smtpd_milters', '')
    if non_smtpd.strip() in ('$smtpd_milters', '${smtpd_milters}'):
        pass  # already follows smtpd_milters
    else:
        changes['non_smtpd_milters'] = ' '.join(plan_milters(non_smtpd, enable))
    if enable:
        changes['milter_default_action'] = 'accept'
        changes['milter_protocol'] = '6'
        changes['milter_mail_macros'] = 'i {mail_addr} {client_addr} {client_name} {auth_authen}'
    return {key: value for key, value in changes.items() if postconf_values.get(key, '') != value}


def read_postconf(names, runner=subprocess.run):
    code, out = run(['postconf'] + list(names), runner)
    values = {}
    if code != 0:
        return values
    for line in out.splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            values[key.strip()] = value.strip()
        elif line.rstrip().endswith(' ='):
            values[line.rstrip()[:-2].strip()] = ''
    return values


# ----------------------------------------------------------------------------- detection

def detect(runner=subprocess.run, exists=os.path.exists, which=shutil.which):
    postconf = read_postconf(['smtpd_milters', 'non_smtpd_milters', 'milter_default_action',
                              'content_filter', 'header_checks'], runner)
    code, master = run(['postconf', '-M'], runner)
    code_sa, _ = run(['systemctl', 'is-active', 'spamassassin'], runner)
    code_ms, _ = run(['systemctl', 'is-active', 'mailscanner'], runner)
    code_rs, _ = run(['systemctl', 'is-active', 'rspamd'], runner)
    code_redis, _ = run(['systemctl', 'is-active', 'redis'], runner)
    if code_redis != 0:
        code_redis, _ = run(['systemctl', 'is-active', 'redis-server'], runner)
    version = ''
    if which('rspamd'):
        _, version_out = run(['rspamd', '--version'], runner)
        match = re.search(r'(\d+\.\d+(\.\d+)?)', version_out)
        version = match.group(1) if match else ''
    milters = split_milters(postconf.get('smtpd_milters', ''))
    conflicts = []
    if 'spamassassin' in master or 'spamc' in master or code_sa == 0:
        conflicts.append({'id': 'spamassassin', 'detail': 'SpamAssassin is wired into Postfix (master.cf '
                          'content_filter / spamc pipe). Running both scans every message twice.',
                          'resolution': 'Choose "replace SpamAssassin" to remove its Postfix filter.'})
    if code_ms == 0 or exists('/usr/local/CyberCP/public/mailwatch') or exists('/etc/MailScanner'):
        conflicts.append({'id': 'mailscanner', 'detail': 'MailScanner is installed. It holds and rescans '
                          'every message itself.', 'resolution': 'Uninstall MailScanner (Email > MailScanner) '
                          'before enabling Rspamd.'})
    if 'amavis' in master or 'amavis' in postconf.get('content_filter', ''):
        conflicts.append({'id': 'amavis', 'detail': 'Amavis is configured as a content filter.',
                          'resolution': 'Remove amavis from Postfix first.'})
    return {
        'installed': bool(which('rspamd')) and exists('/etc/rspamd/rspamd.conf'),
        'version': version,
        'running': code_rs == 0,
        'redis_running': code_redis == 0,
        'milter_enabled': any(is_rspamd_milter(m) for m in milters),
        'milters': milters,
        'milter_default_action': postconf.get('milter_default_action', 'tempfail'),
        'opendkim_milter': any(m.endswith(':8891') for m in milters),
        'conflicts': conflicts,
        'managed_settings': read_settings(),
    }


# ----------------------------------------------------------------------------- settings

def validate_settings(settings):
    clean = dict(DEFAULT_SETTINGS)
    for key in ('reject', 'add_header', 'greylist'):
        try:
            value = float(settings.get(key, clean[key]))
        except (TypeError, ValueError):
            raise RspamdError('%s must be a number.' % key)
        if not -100 <= value <= 1000:
            raise RspamdError('%s is out of range.' % key)
        clean[key] = round(value, 2)
    if not clean['greylist'] < clean['add_header'] < clean['reject']:
        raise RspamdError('Thresholds must satisfy greylist < add header < reject.')
    for key in ('greylisting', 'bayes_autolearn', 'dkim_signing', 'arc_signing'):
        value = settings.get(key, clean[key])
        if not isinstance(value, bool):
            raise RspamdError('%s must be true or false.' % key)
        clean[key] = value
    for key in ('allow_list', 'deny_list'):
        entries = settings.get(key, [])
        if isinstance(entries, str):
            entries = entries.split()
        if not isinstance(entries, list) or len(entries) > 5000:
            raise RspamdError('%s must be a list of up to 5000 entries.' % key)
        cleaned = []
        for entry in entries:
            entry = str(entry).strip().lower()
            if not entry:
                continue
            if not (EMAIL_RE.match(entry) or DOMAIN_RE.match(entry)):
                raise RspamdError('%r in %s is not an email address or domain.' % (entry, key))
            cleaned.append(entry)
        clean[key] = sorted(set(cleaned))
    overlap = set(clean['allow_list']) & set(clean['deny_list'])
    if overlap:
        raise RspamdError('Entries in both lists: %s' % ', '.join(sorted(overlap)))
    return clean


def _bool(value):
    return 'true' if value else 'false'


def render_files(settings):
    """Map of absolute path -> content for every file this module manages."""
    s = validate_settings(settings)
    emails = lambda items: [i for i in items if '@' in i]
    domains = lambda items: [i for i in items if '@' not in i]
    files = {
        os.path.join(LOCAL_D, 'actions.conf'): MANAGED_HEADER +
        'reject = %s;\nadd_header = %s;\ngreylist = %s;\n' % (s['reject'], s['add_header'], s['greylist']),
        os.path.join(LOCAL_D, 'greylist.conf'): MANAGED_HEADER + 'enabled = %s;\n' % _bool(s['greylisting']),
        os.path.join(LOCAL_D, 'classifier-bayes.conf'): MANAGED_HEADER +
        'backend = "redis";\nautolearn = %s;\n' % _bool(s['bayes_autolearn']),
        os.path.join(LOCAL_D, 'redis.conf'): MANAGED_HEADER + 'servers = "127.0.0.1";\n',
        os.path.join(LOCAL_D, 'milter_headers.conf'): MANAGED_HEADER +
        'use = ["x-spamd-bar", "x-spam-level", "authentication-results"];\nauthenticated_headers = ["authentication-results"];\n',
        os.path.join(LOCAL_D, 'worker-proxy.inc'): MANAGED_HEADER +
        'milter = yes;\ntimeout = 120s;\nupstream "local" {\n  default = yes;\n  self_scan = yes;\n}\n'
        'bind_socket = "127.0.0.1:11332";\n',
        os.path.join(LOCAL_D, 'worker-controller.inc'): MANAGED_HEADER +
        'bind_socket = "127.0.0.1:11334";\nsecure_ip = "127.0.0.1";\n',
        os.path.join(MAPS_DIR, 'ua_allow_from.map'): '\n'.join(emails(s['allow_list'])) + '\n',
        os.path.join(MAPS_DIR, 'ua_allow_from_domain.map'): '\n'.join(domains(s['allow_list'])) + '\n',
        os.path.join(MAPS_DIR, 'ua_deny_from.map'): '\n'.join(emails(s['deny_list'])) + '\n',
        os.path.join(MAPS_DIR, 'ua_deny_from_domain.map'): '\n'.join(domains(s['deny_list'])) + '\n',
        os.path.join(LOCAL_D, 'multimap.conf'): MANAGED_HEADER + ''.join(
            '%s {\n  type = "from";\n  filter = "%s";\n  map = "%s";\n  score = %s;\n  description = "%s";\n}\n' % (
                name, flt, os.path.join(MAPS_DIR, mapfile), score, desc)
            for name, flt, mapfile, score, desc in (
                ('UA_ALLOW_FROM', 'email:addr', 'ua_allow_from.map', -20.0, 'Sender on the allow list'),
                ('UA_ALLOW_FROM_DOMAIN', 'email:domain', 'ua_allow_from_domain.map', -20.0, 'Sender domain on the allow list'),
                ('UA_DENY_FROM', 'email:addr', 'ua_deny_from.map', 20.0, 'Sender on the deny list'),
                ('UA_DENY_FROM_DOMAIN', 'email:domain', 'ua_deny_from_domain.map', 20.0, 'Sender domain on the deny list'),
            )),
    }
    signing = ('enabled = %s;\nselector = "default";\npath = "%s/$domain.$selector.key";\n'
               'allow_username_mismatch = true;\nuse_domain = "header";\nsign_authenticated = true;\n'
               'sign_local = true;\n')
    files[os.path.join(LOCAL_D, 'dkim_signing.conf')] = MANAGED_HEADER + signing % (_bool(s['dkim_signing']), DKIM_DIR)
    files[os.path.join(LOCAL_D, 'arc.conf')] = MANAGED_HEADER + signing % (_bool(s['arc_signing']), DKIM_DIR)
    files[os.path.join(LOCAL_D, 'ua-settings.json')] = json.dumps(s, indent=2, sort_keys=True) + '\n'
    return files


def read_settings(path=os.path.join(LOCAL_D, 'ua-settings.json')):
    try:
        with open(path) as handle:
            return validate_settings(json.load(handle))
    except (OSError, ValueError):
        return dict(DEFAULT_SETTINGS)


def _backup(paths, backup_root=None):
    backup_root = backup_root or BACKUP_DIR
    stamp = time.strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(2).hex()
    directory = os.path.join(backup_root, stamp)
    os.makedirs(directory, mode=0o700)
    manifest = {}
    for index, path in enumerate(paths):
        if os.path.exists(path):
            target = os.path.join(directory, '%03d' % index)
            shutil.copy2(path, target)
            manifest[path] = target
        else:
            manifest[path] = None
    with open(os.path.join(directory, 'manifest.json'), 'w') as handle:
        json.dump(manifest, handle, indent=2)
    return directory, manifest


def _restore(manifest):
    for path, saved in manifest.items():
        if saved:
            shutil.copy2(saved, path)
        elif os.path.exists(path):
            os.unlink(path)


def apply_settings(settings, runner=subprocess.run, chown=None, backup_root=None):
    """Write managed files, configtest, and reload; roll back on any failure."""
    files = render_files(settings)
    directory, manifest = _backup(list(files), backup_root)
    try:
        os.makedirs(MAPS_DIR, exist_ok=True)
        for path, content in files.items():
            with open(path, 'w') as handle:
                handle.write(content)
            os.chmod(path, 0o644)
        code, out = run(['rspamadm', 'configtest'], runner)
        if code != 0:
            raise RspamdError('rspamadm configtest failed; previous configuration restored:\n' + out[-2000:])
        code, out = run(['systemctl', 'reload-or-restart', 'rspamd'], runner)
        if code != 0:
            raise RspamdError('Rspamd did not reload; previous configuration restored:\n' + out[-2000:])
    except Exception:
        _restore(manifest)
        run(['systemctl', 'reload-or-restart', 'rspamd'], runner)
        raise
    return {'backup': directory, 'settings': validate_settings(settings)}


# ----------------------------------------------------------------------------- milter on/off

def set_filtering(enable, replace_spamassassin=False, dry_run=False, runner=subprocess.run, backup_root=None):
    """Add or remove the Rspamd milter in Postfix. Returns the planned/applied changes."""
    current = read_postconf(['smtpd_milters', 'non_smtpd_milters', 'milter_default_action', 'milter_protocol',
                             'milter_mail_macros'], runner)
    changes = postfix_plan(current, enable)
    remove_master = []
    if enable and replace_spamassassin:
        _, master = run(['postconf', '-P'], runner)
        for line in master.splitlines():
            match = re.match(r'^(\S+/\S+)/content_filter = (.*)$', line.strip())
            if match and 'spamassassin' in match.group(2):
                remove_master.append(match.group(1) + '/content_filter')
    plan = {'postconf': changes, 'remove_master_params': remove_master}
    if dry_run:
        return plan
    if enable:
        state = detect(runner)
        if not state['installed']:
            raise RspamdError('Install Rspamd first.')
        if any(c['id'] in ('mailscanner', 'amavis') for c in state['conflicts']):
            raise RspamdError('Remove MailScanner/Amavis before enabling Rspamd filtering.')
        if any(c['id'] == 'spamassassin' for c in state['conflicts']) and not replace_spamassassin:
            raise RspamdError('SpamAssassin is wired into Postfix. Choose to replace it, or remove it first.')
    _backup(['/etc/postfix/main.cf', '/etc/postfix/master.cf'], backup_root)
    for key, value in changes.items():
        code, out = run(['postconf', '-e', '%s=%s' % (key, value)], runner)
        if code != 0:
            raise RspamdError('postconf failed for %s: %s' % (key, out.strip()))
    for parameter in remove_master:
        code, out = run(['postconf', '-PX', parameter], runner)
        if code != 0:
            raise RspamdError('postconf failed removing %s: %s' % (parameter, out.strip()))
    code, out = run(['postfix', 'check'], runner)
    if code != 0:
        raise RspamdError('postfix check failed after the change: ' + out.strip()[:1000])
    run(['systemctl', 'reload', 'postfix'], runner)
    return plan


# ----------------------------------------------------------------------------- DKIM keys

def migrate_dkim_keys(keys_dir=OPENDKIM_KEYS, target_dir=DKIM_DIR, chown=os.chown):
    """Copy OpenDKIM private keys to the layout Rspamd's dkim_signing expects."""
    import pwd
    try:
        user = pwd.getpwnam('_rspamd')
    except KeyError:
        try:
            user = pwd.getpwnam('rspamd')
        except KeyError:
            user = None
    os.makedirs(target_dir, mode=0o750, exist_ok=True)
    copied = []
    if os.path.isdir(keys_dir):
        for domain in sorted(os.listdir(keys_dir)):
            source = os.path.join(keys_dir, domain, 'default.private')
            if not DOMAIN_RE.match(domain) or not os.path.isfile(source):
                continue
            target = os.path.join(target_dir, '%s.default.key' % domain)
            shutil.copyfile(source, target)
            os.chmod(target, 0o640)
            if user:
                chown(target, 0, user.pw_gid)
            copied.append(domain)
    if user:
        chown(target_dir, 0, user.pw_gid)
    return {'domains': copied}


# ----------------------------------------------------------------------------- stats / learning / logs

def parse_stat(text):
    stats = {'scanned': 0, 'learned': 0, 'actions': {}, 'spam_count': 0, 'ham_count': 0}
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r'^Messages scanned: (\d+)', line)
        if match:
            stats['scanned'] = int(match.group(1))
        match = re.match(r'^Messages with action ([\w ]+?): (\d+)', line)
        if match:
            stats['actions'][match.group(1)] = int(match.group(2))
        match = re.match(r'^Messages learned: (\d+)', line)
        if match:
            stats['learned'] = int(match.group(1))
        match = re.match(r'^Messages treated as (spam|ham): (\d+)', line)
        if match:
            stats[match.group(1) + '_count'] = int(match.group(2))
    return stats


def stats(runner=subprocess.run):
    code, out = run(['rspamc', 'stat'], runner)
    if code != 0:
        raise RspamdError('rspamc stat failed: ' + out.strip()[:500])
    result = parse_stat(out)
    code, counters = run(['rspamc', '-j', 'counters'], runner)
    top = []
    if code == 0:
        try:
            items = json.loads(counters)
            top = sorted(({'symbol': i.get('symbol'), 'hits': i.get('hits', 0)} for i in items),
                         key=lambda i: -i['hits'])[:20]
        except ValueError:
            pass
    result['top_symbols'] = top
    return result


def maildir_folder(domain, user, folder, vmail='/home/vmail'):
    """Resolve a mailbox folder to its Maildir path, refusing anything that escapes vmail."""
    if not DOMAIN_RE.match(domain or '') or not re.match(r'^[A-Za-z0-9._%+=-]{1,64}$', user or ''):
        raise RspamdError('Invalid mailbox.')
    if folder not in ('Junk', 'Spam', 'INBOX', 'Archive'):
        raise RspamdError('Choose Junk, Spam, INBOX or Archive.')
    base = os.path.join(vmail, domain, user, 'Maildir')
    path = base if folder == 'INBOX' else os.path.join(base, '.' + folder)
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(vmail) + '/'):
        raise RspamdError('Invalid mailbox path.')
    return path


def learn(kind, domain, user, folder, runner=subprocess.run, vmail='/home/vmail'):
    if kind not in ('spam', 'ham'):
        raise RspamdError('Learn spam or ham.')
    path = maildir_folder(domain, user, folder, vmail)
    files = []
    for sub in ('cur', 'new'):
        directory = os.path.join(path, sub)
        if os.path.isdir(directory):
            files.extend(os.path.join(directory, name) for name in sorted(os.listdir(directory))[:2000])
    if not files:
        raise RspamdError('No messages in %s.' % path)
    learned, failed = 0, 0
    for start in range(0, len(files), 100):
        code, out = run(['rspamc', 'learn_' + kind] + files[start:start + 100], runner, timeout=600)
        learned += len(re.findall(r'success = true', out))
        failed += len(re.findall(r'success = false|error', out))
    return {'messages': len(files), 'learned': learned, 'skipped_or_failed': failed, 'folder': path}


def tail_log(lines=200, path='/var/log/rspamd/rspamd.log'):
    lines = max(10, min(int(lines), 2000))
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 512 * 1024))
            data = handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        raise RspamdError('No Rspamd log at %s.' % path)
    return {'path': path, 'lines': data[-lines:]}


# ----------------------------------------------------------------------------- install

def install_commands(family, version, codename=''):
    """Package-manager commands to install rspamd + redis for an OS profile family."""
    if family == 'rhel':
        major = int(version)
        repo = 'https://rspamd.com/rpm-stable/centos-%d/rspamd.repo' % min(max(major, 8), 9)
        return [
            ['curl', '-fsSL', '-o', '/etc/yum.repos.d/rspamd.repo', repo],
            ['rpm', '--import', 'https://rspamd.com/rpm-stable/gpg.key'],
            ['dnf', '-y', 'install', 'redis', 'rspamd'],
            ['systemctl', 'enable', '--now', 'redis'],
            ['systemctl', 'enable', 'rspamd'],
        ]
    if family == 'debian':
        if not re.match(r'^[a-z]+$', codename or ''):
            raise RspamdError('Unknown distribution codename.')
        return [
            ['apt-get', 'update'],
            ['apt-get', '-y', 'install', 'gnupg', 'curl', 'redis-server'],
            ['sh', '-c', 'curl -fsSL https://rspamd.com/apt-stable/gpg.key | gpg --dearmor '
             '> /etc/apt/trusted.gpg.d/rspamd.gpg'],
            ['sh', '-c', 'echo "deb [arch=amd64,arm64] http://rspamd.com/apt-stable/ %s main" '
             '> /etc/apt/sources.list.d/rspamd.list' % codename],
            ['apt-get', 'update'],
            ['apt-get', '-y', 'install', 'rspamd'],
            ['systemctl', 'enable', '--now', 'redis-server'],
            ['systemctl', 'enable', 'rspamd'],
        ]
    raise RspamdError('Unsupported OS family for automatic install.')
