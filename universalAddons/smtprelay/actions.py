"""Root-side SMTP Relay actions (dispatched by universalAddons/runner.py).

Every change: lock, back up main.cf and the three maps, write the maps (postmap), write main.cf,
`postfix check`, `postfix reload`. If any step fails, the backup is put back (and Postfix reloaded
when it had been reloaded) and the error is reported. Only the keys in service.MANAGED_KEYS are
changed in main.cf. Passwords live only in /etc/postfix/sasl_passwd (mode 600, root).
"""
import email.utils
import fcntl
import json
import os
import shutil
import smtplib
import socket
import ssl
import subprocess
import time

from universalAddons.smtprelay import service as sv
from universalAddons.smtprelay.service import RelayError

STATE_DIR = '/etc/cyberpanel/smtprelay'
CONFIG_FILE = os.path.join(STATE_DIR, 'config.json')
BACKUP_DIR = os.path.join(STATE_DIR, 'backups')
KEEP_BACKUPS = 10
MAIL_LOGS = ('/var/log/maillog', '/var/log/mail.log')
LOG_TAIL_BYTES = 2 * 1024 * 1024
SASL_PLUGIN_DIRS = ('/usr/lib64/sasl2', '/usr/lib/sasl2', '/usr/lib/x86_64-linux-gnu/sasl2',
                    '/usr/lib/aarch64-linux-gnu/sasl2')
CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
TEST_TIMEOUT = 20


def _run(argv, timeout=60, runner=subprocess.run):
    try:
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                        timeout=timeout, env=CLEAN_ENV)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return result.returncode, result.stdout or ''


def _read(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return None


def _write(path, text, mode):
    """Atomic write that keeps an existing file's owner (main.cf) and sets `mode`."""
    temporary = path + '.ic-tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as handle:
        handle.write(text)
    os.chmod(temporary, mode)
    try:
        info = os.stat(path)
        os.chown(temporary, info.st_uid, info.st_gid)
    except OSError:
        pass
    os.replace(temporary, path)


def _lock():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    handle = open(os.path.join(STATE_DIR, '.lock'), 'w')
    fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


def load_config():
    try:
        with open(CONFIG_FILE) as handle:
            data = json.load(handle)
        return {'enabled': data.get('enabled') is True, 'config': sv.validate_config(data['config'])}
    except (OSError, ValueError, KeyError, TypeError):
        return {'enabled': False, 'config': None}


def save_config(enabled, config):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    _write(CONFIG_FILE, json.dumps({'version': 1, 'enabled': enabled, 'config': config}, indent=1), 0o600)


def db_type(runner=subprocess.run):
    code, out = _run(['postconf', '-h', 'default_database_type'], 20, runner)
    value = out.strip().splitlines()[-1].strip() if code == 0 and out.strip() else 'hash'
    return value if value in sv.DB_SUFFIX else 'hash'


def stored_credentials():
    return sv.parse_sasl(_read(sv.SASL_MAP) or '')


# ----------------------------------------------------------------------------- backup / rollback

def managed_files(dbt):
    files = [sv.MAIN_CF]
    for path in sv.MAP_FILES:
        files += [path, sv.map_path(path, dbt)]
    return files


def backup(dbt, backup_dir=None):
    """Copy every file a change may touch into a new private directory; record which ones existed."""
    backup_dir = backup_dir or BACKUP_DIR
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    target = os.path.join(backup_dir, time.strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(3).hex())
    os.makedirs(target, mode=0o700)
    manifest = {}
    for index, path in enumerate(managed_files(dbt)):
        if os.path.isfile(path):
            copy = os.path.join(target, '%02d-%s' % (index, os.path.basename(path)))
            shutil.copy2(path, copy)
            os.chmod(copy, 0o600)
            info = os.stat(path)
            manifest[path] = {'copy': copy, 'mode': info.st_mode & 0o7777, 'uid': info.st_uid, 'gid': info.st_gid}
        else:
            manifest[path] = None
    with open(os.path.join(target, 'manifest.json'), 'w') as handle:
        json.dump(manifest, handle, indent=1)
    names = sorted(n for n in os.listdir(backup_dir) if os.path.isdir(os.path.join(backup_dir, n)))
    for old in names[:-KEEP_BACKUPS]:
        shutil.rmtree(os.path.join(backup_dir, old), ignore_errors=True)
    return target


def restore(target):
    with open(os.path.join(target, 'manifest.json')) as handle:
        manifest = json.load(handle)
    for path, saved in manifest.items():
        if saved is None:
            if os.path.lexists(path):
                os.unlink(path)
            continue
        temporary = path + '.ic-restore'
        shutil.copy2(saved['copy'], temporary)
        os.chmod(temporary, saved['mode'])
        try:
            os.chown(temporary, saved['uid'], saved['gid'])
        except OSError:
            pass
        os.replace(temporary, path)


def _postfix_running(runner):
    return _run(['postfix', 'status'], 30, runner)[0] == 0


def _commit(main_text, maps, dbt, runner, backup_dir=None):
    """Write the new main.cf (and maps, when given), check and reload; undo everything on failure."""
    target = backup(dbt, backup_dir)
    reloaded = False
    try:
        for path, text in (maps or {}).items():
            _write(path, text, 0o600 if path == sv.SASL_MAP else 0o644)
            code, out = _run(['postmap', '%s:%s' % (dbt, path)], 60, runner)
            if code != 0:
                raise RelayError('postmap %s failed: %s' % (path, out.strip()[-400:]))
            if path == sv.SASL_MAP and os.path.exists(sv.map_path(path, dbt)):
                os.chmod(sv.map_path(path, dbt), 0o600)
        _write(sv.MAIN_CF, main_text, 0o644 if not os.path.exists(sv.MAIN_CF) else os.stat(sv.MAIN_CF).st_mode & 0o7777)
        code, out = _run(['postfix', 'check'], 60, runner)
        if code != 0:
            raise RelayError('postfix check failed, nothing was changed: %s' % out.strip()[-600:])
        if _postfix_running(runner):
            reloaded = True
            code, out = _run(['postfix', 'reload'], 60, runner)
            if code != 0:
                raise RelayError('Postfix did not reload, the previous settings were restored: %s' % out.strip()[-600:])
            note = 'Postfix reloaded.'
        else:
            note = 'Postfix is not running; the settings take effect when it starts.'
    except Exception as exc:
        restore(target)
        if reloaded:
            _run(['postfix', 'reload'], 60, runner)
        if isinstance(exc, RelayError):
            raise
        raise RelayError('The change failed and was undone: %s' % exc)
    return {'backup': target, 'note': note}


def _sasl_plugin_present():
    for directory in SASL_PLUGIN_DIRS:
        try:
            if any(name.startswith(('libplain.so', 'liblogin.so')) for name in os.listdir(directory)):
                return True
        except OSError:
            continue
    return False


# ----------------------------------------------------------------------------- actions

def apply(config, secrets=None, confirm=False, runner=subprocess.run, backup_dir=None):
    config = sv.validate_config(config)
    with _lock():
        dbt = db_type(runner)
        current = _read(sv.MAIN_CF)
        if current is None:
            raise RelayError('%s does not exist; is Postfix installed?' % sv.MAIN_CF)
        passwords = sv.resolve_passwords(config, secrets, stored_credentials())
        if passwords and not _sasl_plugin_present():
            raise RelayError('The SASL PLAIN/LOGIN plugin is missing, so Postfix cannot log in to the relay. Install '
                             'cyrus-sasl-plain (dnf) or libsasl2-modules (apt) first.')
        foreign = sv.foreign_settings(current, config, dbt)
        if foreign and not confirm:
            return {'needs_confirm': ['main.cf already sets %s = %s; saving replaces it.' % kv
                                      for kv in sorted(foreign.items())]}
        result = _commit(sv.render_main_cf(current, config, dbt), sv.render_maps(config, passwords), dbt, runner,
                         backup_dir)
        save_config(True, config)
    result.update(applied=True, warnings=sv.warnings(config), main_cf=sv.managed_values(config, dbt))
    return result


def disable(forget=False, runner=subprocess.run, backup_dir=None):
    with _lock():
        dbt = db_type(runner)
        current = _read(sv.MAIN_CF)
        if current is None:
            raise RelayError('%s does not exist.' % sv.MAIN_CF)
        maps = None
        if forget:  # drop the stored credentials too (empty maps, so nothing referenced is missing)
            maps = {sv.SASL_MAP: '# Managed by IndiansCloud SMTP Relay. No credentials stored.\n'}
        result = _commit(sv.render_main_cf(current, None, dbt), maps, dbt, runner, backup_dir)
        state = load_config()
        save_config(False, None if forget else state['config'])
    result.update(disabled=True)
    return result


def _tail(path, size=LOG_TAIL_BYTES):
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            end = handle.tell()
            handle.seek(max(0, end - size))
            if end > size:
                handle.readline()
            return handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return []


def queue(runner=subprocess.Popen, limit=50000):
    try:
        process = runner(['postqueue', '-j'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         universal_newlines=True, env=CLEAN_ENV)
    except OSError as exc:
        return {'error': str(exc)}
    try:
        return sv.queue_summary(process.stdout, limit)
    finally:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()


def overview(runner=subprocess.run, popen=subprocess.Popen):
    state = load_config()
    config = state['config']
    stored = stored_credentials()
    effective = {}
    for key in ('relayhost', 'sender_dependent_relayhost_maps', 'smtp_tls_wrappermode', 'smtp_sasl_auth_enable'):
        code, out = _run(['postconf', '-h', key], 20, runner)
        effective[key] = out.strip().splitlines()[-1].strip() if code == 0 and out.strip() else ''
    text = _read(sv.MAIN_CF) or ''
    managed = sv.BEGIN in text
    foreign = sv.foreign_settings(text, config if managed else None, db_type(runner))
    hosts = [r['host'] for r in sv.used_relays(config)] if config else []
    if effective['relayhost']:
        hosts.append(effective['relayhost'].lstrip('[').split(']')[0].split(':')[0])
    log_path = next((p for p in MAIL_LOGS if os.path.exists(p)), None)
    return {
        'enabled': state['enabled'] and managed,
        'config': sv.public_config(config, stored),
        'effective': effective,
        'managed_block': managed,
        'foreign': foreign,
        'warnings': sv.warnings(config) if config else [],
        'sasl_plugin': _sasl_plugin_present(),
        'queue': queue(popen),
        'log_file': log_path,
        'log': sv.relay_log_lines(_tail(log_path), hosts) if log_path else [],
        'postfix_running': _postfix_running(runner),
    }


# ----------------------------------------------------------------------------- test message

class _Recorder:
    def __init__(self):
        self.lines = []
        self.data_pending = False   # DATA sent, waiting for 354
        self.in_data = False        # the next send() is the message body

    def add(self, direction, text):
        for part in str(text).splitlines() or ['']:
            self.lines.append((direction, part[:500]))


def _transcript_class(base, recorder):
    """smtplib client that records each command and reply (the message body only as its size)."""
    class Transcript(base):
        def send(self, s):
            text = s.decode('utf-8', 'replace') if isinstance(s, bytes) else str(s)
            if recorder.in_data:
                recorder.in_data = False
                recorder.add('C', '<message body, %d bytes>' % len(text))
            else:
                recorder.add('C', text.rstrip('\r\n'))
            return super().send(s)

        def getreply(self):
            code, message = super().getreply()
            text = message.decode('utf-8', 'replace') if isinstance(message, bytes) else str(message)
            for line in text.splitlines() or ['']:
                recorder.add('S', '%s %s' % (code, line))
            if recorder.data_pending:
                recorder.data_pending = False
                recorder.in_data = code == 354
            return code, message

        def data(self, msg):
            recorder.data_pending = True
            try:
                return super().data(msg)
            finally:
                recorder.data_pending = recorder.in_data = False
    return Transcript


def _test_message(sender, to, relay_label):
    host = socket.getfqdn()
    return ('From: %s\r\nTo: %s\r\nSubject: IndiansCloud SMTP relay test\r\nDate: %s\r\nMessage-ID: %s\r\n'
            'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            'This is a test message sent by the IndiansCloud panel on %s through the relay %s.\r\n'
            'If you can read it, the relay accepted and delivered it.\r\n'
            % (sender, to, email.utils.formatdate(localtime=True), email.utils.make_msgid(domain=host), host,
               relay_label))


def send_test(to, target='global', sender='', smtp_factory=None, timeout=TEST_TIMEOUT):
    """Send one message straight to the saved relay with the stored credentials; return the masked
    SMTP transcript. target: 'global' or 'domain:<name>'."""
    to = sv.clean_email(to, 'recipient address')
    state = load_config()
    config = state['config']
    if not config:
        raise RelayError('Save the relay settings first.')
    if target == 'global':
        if not config.get('relay'):
            raise RelayError('There is no global relay.')
        relay, key, domain = config['relay'], sv.nexthop(config['relay']['host'], config['relay']['port']), None
    else:
        name = str(target)[len('domain:'):] if str(target).startswith('domain:') else ''
        entry = next((d for d in config['domains'] if d['domain'] == name), None)
        if entry is None:
            raise RelayError('Unknown sender domain.')
        relay, domain = sv.domain_relay(config, entry), name
        key = '@' + name if entry.get('username') else sv.nexthop(relay['host'], relay['port'])
    username = sv.credential_keys(config).get(key)
    password = stored_credentials().get(key, (None, None))[1] if username else None
    if sender:
        sender = sv.clean_email(sender, 'sender address')
        if domain and not sender.lower().endswith('@' + domain):
            raise RelayError('The sender must be an address at %s.' % domain)
    else:
        sender = 'postmaster@%s' % (domain or socket.getfqdn())
    label = sv.nexthop(relay['host'], relay['port'])
    recorder = _Recorder()
    result = {'relay': label, 'tls': relay['tls'], 'from': sender, 'to': to, 'authenticated': False,
              'tls_verified': None}
    start = time.time()

    def connect(verify):
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if smtp_factory:
            return smtp_factory(relay, context, recorder), context
        if relay['tls'] == 'implicit':
            client = _transcript_class(smtplib.SMTP_SSL, recorder)(relay['host'], relay['port'], timeout=timeout,
                                                                    context=context)
        else:
            client = _transcript_class(smtplib.SMTP, recorder)(relay['host'], relay['port'], timeout=timeout)
        return client, context

    client = None
    try:
        recorder.add('*', 'Connecting to %s (%s)' % (label, relay['tls']))
        try:
            client, context = connect(True)
            if relay['tls'] == 'implicit':
                result['tls_verified'] = True
        except ssl.SSLCertVerificationError as exc:
            recorder.add('*', 'Certificate NOT verified: %s. Retrying without verification (Postfix\'s '
                              '"encrypt" level does not verify certificates either).' % exc)
            result['tls_verified'] = False
            client, context = connect(False)
        client.ehlo(socket.getfqdn())
        if relay['tls'] == 'starttls':
            if not client.has_extn('starttls'):
                raise RelayError('The relay does not offer STARTTLS.')
            try:
                client.starttls(context=context)
                result['tls_verified'] = context.verify_mode != ssl.CERT_NONE
            except ssl.SSLCertVerificationError as exc:
                recorder.add('*', 'Certificate NOT verified: %s. Retrying without verification.' % exc)
                result['tls_verified'] = False
                try:
                    client.close()
                except Exception:
                    pass
                client, context = connect(False)
                client.ehlo(socket.getfqdn())
                client.starttls(context=context)
            recorder.add('*', 'TLS started (%s)' % (client.sock.version() if hasattr(client.sock, 'version') else 'TLS'))
            client.ehlo(socket.getfqdn())
        if username:
            if not password:
                raise RelayError('No password is stored for this relay; save the settings with the password.')
            client.login(username, password)
            result['authenticated'] = True
        refused = client.sendmail(sender, [to], _test_message(sender, to, label).encode('utf-8'))
        if refused:
            raise RelayError('The relay refused the recipient: %s' % refused)
        result.update(ok=True, message='The relay accepted the message for %s.' % to)
    except (RelayError, smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        result.update(ok=False, message=_explain(exc))
    finally:
        if client is not None:
            try:
                client.quit()
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass
    result['seconds'] = round(time.time() - start, 2)
    result['transcript'] = ['%s %s' % (d, t) if d != '*' else '-- ' + t for d, t in sv.mask_transcript(recorder.lines)]
    if password:  # belt and braces: the password never appears in the answer
        result['transcript'] = [line.replace(password, '****') for line in result['transcript']]
        result['message'] = result['message'].replace(password, '****')
    return result


def _explain(exc):
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return 'The relay rejected the user name or password (%s).' % exc.smtp_code
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return 'The relay refused the recipient.'
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return 'The relay refused the sender address (%s %s).' % (exc.smtp_code, exc.smtp_error.decode('utf-8', 'replace')[:200])
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return 'Timed out: the relay did not answer (is the port blocked by a firewall?).'
    if isinstance(exc, ConnectionRefusedError):
        return 'Connection refused by the relay.'
    if isinstance(exc, socket.gaierror):
        return 'The relay host name does not resolve.'
    return str(exc)[:400] or exc.__class__.__name__


ACTIONS = {
    'overview': lambda: overview(),
    'apply': lambda config, secrets=None, confirm=False: apply(config, secrets, confirm),
    'disable': lambda forget=False: disable(forget),
    'test': lambda to, target='global', sender='': send_test(to, target, sender),
}
