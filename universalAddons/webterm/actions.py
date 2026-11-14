"""Root-side Web Terminal actions (dispatched by universalAddons/runner.py)."""
import os
import re
import shutil
import subprocess
import time

from universalAddons.webterm import service, tickets

VHOSTS = '/usr/local/lsws/conf/vhosts'
MARK_BEGIN = '# BEGIN cp-ua-webterm'
MARK_END = '# END cp-ua-webterm'
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


class SetupError(ValueError):
    pass


def _run(argv, timeout=120):
    try:
        out = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                             timeout=timeout)
        return out.returncode, out.stdout or ''
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def _write(path, text, mode=0o644):
    with open(path + '.tmp', 'w') as handle:
        handle.write(text)
    os.chmod(path + '.tmp', mode)
    os.replace(path + '.tmp', path)


# ----------------------------------------------------------------------------- OpenLiteSpeed proxy block

def render_block(port):
    return '%s\nwebsocket %s {\n  address                 127.0.0.1:%d\n}\n%s\n' % (
        MARK_BEGIN, service.WS_PATH, int(port), MARK_END)


def strip_block(text):
    return re.sub(r'\n?%s\n.*?%s\n?' % (re.escape(MARK_BEGIN), re.escape(MARK_END)), '\n', text, flags=re.S)


def apply_block(text, port):
    """Idempotent: the managed websocket block, placed before vhssl like the other add-ons."""
    base = strip_block(text).rstrip('\n') + '\n'
    if re.search(r'^websocket\s+%s\s*\{' % re.escape(service.WS_PATH), base, re.M):
        raise SetupError('This site already has its own websocket context for %s.' % service.WS_PATH)
    block = render_block(port)
    match = re.search(r'^vhssl\s*\{', base, re.M)
    text = base[:match.start()] + block + '\n' + base[match.start():] if match else base + '\n' + block
    text = re.sub(r'\n{3,}', '\n\n', text)
    if text.count('{') != text.count('}'):
        raise SetupError('Refusing to write an unbalanced vhost configuration.')
    return text


def _vhost_path(site):
    if not DOMAIN_RE.match(site or ''):
        raise SetupError('Invalid site name.')
    path = os.path.join(VHOSTS, site, 'vhost.conf')
    if not os.path.isfile(path):
        raise SetupError('%s has no OpenLiteSpeed vhost.' % site)
    return path


def _status_code(site):
    code, out = _run(['curl', '-sk', '-o', '/dev/null', '-m', '20', '-w', '%{http_code}',
                      '--resolve', '%s:443:127.0.0.1' % site, 'https://%s/' % site], timeout=30)
    return out.strip() if code == 0 else 'error'


def _ws_probe(site):
    """An unauthenticated upgrade through OLS must reach the service (it answers 101, then closes)."""
    code, out = _run(['curl', '-sk', '-o', '/dev/null', '-m', '10', '-w', '%{http_code}', '--http1.1',
                      '--resolve', '%s:443:127.0.0.1' % site,
                      '-H', 'Connection: Upgrade', '-H', 'Upgrade: websocket', '-H', 'Sec-WebSocket-Version: 13',
                      '-H', 'Sec-WebSocket-Key: Y3AtdWEtd2VidGVybS1wcm9iZQ==',
                      'https://%s%s' % (site, service.WS_PATH)], timeout=20)
    return out.strip()


def _restart_ols():
    return _run(['/usr/local/lsws/bin/lswsctrl', 'restart'])[0] == 0


# ----------------------------------------------------------------------------- actions

def overview():
    config = service.load_config()
    proxied = False
    if config.get('site'):
        try:
            with open(_vhost_path(config['site'])) as handle:
                proxied = MARK_BEGIN in handle.read()
        except (OSError, SetupError):
            proxied = False
    return {'service': service.service_status(), 'config': config, 'proxied': proxied,
            'policy': service.terminal_policy(), 'unit_installed': os.path.exists(service.UNIT_PATH)}


def setup(site):
    """Install/refresh the service and route https://<site>/cp-webterm/ws to it."""
    path = _vhost_path(site)
    config = service.save_config(dict(service.load_config(), site=site, listen='127.0.0.1', tls=False,
                                      trust_proxy=True, public_url='wss://%s%s' % (site, service.WS_PATH)))
    _write(service.UNIT_PATH, service.render_unit(config, service.systemd_version(), service.cgroup_v2()))
    _write(service.LOGROTATE_PATH, service.render_logrotate())
    _run(['systemctl', 'daemon-reload'])
    code, out = _run(['systemctl', 'enable', '--now', service.SERVICE])
    if code != 0:
        raise SetupError('The terminal service did not start: %s' % out.strip()[-300:])
    _run(['systemctl', 'restart', service.SERVICE])
    time.sleep(1)
    if not service.service_status()['running']:
        raise SetupError('The terminal service is not running; see journalctl -u %s.' % service.SERVICE)

    with open(path) as handle:
        original = handle.read()
    updated = apply_block(original, config['port'])
    if updated == original:
        return dict(overview(), changed=False)
    before = _status_code(site)
    backup = '%s.bak-webterm-%d' % (path, int(time.time()))
    shutil.copy2(path, backup)
    _write(path, updated, os.stat(path).st_mode & 0o777)
    _restart_ols()
    time.sleep(3)
    after, probe = _status_code(site), _ws_probe(site)
    if after != before or probe != '101':
        shutil.copy2(backup, path)
        _restart_ols()
        raise SetupError('Rolled back: the site answered %s (was %s) and the websocket probe %s.' % (after, before, probe))
    return dict(overview(), changed=True, backup=backup)


def teardown():
    """Remove the proxy block and stop the service (the unit file stays, disabled)."""
    config = service.load_config()
    if config.get('site'):
        try:
            path = _vhost_path(config['site'])
            with open(path) as handle:
                text = handle.read()
            if MARK_BEGIN in text:
                stripped = re.sub(r'\n{3,}', '\n\n', strip_block(text))
                _write(path, stripped, os.stat(path).st_mode & 0o777)
                _restart_ols()
        except SetupError:
            pass
    _run(['systemctl', 'disable', '--now', service.SERVICE])
    return overview()


def issue_ticket(record):
    """Called by the panel after its own session, ownership and policy checks."""
    allowed = {'user_id', 'username', 'is_admin', 'domain', 'system_user', 'root', 'ip', 'host'}
    record = {k: v for k, v in record.items() if k in allowed}
    if not service.valid_host(record.get('host')):
        raise tickets.TicketError('Invalid panel host.')
    config = service.load_config()
    if not config.get('public_url') or not service.service_status()['running']:
        raise tickets.TicketError('The web terminal service is not set up yet; an administrator must enable it.')
    return {'ticket': tickets.issue(record), 'url': config['public_url'], 'ttl': tickets.TTL}


def save_policy(values):
    return service.save_terminal_policy(values)


ACTIONS = {
    'overview': overview,
    'setup': setup,
    'teardown': teardown,
    'ticket': issue_ticket,
    'save_policy': save_policy,
}
