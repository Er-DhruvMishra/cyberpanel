"""Apply .htaccess translations to OpenLiteSpeed vhosts, watch for changes, guard logins.

Safety model
- Opt-in per site. Nothing is touched for sites that are not enabled.
- Preview first: the generated configuration, a per-line report and any conflicts.
- Apply = back up vhost.conf (+ root .htaccess), write atomically, graceful restart, health
  check (OpenLiteSpeed running and the site answering without a 5xx). On failure the previous
  files are restored and OpenLiteSpeed is restarted again.
- The watcher re-applies only when the translated output really changed, and restarts at most
  once per run for all changed sites.
- The brute-force guard counts POSTs to protected paths in each site's access log and blocks
  offenders with self-expiring firewall rules (firewalld or CSF), never permanently.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

from universalAddons.htaccess import translator as tr

VHOSTS = '/usr/local/lsws/conf/vhosts'
LSWSCTRL = '/usr/local/lsws/bin/lswsctrl'
STATE_FILE = '/etc/cyberpanel/universal-htaccess.json'
BACKUP_DIR = '/var/lib/cyberpanel-universal/htaccess-backups'
SKIP_DIRS = {'.git', 'node_modules', 'cache', '.cache', 'vendor', '.cp-wp-snapshots', 'litespeed'}
MAX_DEPTH, MAX_FILES, MAX_BYTES = 6, 200, 256 * 1024


class HtaccessError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=120):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- state

def load_state(path=None):
    try:
        with open(path or STATE_FILE) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    data.setdefault('sites', {})
    data.setdefault('blocks', [])
    return data


def save_state(data, path=None):
    path = path or STATE_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(temporary, path)


# ----------------------------------------------------------------------------- collection

def collect(docroot):
    """{relative_dir: text} for every .htaccess under docroot (bounded depth/count/size)."""
    files = {}
    base_depth = docroot.rstrip('/').count('/')
    for current, dirs, names in os.walk(docroot):
        depth = current.rstrip('/').count('/') - base_depth
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(current, d)))
        if depth >= MAX_DEPTH:
            dirs[:] = []
        if '.htaccess' in names:
            path = os.path.join(current, '.htaccess')
            if os.path.islink(path):
                continue
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                with open(path, encoding='utf-8', errors='replace') as handle:
                    text = handle.read()
            except OSError:
                continue
            rel = os.path.relpath(current, docroot)
            files['' if rel == '.' else rel] = tr.strip_managed(text, tr.HT_BEGIN, tr.HT_END)
            if len(files) >= MAX_FILES:
                break
    return files


def fingerprint(files):
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(rel.encode() + b'\0' + files[rel].encode() + b'\0')
    return digest.hexdigest()


# ----------------------------------------------------------------------------- preview / apply

def plan(domain, docroot, home, vhosts=VHOSTS):
    vhost_path = os.path.join(vhosts, domain, 'vhost.conf')
    if not os.path.isfile(vhost_path):
        raise HtaccessError('No OpenLiteSpeed vhost for %s.' % domain)
    with open(vhost_path) as handle:
        vhost_text = handle.read()
    files = collect(docroot)
    result = tr.translate(files, home, docroot)
    clashes = tr.conflicts(vhost_text, result)
    if clashes:
        # Never duplicate blocks the administrator manages by hand.
        result.contexts = [c for c in result.contexts if 'context %s' % c.uri not in clashes]
        result.vhost['errorpages'] = {k: v for k, v in result.vhost['errorpages'].items()
                                      if 'errorpage %s' % k not in clashes}
        if 'expires' in clashes:
            result.vhost['expires'] = None
    new_vhost = tr.apply_to_vhost(vhost_text, result)
    root_htaccess = os.path.join(docroot, '.htaccess')
    try:
        with open(root_htaccess) as handle:
            current_htaccess = handle.read()
    except OSError:
        current_htaccess = ''
    new_htaccess = tr.apply_redirects(current_htaccess, result.redirects.get('', []))
    return {
        'domain': domain, 'vhost_path': vhost_path, 'htaccess_path': root_htaccess,
        'vhost_before': vhost_text, 'vhost_after': new_vhost,
        'htaccess_before': current_htaccess, 'htaccess_after': new_htaccess,
        'report': result.report, 'conflicts': clashes, 'bruteforce': result.bruteforce,
        'fingerprint': fingerprint(files), 'files': sorted(files),
        'changed': new_vhost != vhost_text or new_htaccess != current_htaccess,
    }


def _write_atomic(path, text):
    """Replace path atomically, keeping its mode/owner; a new file gets 0644 and the directory's owner."""
    if os.path.exists(path):
        info = os.stat(path)
        mode, uid, gid = info.st_mode & 0o777, info.st_uid, info.st_gid
    else:
        info = os.stat(os.path.dirname(path))
        mode, uid, gid = 0o644, info.st_uid, info.st_gid
    temporary = '%s.cp-ua.%d' % (path, os.getpid())
    with open(temporary, 'w') as handle:
        handle.write(text)
    os.chmod(temporary, mode)
    try:
        os.chown(temporary, uid, gid)
    except PermissionError:
        pass  # not root (tests): ownership already matches the caller
    os.replace(temporary, path)


def _backup(paths, backup_root=None):
    directory = os.path.join(backup_root or BACKUP_DIR, time.strftime('%Y%m%d-%H%M%S-') + os.urandom(2).hex())
    os.makedirs(directory, mode=0o700)
    saved = {}
    for index, path in enumerate(paths):
        if os.path.exists(path):
            target = os.path.join(directory, '%02d' % index)
            shutil.copy2(path, target)
            saved[path] = target
        else:
            saved[path] = None
    with open(os.path.join(directory, 'manifest.json'), 'w') as handle:
        json.dump(saved, handle)
    return saved


def _restore(saved):
    for path, copy in saved.items():
        if copy:
            shutil.copy2(copy, path)
        elif os.path.exists(path):
            os.unlink(path)


def lsws_running(runner=subprocess.run):
    code, out = run([LSWSCTRL, 'status'], runner, timeout=30)
    return 'is running' in out


def restart(runner=subprocess.run):
    """Graceful OpenLiteSpeed restart, then wait until it reports running."""
    run([LSWSCTRL, 'restart'], runner, timeout=120)
    for _ in range(15):
        if lsws_running(runner):
            return True
        time.sleep(1)
    return False


def site_healthy(domain, runner=subprocess.run):
    for scheme, port in (('https', '443'), ('http', '80')):
        code, out = run(['curl', '-sS', '-k', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20',
                         '--resolve', '%s:%s:127.0.0.1' % (domain, port), '%s://%s/' % (scheme, domain)],
                        runner, timeout=40)
        status = out.strip()[-3:]
        if code == 0 and status.isdigit():
            return int(status) < 500, status
    return False, '000'


def apply_plans(plans, runner=subprocess.run, backup_root=None, healthy=None, do_restart=None):
    """Write every changed plan, restart once, verify; roll every site back if anything failed."""
    healthy = healthy or (lambda domain: site_healthy(domain, runner))
    do_restart = do_restart or (lambda: restart(runner))
    changed = [p for p in plans if p['changed']]
    if not changed:
        return {'applied': [], 'restarted': False}
    saved = _backup([path for p in changed for path in (p['vhost_path'], p['htaccess_path'])], backup_root)
    try:
        for p in changed:
            if p['vhost_after'] != p['vhost_before']:
                _write_atomic(p['vhost_path'], p['vhost_after'])
            if p['htaccess_after'] != p['htaccess_before']:
                _write_atomic(p['htaccess_path'], p['htaccess_after'])
        if not do_restart():
            raise HtaccessError('OpenLiteSpeed did not come back after the restart.')
        failures = []
        for p in changed:
            ok, status = healthy(p['domain'])
            if not ok:
                failures.append('%s answered HTTP %s' % (p['domain'], status))
        if failures:
            raise HtaccessError('Health check failed: %s' % '; '.join(failures))
    except Exception as exc:
        _restore(saved)
        do_restart()
        raise HtaccessError('%s The previous configuration was restored.' % exc)
    return {'applied': [p['domain'] for p in changed], 'restarted': True}


# ----------------------------------------------------------------------------- brute-force guard

LOG_LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3})')


def parse_access_time(text):
    import datetime
    try:
        return datetime.datetime.strptime(text, '%d/%b/%Y:%H:%M:%S %z').timestamp()
    except ValueError:
        return None


def scan_log(lines, config, now=None):
    """Return {ip: attempts} of POSTs to protected paths within the window, minus whitelist."""
    import ipaddress
    now = now or time.time()
    window = config.get('window', 300)
    paths = config.get('paths') or ['/wp-login.php', '/xmlrpc.php']
    whitelist = []
    for item in config.get('whitelist', []):
        try:
            whitelist.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    counts = {}
    for line in lines:
        match = LOG_LINE.match(line)
        if not match or match.group(3) != 'POST':
            continue
        path = match.group(4).split('?', 1)[0]
        if not any(path == p or path.startswith(p.rstrip('/') + '/') for p in paths):
            continue
        stamp = parse_access_time(match.group(2))
        if stamp is None or now - stamp > window:
            continue
        ip = match.group(1)
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(address in net for net in whitelist):
            continue
        counts[ip] = counts.get(ip, 0) + 1
    return counts


def offenders(counts, config):
    limit = config.get('attempts', 10)
    return sorted(ip for ip, count in counts.items() if count > limit)


def block_ip(ip, seconds, runner=subprocess.run, which=shutil.which):
    """Self-expiring block with firewalld (runtime rule + timeout) or CSF (csf -td)."""
    family = 'ipv6' if ':' in ip else 'ipv4'
    if which('firewall-cmd') and run(['firewall-cmd', '--state'], runner)[1].strip() == 'running':
        rule = 'rule family="%s" source address="%s" reject' % (family, ip)
        code, out = run(['firewall-cmd', '--add-rich-rule=' + rule, '--timeout=%d' % seconds], runner)
        if code == 0 or 'ALREADY_ENABLED' in out:
            return 'firewalld'
        raise HtaccessError('firewalld refused the block: ' + out.strip()[-200:])
    if which('csf'):
        code, out = run(['csf', '-td', ip, str(seconds), 'CyberPanel brute-force guard'], runner)
        if code == 0:
            return 'csf'
        raise HtaccessError('csf refused the block: ' + out.strip()[-200:])
    raise HtaccessError('No firewall (firewalld or CSF) is available to block %s.' % ip)


def tail_lines(path, max_bytes=2 * 1024 * 1024):
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            data = handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return []
    return data[1:] if size > max_bytes else data


def guard(site_configs, state, runner=subprocess.run, now=None, log_path=None, blocker=None):
    """site_configs: {domain: bruteforce config}. Blocks offenders; returns new block events."""
    now = now or time.time()
    blocker = blocker or (lambda ip, seconds: block_ip(ip, seconds, runner))
    active = {(b['ip'], b['domain']) for b in state['blocks'] if b.get('until', 0) > now}
    events = []
    for domain, config in sorted(site_configs.items()):
        if not config or not config.get('enabled'):
            continue
        path = (log_path or (lambda d: '/home/%s/logs/%s.access_log' % (d, d)))(domain)
        counts = scan_log(tail_lines(path), config, now)
        for ip in offenders(counts, config):
            if (ip, domain) in active:
                continue
            action = config.get('action', 'block')
            seconds = config.get('window', 300) if action == 'throttle' else max(3600, config.get('window', 300) * 4)
            event = {'ip': ip, 'domain': domain, 'attempts': counts[ip], 'at': int(now), 'action': action}
            if action in ('block', 'throttle'):
                try:
                    event['via'] = blocker(ip, seconds)
                    event['until'] = int(now + seconds)
                except HtaccessError as exc:
                    event['error'] = str(exc)
            events.append(event)
    state['blocks'] = [b for b in state['blocks'] if b.get('until', b.get('at', 0) + 86400) > now - 86400] + events
    state['blocks'] = state['blocks'][-500:]
    return events
