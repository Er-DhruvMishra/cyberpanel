"""Root-side SSH Security actions (dispatched by universalAddons/runner.py).

Read-only except: block/unblock (firewalld rich rules + the registry file) and enable_f2b_sshd
(writes only /etc/fail2ban/jail.d/cp-sshd.local). sshd_config is never touched.
"""
import fcntl
import glob
import gzip
import json
import os
import re
import subprocess
import time

from universalAddons import jobs
from universalAddons.sshsec import service as sv
from universalAddons.sshsec.service import SSHSecError

STATE_DIR = '/etc/cyberpanel/sshsec'
REGISTRY = os.path.join(STATE_DIR, 'blocked.json')
F2B_JAIL_FILE = '/etc/fail2ban/jail.d/cp-sshd.local'
LOG_BASES = ('/var/log/secure', '/var/log/auth.log')
# A clean environment for every tool: firewall-cmd and fail2ban-client are Python programs, and an
# inherited PYTHONPATH pointing at the CyberCP tree makes CyberPanel's own `firewall` package shadow
# firewalld's `firewall.client`.
CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def _run(argv, timeout=30, runner=subprocess.run):
    try:
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                        timeout=timeout, env=CLEAN_ENV)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return result.returncode, result.stdout or ''


def _active(unit, runner=subprocess.run):
    return _run(['systemctl', 'is-active', unit], 10, runner)[1].strip() == 'active'


def firewall_state(runner=subprocess.run):
    if not _active('firewalld', runner):
        return {'running': False, 'zone': None}
    code, out = _run(['firewall-cmd', '--get-default-zone'], 20, runner)
    zone = out.strip() if code == 0 and re.match(r'^[A-Za-z0-9_-]{1,32}$', out.strip()) else None
    code, active = _run(['firewall-cmd', '--get-active-zones'], 20, runner)
    return {'running': zone is not None, 'zone': zone,
            'zone_has_interfaces': bool(zone and re.search(r'^%s\n\s+(interfaces|sources):' % re.escape(zone), active,
                                                           re.M))}


def server_ips(runner=subprocess.run):
    return sv.parse_ip_addr(_run(['ip', '-o', 'addr', 'show'], 10, runner)[1])


def f2b_state(runner=subprocess.run):
    state = {'installed': bool(_which('fail2ban-client')), 'running': False, 'jail': False, 'jails': []}
    if not state['installed'] or not _active('fail2ban', runner):
        return state
    state['running'] = True
    code, out = _run(['fail2ban-client', 'status'], 20, runner)
    state['jails'] = sv.parse_f2b_jails(out) if code == 0 else []
    state['jail'] = 'sshd' in state['jails']
    if state['jail']:
        for key in ('maxretry', 'bantime', 'findtime'):
            code, out = _run(['fail2ban-client', 'get', 'sshd', key], 10, runner)
            state[key] = out.strip() if code == 0 and re.match(r'^-?\d+$', out.strip()) else '?'
        state['ignoreip'] = sv.parse_f2b_list(_run(['fail2ban-client', 'get', 'sshd', 'ignoreip'], 10, runner)[1])
    return state


def _which(name):
    import shutil
    return shutil.which(name) or next((p for p in ('/usr/bin/' + name, '/usr/sbin/' + name) if os.path.exists(p)),
                                      None)


def block_index(firewall=None, runner=subprocess.run):
    """Everything that currently blocks addresses: runtime rich rules in every active zone,
    ipsets used by rich rules, and fail2ban bans."""
    index = sv.BlockIndex()
    firewall = firewall or firewall_state(runner)
    if firewall['running']:
        code, out = _run(['firewall-cmd', '--get-active-zones'], 20, runner)
        zones = [z for z in re.findall(r'^(\S+)\s*$', out, re.M) if re.match(r'^[A-Za-z0-9_-]{1,32}$', z)]
        for zone in dict.fromkeys(zones + [firewall['zone']]):
            code, rules = _run(['firewall-cmd', '--zone=' + zone, '--list-rich-rules'], 20, runner)
            for rule in sv.parse_rich_rules(rules if code == 0 else ''):
                label = 'firewalld %s%s' % (rule['action'], ' port ' + rule['port'] if rule['port'] else '')
                if 'network' in rule:
                    index.add(rule['network'], label)
                elif re.match(r'^[A-Za-z0-9_.-]{1,32}$', rule['ipset']):
                    code, entries = _run(['firewall-cmd', '--ipset=' + rule['ipset'], '--get-entries'], 30, runner)
                    for entry in entries.split()[:100000] if code == 0 else []:
                        index.add(entry, label + ' (ipset %s)' % rule['ipset'])
    state = f2b_state(runner)
    for jail in state['jails']:
        code, out = _run(['fail2ban-client', 'status', jail], 20, runner)
        for ip in sv.parse_f2b_banned(out if code == 0 else ''):
            index.add(ip, 'fail2ban ' + jail)
    return index


# ----------------------------------------------------------------------------- log reading

def log_files(cutoff, bases=LOG_BASES):
    """Auth log files that may hold lines after `cutoff`, newest first."""
    found = []
    for base in bases:
        for path in set(glob.glob(base) + glob.glob(base + '[.-]*')):
            if not re.match(r'^%s(\.\d+|-\d{8})?(\.gz)?$' % re.escape(base), path) or not os.path.isfile(path):
                continue
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if mtime >= cutoff:
                found.append((mtime, path))
    return [path for _, path in sorted(found, reverse=True)]


def read_files(analyzer, cutoff, paths, now=None, budget=None, per_file=None):
    budget = sv.MAX_BYTES_TOTAL if budget is None else budget
    per_file = sv.MAX_BYTES_PER_FILE if per_file is None else per_file
    coverage = []
    truncated = False
    for path in paths:
        if budget <= 0:
            truncated = True
            break
        allowance = min(budget, per_file)
        try:
            if path.endswith('.gz'):
                with gzip.open(path, 'rb') as handle:
                    used = sv.scan_stream(handle, analyzer, cutoff, allowance, now)
                size = used
            else:
                with open(path, 'rb') as handle:
                    size = os.fstat(handle.fileno()).st_size
                    window_start = sv.seek_time(handle, size, cutoff, now)
                    start = max(window_start, size - allowance)
                    if start > window_start:
                        truncated = True  # the window holds more than the allowance: newest part only
                    handle.seek(start)
                    if start:
                        handle.readline()
                    used = sv.scan_stream(handle, analyzer, cutoff, allowance, now)
        except (OSError, EOFError) as exc:
            coverage.append({'path': path, 'error': str(exc)[:200]})
            continue
        if used >= allowance:
            truncated = True
        budget -= used
        coverage.append({'path': path, 'bytes': used, 'size': size})
    return coverage, truncated


def read_journal(analyzer, cutoff, budget=None, popen=subprocess.Popen):
    """journalctl fallback, newest first, stopped after `budget` bytes."""
    budget = sv.MAX_BYTES_TOTAL if budget is None else budget
    since = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cutoff))
    argv = ['journalctl', '-q', '--no-pager', '-r', '-o', 'short-iso', '-u', 'sshd', '-u', 'ssh', '--since', since]
    try:
        process = popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=CLEAN_ENV)
    except OSError as exc:
        return [{'path': 'journalctl', 'error': str(exc)}], False
    try:
        used = sv.scan_stream(process.stdout, analyzer, cutoff, budget)
    finally:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
    return [{'path': 'journalctl -u sshd', 'bytes': used}], used >= budget


def analyze_now(window, client=(), bases=LOG_BASES, runner=subprocess.run, popen=subprocess.Popen, now=None):
    if window not in sv.WINDOWS:
        raise SSHSecError('Unknown window.')
    now = now or time.time()
    cutoff = now - sv.WINDOWS[window]
    analyzer = sv.Analyzer(cutoff)
    paths = log_files(cutoff, bases)
    coverage, truncated = read_files(analyzer, cutoff, paths, now)
    source = 'files'
    if analyzer.lines == 0:
        coverage2, truncated = read_journal(analyzer, cutoff, popen=popen)
        coverage += coverage2
        source = 'journal'
    index = block_index(runner=runner)
    result = analyzer.result(index)
    for ip in client:
        for row in result['top_ips']:
            if row['ip'] == ip:
                row['you'] = True
    result.update(window=window, cutoff=int(cutoff), source=source, coverage=coverage, truncated=truncated,
                  client=list(client))
    return result


def analyze_run(job_id, window, client=()):
    return jobs.run_job(job_id, [('Analysis', lambda job: analyze_now(window, client))])


# ----------------------------------------------------------------------------- registry

def _lock():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    handle = open(os.path.join(STATE_DIR, '.lock'), 'w')
    fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


def load_registry():
    try:
        with open(REGISTRY) as handle:
            data = json.load(handle)
        entries = data.get('entries', [])
        return [e for e in entries if isinstance(e, dict) and isinstance(e.get('target'), str)]
    except (OSError, ValueError, AttributeError):
        return []


def save_registry(entries):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    temporary = REGISTRY + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump({'version': 1, 'entries': entries}, handle, indent=1)
    os.replace(temporary, REGISTRY)


def blocklist(runner=subprocess.run):
    entries = load_registry()
    firewall = firewall_state(runner)
    live = set()
    if firewall['running']:
        zones = {e.get('zone') or firewall['zone'] for e in entries}
        for zone in zones:
            if not re.match(r'^[A-Za-z0-9_-]{1,32}$', zone or ''):
                continue
            code, out = _run(['firewall-cmd', '--zone=' + zone, '--list-rich-rules'], 20, runner)
            live.update((zone, str(r['network'])) for r in sv.parse_rich_rules(out) if 'network' in r
                        and r['action'] == 'drop' and not r['port'])
    for entry in entries:
        entry['active'] = (entry.get('zone') or firewall['zone'], entry['target']) in live
    return {'entries': sorted(entries, key=lambda e: -e.get('added', 0)), 'firewall': firewall}


def _apply(op, zone, network, runner):
    outputs = []
    for argv in sv.firewall_argvs(op, zone, network):
        code, out = _run(argv, 30, runner)
        if code != 0:
            raise SSHSecError('firewall-cmd failed: %s' % out.strip()[-300:])
        outputs.append(out.strip())
    return outputs


def block(target, reason='', client=(), confirm=False, by='', runner=subprocess.run):
    network = sv.parse_target(target)
    reason = sv.validate_reason(reason)
    firewall = firewall_state(runner)
    if not firewall['running']:
        raise SSHSecError('firewalld is not running, so nothing can be blocked. Start firewalld first '
                          '(this add-on has no iptables fallback).')
    refusals, confirmations = sv.block_checks(network, client, server_ips(runner))
    if refusals:
        raise SSHSecError(' '.join(refusals))
    if confirmations and not confirm:
        return {'needs_confirm': confirmations}
    with _lock():
        entries = load_registry()
        if any(e['target'] == str(network) for e in entries):
            raise SSHSecError('%s is already on the blocklist.' % network)
        if len(entries) >= sv.MAX_BLOCKS:
            raise SSHSecError('The blocklist holds %d entries; remove some first.' % sv.MAX_BLOCKS)
        _apply('add', firewall['zone'], network, runner)
        entry = {'target': str(network), 'family': network.version, 'zone': firewall['zone'],
                 'reason': reason, 'by': str(by)[:64], 'added': int(time.time()),
                 'rule': sv.rich_rule(network)}
        entries.append(entry)
        save_registry(entries)
    return {'blocked': entry}


def unblock(target, runner=subprocess.run):
    network = sv.parse_target(target)
    firewall = firewall_state(runner)
    if not firewall['running']:
        raise SSHSecError('firewalld is not running.')
    with _lock():
        entries = load_registry()
        entry = next((e for e in entries if e['target'] == str(network)), None)
        zone = (entry or {}).get('zone') or firewall['zone']
        _apply('remove', zone, network, runner)
        save_registry([e for e in entries if e['target'] != str(network)])
    return {'unblocked': str(network), 'was_registered': entry is not None}


# ----------------------------------------------------------------------------- audit & fail2ban

def _root_key_count():
    try:
        with open('/root/.ssh/authorized_keys') as handle:
            return sum(1 for line in handle if line.strip() and not line.lstrip().startswith('#'))
    except OSError:
        return 0


def audit(client=(), runner=subprocess.run):
    code, out = _run([_which('sshd') or '/usr/sbin/sshd', '-T'], 20, runner)
    if code != 0:
        raise SSHSecError('sshd -T failed: %s' % out.strip()[-300:])
    config = sv.parse_sshd_t(out)
    f2b = f2b_state(runner)
    return {'rows': sv.audit(config, f2b, _root_key_count(), client),
            'f2b': {k: v for k, v in f2b.items() if k != 'ignoreip'},
            'can_enable_jail': f2b['installed'] and not f2b['jail']}


def overview(runner=subprocess.run):
    firewall = firewall_state(runner)
    f2b = f2b_state(runner)
    sources = [b for b in LOG_BASES if os.path.exists(b)]
    return {'firewall': firewall, 'fail2ban': {'installed': f2b['installed'], 'running': f2b['running'],
                                               'jail': f2b['jail']},
            'log_sources': sources or ['journalctl'], 'blocked_count': len(load_registry())}


def enable_f2b_sshd(runner=subprocess.run, jail_file=None):
    jail_file = jail_file or F2B_JAIL_FILE
    state = f2b_state(runner)
    if not state['installed']:
        raise SSHSecError('fail2ban is not installed.')
    if state['jail']:
        return {'changed': False, 'message': 'The sshd jail is already active; nothing was written.'}
    code, out = _run([_which('sshd') or '/usr/sbin/sshd', '-T'], 20, runner)
    ports = sv.parse_sshd_t(out).get('port', '').split() if code == 0 else []
    text = sv.f2b_jail_text(ports)
    try:
        with open(jail_file) as handle:
            previous = handle.read()
    except OSError:
        previous = None
    if previous != text:
        os.makedirs(os.path.dirname(jail_file), exist_ok=True)
        with open(jail_file + '.tmp', 'w') as handle:
            handle.write(text)
        os.chmod(jail_file + '.tmp', 0o644)
        os.replace(jail_file + '.tmp', jail_file)
    code, out = _run(['fail2ban-client', '-t'], 60, runner)
    if code != 0:
        if previous is None:
            os.unlink(jail_file)
        else:
            with open(jail_file, 'w') as handle:
                handle.write(previous)
        raise SSHSecError('fail2ban rejected the configuration, change undone: %s' % out.strip()[-300:])
    if state['running']:
        code, out = _run(['fail2ban-client', 'reload'], 60, runner)
    else:
        code, out = _run(['systemctl', 'enable', '--now', 'fail2ban'], 60, runner)
    if code != 0:
        raise SSHSecError('fail2ban did not reload: %s' % out.strip()[-300:])
    return {'changed': previous != text, 'message': 'sshd jail enabled (%s).' % jail_file}


ACTIONS = {
    'overview': overview,
    'analyze': lambda window, client=(): jobs.spawn('sshsec', 'analyze_run', {'window': window,
                                                                              'client': list(client)}),
    'analyze_run': analyze_run,
    'audit': lambda client=(): audit(client),
    'blocklist': lambda: blocklist(),
    'block': lambda target, reason='', client=(), confirm=False, by='': block(target, reason, client, confirm, by),
    'unblock': lambda target: unblock(target),
    'enable_f2b_sshd': lambda: enable_f2b_sshd(),
    'job': lambda job_id: jobs.status(job_id),
}
