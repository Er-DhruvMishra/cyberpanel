"""Root-side Fail2ban ban manager actions (dispatched by universalAddons/runner.py).

fail2ban-client always runs with argv lists, a clean environment, a validated jail name that is in
the live jail list, and a validated address. The only file written is the whitelist drop-in
(service.DROPIN), backed up first, tested with `fail2ban-client -t`, then reloaded.
"""
import glob
import os
import shutil
import subprocess
import time

from universalAddons.bans import service as sv
from universalAddons.bans.service import BansError
from universalAddons.sshsec import actions as ssh_actions
from universalAddons.sshsec import service as ssh

_run = ssh_actions._run   # clean environment (CyberPanel's `firewall` package must not shadow firewalld's)


def _client(*args, timeout=30, runner=subprocess.run):
    return _run(['fail2ban-client'] + list(args), timeout, runner)


def _require_running(runner=subprocess.run):
    if not ssh_actions._which('fail2ban-client'):
        raise BansError('fail2ban is not installed.')
    code, out = _client('status', runner=runner)
    if code != 0:
        raise BansError('fail2ban is not running: %s' % out.strip()[-200:])
    return sv.parse_jails(out)


def _config_texts():
    texts = []
    for pattern in sv.CONFIG_ORDER:
        for path in sorted(glob.glob(pattern)):
            try:
                with open(path) as handle:
                    texts.append(handle.read())
            except OSError:
                pass
    return texts


def _read(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return None


def jails(runner=subprocess.run):
    live = _require_running(runner)
    filters = sv.jail_filters(_config_texts(), live)
    out = []
    for jail in live:
        code, text = _client('status', jail, runner=runner)
        entry = sv.parse_jail_status(text if code == 0 else '')
        code, ignored = _client('get', jail, 'ignoreip', runner=runner)
        entry.update(name=jail, filter=filters.get(jail), ignoreip=sv.parse_ignore(ignored) if code == 0 else [])
        out.append(entry)
    return out


def overview(runner=subprocess.run):
    try:
        listing = jails(runner)
        problem = None
    except BansError as exc:
        listing, problem = [], str(exc)
    try:
        firewall = ssh_actions.blocklist(runner)
    except Exception as exc:  # firewalld missing or not running: still show fail2ban
        firewall = {'entries': [], 'firewall': {'running': False}, 'error': str(exc)[:200]}
    return {'jails': listing, 'problem': problem, 'whitelist': sv.parse_dropin(_read(sv.DROPIN)),
            'dropin': sv.DROPIN, 'firewall': firewall,
            'total_banned': sum(j.get('currently_banned') or 0 for j in listing)}


def search(ip, runner=subprocess.run):
    ip = sv.check_ip(ip)
    data = overview(runner)
    return {'ip': ip,
            'banned_in': [j['name'] for j in data['jails'] if ip in j['banned']],
            'ignored_in': [j['name'] for j in data['jails'] if sv.covers(j['ignoreip'], ip)],
            'whitelisted': sv.covers(data['whitelist'], ip),
            'firewall': [e['target'] for e in data['firewall'].get('entries', []) if sv.covers([e['target']], ip)]}


def unban(jail, ip, runner=subprocess.run):
    jail = sv.check_jail(jail, _require_running(runner))
    ip = sv.check_ip(ip)
    code, out = _client('set', jail, 'unbanip', ip, runner=runner)
    if code != 0:
        raise BansError('fail2ban refused: %s' % out.strip()[-300:])
    return {'jail': jail, 'ip': ip, 'output': out.strip()[-200:]}


def ban(jail, ip, client=(), runner=subprocess.run):
    jail = sv.check_jail(jail, _require_running(runner))
    ip = sv.check_ip(ip)
    network = ssh.parse_target(ip)
    refusals, private = ssh.block_checks(network, client, ssh_actions.server_ips(runner))
    code, ignored = _client('get', jail, 'ignoreip', runner=runner)
    if sv.covers(sv.parse_ignore(ignored), ip):
        refusals.append('%s is on the ignore list of %s.' % (ip, jail))
    if refusals:
        raise BansError(' '.join(refusals))
    code, out = _client('set', jail, 'banip', ip, runner=runner)
    if code != 0:
        raise BansError('fail2ban refused: %s' % out.strip()[-300:])
    return {'jail': jail, 'ip': ip, 'warnings': private}


def _ignored_everywhere(live, runner):
    result = {}
    for jail in live:
        code, out = _client('get', jail, 'ignoreip', runner=runner)
        result[jail] = set(sv.parse_ignore(out)) if code == 0 else None
    return result


def set_whitelist(entries, runner=subprocess.run, dropin=None, backup_dir=None):
    """Rewrite the managed drop-in with `entries`, test, reload; roll back if anything that was
    ignored before is no longer ignored afterwards."""
    dropin, backup_dir = dropin or sv.DROPIN, backup_dir or sv.BACKUP_DIR
    entries = sorted(set(sv.check_entry(e) for e in entries))
    live = _require_running(runner)
    text = sv.render_dropin(entries)
    previous = _read(dropin)
    if previous == text:
        return {'changed': False, 'whitelist': entries}
    before = _ignored_everywhere(live, runner)
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    backup = None
    if previous is not None:
        backup = os.path.join(backup_dir, time.strftime('%Y%m%d-%H%M%S-') + os.path.basename(dropin))
        shutil.copy2(dropin, backup)

    def restore():
        if previous is None:
            if os.path.exists(dropin):
                os.unlink(dropin)
        else:
            with open(dropin + '.tmp', 'w') as handle:
                handle.write(previous)
            os.replace(dropin + '.tmp', dropin)

    with open(dropin + '.tmp', 'w') as handle:
        handle.write(text)
    os.chmod(dropin + '.tmp', 0o644)
    os.replace(dropin + '.tmp', dropin)
    code, out = _client('-t', timeout=60, runner=runner)
    if code != 0:
        restore()
        raise BansError('fail2ban rejected the configuration, change undone: %s' % out.strip()[-300:])
    code, out = _client('reload', timeout=120, runner=runner)
    if code != 0:
        restore()
        _client('reload', timeout=120, runner=runner)
        raise BansError('fail2ban did not reload, change undone: %s' % out.strip()[-300:])
    after = _ignored_everywhere(live, runner)
    lost = {j: sorted(before[j] - (after.get(j) or set())) for j in live if before.get(j) is not None}
    lost = {j: v for j, v in lost.items() if v}
    if lost:
        restore()
        _client('reload', timeout=120, runner=runner)
        raise BansError('After the reload fail2ban no longer ignored %s; the change was undone.' % '; '.join(
            '%s in %s' % (', '.join(v), j) for j, v in sorted(lost.items())))
    return {'changed': True, 'whitelist': entries, 'backup': backup}


def whitelist_add(entry, runner=subprocess.run):
    entry = sv.check_entry(entry)
    current = sv.parse_dropin(_read(sv.DROPIN))
    if entry in current:
        raise BansError('%s is already on the whitelist.' % entry)
    return set_whitelist(current + [entry], runner)


def whitelist_remove(entry, runner=subprocess.run):
    entry = sv.check_entry(entry)
    current = sv.parse_dropin(_read(sv.DROPIN))
    if entry not in current:
        raise BansError('%s is not on the panel whitelist (addresses in jail.local are edited there).' % entry)
    return set_whitelist([e for e in current if e != entry], runner)


ACTIONS = {
    'overview': lambda: overview(),
    'search': lambda ip: search(ip),
    'unban': lambda jail, ip: unban(jail, ip),
    'ban': lambda jail, ip, client=(): ban(jail, ip, client),
    'whitelist_add': lambda entry: whitelist_add(entry),
    'whitelist_remove': lambda entry: whitelist_remove(entry),
}
