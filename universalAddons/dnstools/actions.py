"""Root-side DNS tools actions (dispatched by universalAddons/runner.py).

DNSSEC: pdnsutil with argv lists (zone names validated, and the zone must exist in the panel's
PowerDNS tables; the views check ownership with ACLManager.checkOwnershipZone first). Templates:
the only file written is service.TEMPLATES_FILE.
"""
import json
import os
import subprocess

from universalAddons.dnstools import service as sv
from universalAddons.dnstools.service import DNSToolsError

CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def _run(argv, timeout=60, runner=subprocess.run):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=CLEAN_ENV)
    except FileNotFoundError:
        return 127, '%s is not installed.' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s timed out.' % argv[0]
    return out.returncode, out.stdout or ''


def _conf(path=None):
    try:
        with open(path or sv.PDNS_CONF) as handle:
            return sv.parse_pdns_conf(handle.read())
    except OSError:
        return {}


def _zone(zone):
    zone = sv.check_zone(zone)
    from universalAddons import django_env
    django_env.setup()
    from dns.models import Domains
    if not Domains.objects.filter(name=zone).exists():
        raise DNSToolsError('Unknown zone.')
    return zone


def _pdnsutil(op, zone, runner=subprocess.run):
    code, out = _run(sv.pdnsutil_argv(op, zone), 120, runner)
    if code != 0:
        raise DNSToolsError('pdnsutil %s failed: %s' % (op, out.strip()[-500:]))
    return out


def support(runner=subprocess.run):
    ok, problems, facts = sv.dnssec_support(_conf())
    if not os.path.exists(sv.PDNSUTIL):
        ok, problems = False, problems + ['pdnsutil is not installed.']
    return {'ok': ok, 'problems': problems, 'facts': facts}


def status(zone, runner=subprocess.run):
    zone = _zone(zone)
    state = support(runner)
    if os.path.exists(sv.PDNSUTIL):
        code, out = _run(sv.pdnsutil_argv('show', zone), 60, runner)
        state['zone'] = sv.parse_show_zone(out) if code == 0 else {'secured': False, 'error': out.strip()[-500:]}
    return dict(state, name=zone)


def enable(zone, runner=subprocess.run):
    zone = _zone(zone)
    state = support(runner)
    if not state['ok']:
        raise DNSToolsError(' '.join(state['problems']))
    current = sv.parse_show_zone(_pdnsutil('show', zone, runner))
    log = []
    if not current['secured']:
        log.append(_pdnsutil('secure', zone, runner).strip())
    log.append(_pdnsutil('rectify', zone, runner).strip())
    result = sv.parse_show_zone(_pdnsutil('show', zone, runner))
    if not result['secured'] or not result['ds']:
        raise DNSToolsError('pdnsutil did not report active keys for %s: %s' % (zone, result['raw'][-400:]))
    return {'name': zone, 'zone': result, 'log': [l for l in log if l][-10:]}


def disable(zone, confirm_ds_removed=False, runner=subprocess.run):
    if confirm_ds_removed is not True:
        raise DNSToolsError('Remove the DS record at the registrar first and confirm it, or the domain stops resolving.')
    zone = _zone(zone)
    out = _pdnsutil('disable', zone, runner)
    _pdnsutil('rectify', zone, runner)
    return {'name': zone, 'zone': sv.parse_show_zone(_pdnsutil('show', zone, runner)), 'log': out.strip()[-500:]}


def rectify(zone, runner=subprocess.run):
    zone = _zone(zone)
    return {'name': zone, 'log': _pdnsutil('rectify', zone, runner).strip()[-500:]}


# ----------------------------------------------------------------------------- templates

def save_template(scope, template=None, ipv6=None, path=None):
    """scope 'default' or 'reseller:<admin id>'; template None removes it. ipv6 (admins) sets {ipv6}."""
    path = path or sv.TEMPLATES_FILE
    data = sv.load_templates(path)
    if scope == 'default':
        data['default'] = sv.validate_template(template) if template is not None else None
        if ipv6 is not None:
            data['ipv6'] = sv.check_ipv6(ipv6)
    elif isinstance(scope, str) and scope.startswith('reseller:') and scope[9:].isdigit():
        if template is None:
            data['resellers'].pop(scope[9:], None)
        else:
            data['resellers'][scope[9:]] = sv.validate_template(template)
    else:
        raise DNSToolsError('Unknown template scope.')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + '.tmp', 'w') as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)
    return sv.load_templates(path)


ACTIONS = {
    'support': lambda: support(),
    'status': lambda zone: status(zone),
    'enable': lambda zone: enable(zone),
    'disable': lambda zone, confirm_ds_removed=False: disable(zone, confirm_ds_removed),
    'rectify': lambda zone: rectify(zone),
    'save_template': lambda scope, template=None, ipv6=None: save_template(scope, template, ipv6),
}
