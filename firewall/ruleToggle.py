"""Enable/disable for panel firewall rules, live firewalld status and lock-out protection.

A panel rule (firewall.FirewallRules) is applied as two firewalld rich rules in zone public,
one IPv4 (with the rule's source address) and one IPv6 (no source), exactly as
FirewallUtilities.addRule has always done. Disabling a rule removes both rich rules and keeps
the FirewallRules row; the enabled flag and the time it was disabled are stored in
universalAddons.FirewallRuleState (the firewall app has no migration files, see that model).

Nothing here runs a shell command directly: firewall-cmd goes through ProcessUtilities (lscpd
as root), and every value placed in a command is validated by FirewallUtilities first.
"""
import ipaddress
import re
import shlex

from django.utils import timezone

from plogical.firewallUtilities import FirewallUtilities
from plogical.processUtilities import ProcessUtilities

PANEL_PORT_FILE = '/usr/local/lscp/conf/bind.conf'
SSHD_CONFIG = '/etc/ssh/sshd_config'
DEFAULT_PANEL_PORT = 8090
DEFAULT_SSH_PORT = 22
MAX_BULK = 500
ACTIONS = ('enable', 'disable', 'reapply')

STATUS_ACTIVE = 'active'
STATUS_DISABLED = 'disabled'
STATUS_MISSING = 'missing'
STATUS_UNKNOWN = 'unknown'


class RuleError(ValueError):
    """A request that cannot be carried out; the message is safe to show to the admin."""


# ---------------------------------------------------------------- live state parsing

def _norm_source(value):
    try:
        return str(ipaddress.ip_network(str(value), strict=False))
    except ValueError:
        return None


def parse_rich_rule(line):
    """Parse one `firewall-cmd --list-rich-rules` line into (family, source, port, proto).

    Only plain "allow a port" rules of the shape the panel creates are recognised:
    rule family=F [source address=A] port port=P protocol=T accept
    Anything else (drop/reject, services, logging, limits, NOT, ipset, ...) returns None, as
    does a line that cannot be tokenised. source is normalised (None when absent).
    """
    try:
        tokens = shlex.split(line.strip())
    except ValueError:
        return None
    if len(tokens) < 2 or tokens[0] != 'rule' or tokens[-1] != 'accept':
        return None
    family = source = port = proto = None
    body = tokens[1:-1]
    i = 0
    while i < len(body):
        tok = body[i]
        if tok.startswith('family=') and family is None:
            family = tok[len('family='):]
            i += 1
        elif tok == 'source' and source is None and i + 1 < len(body) and body[i + 1].startswith('address='):
            source = _norm_source(body[i + 1][len('address='):])
            if source is None:
                return None
            i += 2
        elif (tok == 'port' and port is None and i + 2 < len(body)
              and body[i + 1].startswith('port=') and body[i + 2].startswith('protocol=')):
            port = body[i + 1][len('port='):]
            proto = body[i + 2][len('protocol='):].lower()
            i += 3
        else:
            return None
    if family not in ('ipv4', 'ipv6') or port is None or not re.match(r'^[0-9]{1,5}(-[0-9]{1,5})?$', port):
        return None
    return family, source, port, proto


def parse_rich_rules(text):
    found = set()
    for line in (text or '').splitlines():
        parsed = parse_rich_rule(line)
        if parsed:
            found.add(parsed)
    return found


def parse_ports(text):
    """Parse `firewall-cmd --list-ports` ("80/tcp 3000-3010/udp ...") into {(port, proto)}."""
    found = set()
    for item in (text or '').split():
        m = re.match(r'^([0-9]{1,5}(?:-[0-9]{1,5})?)/([a-z]+)$', item.strip())
        if m:
            found.add((m.group(1), m.group(2)))
    return found


def _run_output(command):
    """Run a read-only command through the root runner; returns its output or None on failure."""
    try:
        result = ProcessUtilities.outputExecutioner(command, retRequired=True)
    except BaseException:
        return None
    if isinstance(result, tuple) and len(result) == 2:
        ok, output = result
        return output if ok == 1 else None
    return None


def read_live_state():
    """One read of zone public: {'rich': set, 'ports': set}, or None when firewalld is unavailable."""
    rich = _run_output('firewall-cmd --zone=public --list-rich-rules')
    if rich is None or 'not running' in rich.lower():
        return None
    ports = _run_output('firewall-cmd --zone=public --list-ports')
    return {'rich': parse_rich_rules(rich), 'ports': parse_ports(ports or '')}


def expected_keys(rule):
    """The two parsed rich rules a panel rule should produce, or None if the row is invalid."""
    if FirewallUtilities.richRuleTexts(rule.proto, rule.port, rule.ipAddress) is None:
        return None
    return {
        'ipv4': ('ipv4', _norm_source(rule.ipAddress), rule.port, rule.proto.lower()),
        'ipv6': ('ipv6', None, rule.port, rule.proto.lower()),
    }


def live_status(rule, enabled, live):
    """(status, details) for one rule against a read_live_state() result."""
    if live is None:
        return STATUS_UNKNOWN, {'missing': [], 'note': 'Live firewall state is unavailable.'}
    keys = expected_keys(rule)
    via_ports = (rule.port, rule.proto.lower()) in live['ports'] and _norm_source(rule.ipAddress) == '0.0.0.0/0'
    if keys is None:
        present, missing = [], ['ipv4', 'ipv6']
    else:
        present = [fam for fam, key in keys.items() if key in live['rich']]
        missing = [fam for fam in ('ipv4', 'ipv6') if fam not in present]
    if not enabled:
        note = ''
        if present or via_ports:
            note = 'Disabled in the panel, but firewalld still allows this port.'
        return STATUS_DISABLED, {'missing': [], 'note': note}
    if not missing:
        return STATUS_ACTIVE, {'missing': [], 'note': ''}
    if via_ports:
        return STATUS_ACTIVE, {'missing': missing, 'note': 'Open through the zone port list.'}
    return STATUS_MISSING, {'missing': missing, 'note': 'Not found in firewalld: ' + ', '.join(missing) + '.'}


# ---------------------------------------------------------------- lock-out protection

def _read_text(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            return handle.read()
    except (OSError, IOError):
        return None


def panel_ports():
    ports = {DEFAULT_PANEL_PORT}
    text = _read_text(PANEL_PORT_FILE) or ''
    for m in re.finditer(r':([0-9]{1,5})\b', text):
        ports.add(int(m.group(1)))
    return ports


def ssh_ports():
    ports = {DEFAULT_SSH_PORT}
    text = _read_text(SSHD_CONFIG)
    if text is None:
        text = _run_output('cat ' + SSHD_CONFIG) or ''
    for line in text.splitlines():
        m = re.match(r'^\s*Port\s+([0-9]{1,5})\s*(#.*)?$', line, re.IGNORECASE)
        if m:
            ports.add(int(m.group(1)))
    return ports


def protected_ports():
    """{port: 'panel'|'SSH'} for the ports whose removal could lock the admin out."""
    result = {}
    for p in ssh_ports():
        result[p] = 'SSH'
    for p in panel_ports():
        result[p] = 'panel'
    return result


def rule_protection(rule, protected):
    """The label ('panel'/'SSH') when a tcp rule covers a protected port, else ''."""
    if (rule.proto or '').lower() != 'tcp':
        return ''
    m = re.match(r'^([0-9]{1,5})(?:-([0-9]{1,5}))?$', str(rule.port))
    if not m:
        return ''
    low = int(m.group(1))
    high = int(m.group(2) or low)
    for port in sorted(protected):
        if low <= port <= high:
            return protected[port]
    return ''


# ---------------------------------------------------------------- state store

def _state_model():
    from universalAddons.models import FirewallRuleState
    return FirewallRuleState


def states_for(ids):
    return {s.rule_id: s for s in _state_model().objects.filter(rule_id__in=list(ids))}


def is_enabled(state):
    return state is None or state.enabled


def _mark(rule_id, enabled):
    model = _state_model()
    state, _ = model.objects.get_or_create(rule_id=rule_id)
    state.enabled = enabled
    state.disabled_at = None if enabled else timezone.now()
    state.save()
    return state


def forget(rule_id):
    _state_model().objects.filter(rule_id=rule_id).delete()


# ---------------------------------------------------------------- validation

def clean_rule_id(value):
    if isinstance(value, bool) or value is None:
        raise RuleError('Invalid rule id.')
    if isinstance(value, str):
        if not re.match(r'^[0-9]{1,10}$', value):
            raise RuleError('Invalid rule id.')
        value = int(value)
    if not isinstance(value, int) or value < 1 or value > 2 ** 31 - 1:
        raise RuleError('Invalid rule id.')
    return value


def clean_rule_ids(values):
    if not isinstance(values, list) or not values:
        raise RuleError('Select at least one rule.')
    if len(values) > MAX_BULK:
        raise RuleError('Too many rules in one request.')
    ids = []
    for value in values:
        rid = clean_rule_id(value)
        if rid not in ids:
            ids.append(rid)
    return ids


def load_rules(ids):
    from firewall.models import FirewallRules
    rules = {r.id: r for r in FirewallRules.objects.filter(id__in=ids)}
    unknown = [rid for rid in ids if rid not in rules]
    if unknown:
        raise RuleError('Unknown rule id: %s.' % ', '.join(str(r) for r in unknown))
    return [rules[rid] for rid in ids]


# ---------------------------------------------------------------- listing

def describe_rules(rules):
    """Rows for the rules table: the rule, its panel state, live status and protection."""
    rules = list(rules)
    states = states_for(r.id for r in rules)
    live = read_live_state()
    protected = protected_ports()
    rows = []
    for rule in rules:
        state = states.get(rule.id)
        enabled = is_enabled(state)
        status, details = live_status(rule, enabled, live)
        rows.append({
            'id': rule.id,
            'name': rule.name,
            'proto': rule.proto,
            'port': rule.port,
            'ipAddress': rule.ipAddress,
            'enabled': 1 if enabled else 0,
            'disabledAt': state.disabled_at.isoformat() if (state and state.disabled_at and not enabled) else '',
            'status': status,
            'missingFamilies': details['missing'],
            'statusNote': details['note'],
            'protected': rule_protection(rule, protected),
        })
    return rows, live is not None, protected


# ---------------------------------------------------------------- actions

def lockout_conflicts(rules):
    protected = protected_ports()
    return [{'id': r.id, 'name': r.name, 'port': r.port, 'protects': rule_protection(r, protected)}
            for r in rules if rule_protection(r, protected)]


def change_rules(ids, action, confirm_lockout=False):
    """Enable, disable or re-apply rules; firewall-cmd --reload runs once at the end.

    Returns {'needsConfirm': [...]} when a disable would touch a protected port without
    confirm_lockout, else {'results': [...], 'reloaded': bool}.
    """
    if action not in ACTIONS:
        raise RuleError('Unknown action.')
    rules = load_rules(clean_rule_ids(ids))
    if action == 'disable' and confirm_lockout is not True:
        conflicts = lockout_conflicts(rules)
        if conflicts:
            return {'needsConfirm': conflicts}

    states = states_for(r.id for r in rules)
    results = []
    ran_any = False
    for rule in rules:
        enabled = is_enabled(states.get(rule.id))
        if action == 'disable' and not enabled:
            results.append({'id': rule.id, 'ok': 1, 'message': 'Already disabled.'})
            continue
        if action == 'enable' and enabled:
            results.append({'id': rule.id, 'ok': 1, 'message': 'Already enabled.'})
            continue
        if action == 'reapply' and not enabled:
            results.append({'id': rule.id, 'ok': 0, 'message': 'Rule is disabled; enable it instead.'})
            continue
        op = 'remove' if action == 'disable' else 'add'
        ok, ran = FirewallUtilities.applyRichRules(op, rule.proto, rule.port, rule.ipAddress, reload=False)
        ran_any = ran_any or ran
        if not ran:
            results.append({'id': rule.id, 'ok': 0, 'message': 'Rule has an invalid protocol, port or IP address.'})
            continue
        if ok != 1:
            results.append({'id': rule.id, 'ok': 0, 'message': 'firewall-cmd reported an error; nothing was marked.'})
            continue
        if action == 'disable':
            _mark(rule.id, False)
        elif action == 'enable':
            _mark(rule.id, True)
        results.append({'id': rule.id, 'ok': 1, 'message': {'disable': 'Disabled.', 'enable': 'Enabled.',
                                                            'reapply': 'Re-applied.'}[action]})
    if ran_any:
        ProcessUtilities.executioner('firewall-cmd --reload')
    return {'results': results, 'reloaded': ran_any}


def delete_rule(rule_id, confirm_lockout=False):
    """Delete a rule permanently. Uses the stored rule (never client-supplied values).

    Returns {'needsConfirm': [...]} for a protected rule without confirm_lockout, else
    {'deleted': id}. A disabled rule has no rich rules left, so firewalld is not touched.
    """
    rule_id = clean_rule_id(rule_id)
    rule = load_rules([rule_id])[0]
    if confirm_lockout is not True:
        conflicts = lockout_conflicts([rule])
        if conflicts:
            return {'needsConfirm': conflicts}
    state = states_for([rule.id]).get(rule.id)
    if is_enabled(state):
        FirewallUtilities.deleteRule(rule.proto, rule.port, rule.ipAddress)
    rule.delete()
    forget(rule_id)
    return {'deleted': rule_id}
