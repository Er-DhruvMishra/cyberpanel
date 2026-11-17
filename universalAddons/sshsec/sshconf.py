"""sshd login settings as a managed block (pure functions, no subprocess, no root).

Where the settings go:
- sshd_config without a global `Include` of sshd_config.d (EL8: OpenSSH 8.0 has no Include): a
  marked block in sshd_config itself, placed before the first directive and therefore before
  any Match block. sshd uses the FIRST value it reads for each keyword, so the block wins over
  the distribution's lines further down.
- sshd_config that includes sshd_config.d/*.conf (Debian/Ubuntu, newer EL): a drop-in
  `00-indianscloud.conf`, read first among the drop-ins.

Lines elsewhere in the global part of sshd_config (before the first Match) that set a keyword the
block manages are commented out with a marker, and restored when the block stops managing that
keyword. That keeps one visible source of truth, and matters for Port, which is cumulative: two
Port lines make sshd listen on both. Lines inside Match blocks are never touched.

Living with CyberPanel's own SSH page (Security > Secure SSH, plogical/sshConfigUtilities.py):
that page rewrites the first non-comment Port / PermitRootLogin line, which is the line in this
block, so a change made there lands in the block and takes effect; this page then shows the
block as "changed outside this page" (the checksum in the BEGIN line no longer matches) and
displays the effective values from `sshd -T`. Neither page rewrites settings it does not own.
"""
import hashlib
import re

from universalAddons.sshsec.service import SSHSecError

BRAND = 'IndiansCloud'
BEGIN = '# BEGIN %s SSH login settings' % BRAND
END = '# END %s SSH login settings' % BRAND
SUPERSEDED = '#[%s superseded] ' % BRAND
DROPIN_NAME = '00-indianscloud.conf'

ROOT_CHOICES = ('yes', 'prohibit-password', 'no')
ROOT_ALIASES = {'without-password': 'prohibit-password'}
LIMITS = {'maxauthtries': (1, 10), 'logingracetime': (10, 600)}
# Ports that this server's other services use; refusing them avoids an sshd that cannot bind.
RESERVED_PORTS = {20, 21, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 7080, 8090, 8888, 1433,
                  6379, 11211, 4190, 11332, 11333, 11334}

# keyword (lower case) -> name as written
NAMES = {'passwordauthentication': 'PasswordAuthentication',
         'kbdinteractiveauthentication': 'KbdInteractiveAuthentication',
         'challengeresponseauthentication': 'ChallengeResponseAuthentication',
         'permitrootlogin': 'PermitRootLogin', 'port': 'Port', 'maxauthtries': 'MaxAuthTries',
         'logingracetime': 'LoginGraceTime'}
_DIRECTIVE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.*?)\s*$')


def _int(value, name, low, high):
    if value in (None, ''):
        return None
    text = str(value).strip()
    if not re.match(r'^\d{1,5}$', text) or not low <= int(text) <= high:
        raise SSHSecError('%s must be a whole number from %d to %d.' % (name, low, high))
    return int(text)


def validate_settings(raw):
    """Normalise the form: {'password': 'yes'|'no', 'root': one of ROOT_CHOICES, 'port': int|None,
    'maxauthtries': int|None, 'logingracetime': int|None}. None means "leave as it is"."""
    raw = raw if isinstance(raw, dict) else {}
    password = raw.get('password')
    if password not in ('yes', 'no'):
        raise SSHSecError('Choose whether password login is allowed.')
    root = ROOT_ALIASES.get(raw.get('root'), raw.get('root'))
    if root not in ROOT_CHOICES:
        raise SSHSecError('Choose how root may log in.')
    port = _int(raw.get('port'), 'SSH port', 1, 65535)
    if port is not None and port in RESERVED_PORTS:
        raise SSHSecError('Port %d belongs to another service on this server (mail, web, panel or database).'
                          % port)
    return {'password': password, 'root': root, 'port': port,
            'maxauthtries': _int(raw.get('maxauthtries'), 'MaxAuthTries', *LIMITS['maxauthtries']),
            'logingracetime': _int(raw.get('logingracetime'), 'LoginGraceTime (seconds)', *LIMITS['logingracetime'])}


def directives(settings, supported=None):
    """[(keyword lower, 'Name value')] for the block. `supported` is the set of keywords that
    `sshd -T` prints on this server: ChallengeResponseAuthentication and KbdInteractiveAuthentication
    are written only where sshd knows them."""
    def known(key):
        return supported is None or key in supported

    out = [('passwordauthentication', 'PasswordAuthentication %s' % settings['password'])]
    if settings['password'] == 'no':
        # Keyboard-interactive (PAM) can ask for the same password, so it goes off with it.
        for key in ('kbdinteractiveauthentication', 'challengeresponseauthentication'):
            if known(key):
                out.append((key, '%s no' % NAMES[key]))
    out.append(('permitrootlogin', 'PermitRootLogin %s' % settings['root']))
    for key in ('port', 'maxauthtries', 'logingracetime'):
        if settings.get(key) is not None:
            out.append((key, '%s %d' % (NAMES[key], settings[key])))
    return out


def checksum(lines):
    return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()[:16]


def block_text(settings, supported=None, newline='\n'):
    lines = [d for _, d in directives(settings, supported)]
    head = '%s (managed by the %s panel, SSH Security page; sum=%s)' % (BEGIN, BRAND, checksum(lines))
    note = '# Change these in the panel. sshd uses the first value it reads, so this block wins.'
    return newline.join([head, note] + lines + [END]) + newline


def split_block(text):
    """(before, block lines or None, after). Raises SSHSecError for a damaged block."""
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith(BEGIN)]
    ends = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == END]
    if not starts and not ends:
        return text, None, ''
    if len(starts) != 1 or len(ends) != 1 or ends[0] < starts[0]:
        raise SSHSecError('The %s block in the SSH configuration is damaged (BEGIN/END markers do not match). '
                          'Fix or remove it by hand first.' % BRAND)
    s, e = starts[0], ends[0]
    return ''.join(lines[:s]), lines[s:e + 1], ''.join(lines[e + 1:])


def read_block(text):
    """What the block currently sets: {'present', 'edited', 'values': {keyword: value}}."""
    try:
        _, block, _ = split_block(text or '')
    except SSHSecError:
        return {'present': True, 'damaged': True, 'edited': True, 'values': {}}
    if block is None:
        return {'present': False, 'edited': False, 'values': {}}
    values, body = {}, []
    for line in block[1:-1]:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        body.append(stripped)
        match = _DIRECTIVE.match(stripped)
        if match:
            values.setdefault(match.group(1).lower(), match.group(2))
    match = re.search(r'sum=([0-9a-f]{16})', block[0])
    return {'present': True, 'edited': not match or match.group(1) != checksum(body), 'values': values}


def _is_match(line):
    match = _DIRECTIVE.match(line)
    return bool(match and match.group(1).lower() == 'match')


def includes_dropins(text):
    """True when sshd_config includes sshd_config.d/*.conf at global level."""
    for line in (text or '').splitlines():
        if _is_match(line):
            return False
        match = _DIRECTIVE.match(line)
        if match and match.group(1).lower() == 'include' and 'sshd_config.d' in match.group(2):
            return True
    return False


def match_blocks(text):
    """Match lines (without the keyword) and what they override among the managed keywords."""
    out, current = [], None
    for line in (text or '').splitlines():
        match = _DIRECTIVE.match(line)
        if not match or line.lstrip().startswith('#'):
            continue
        key = match.group(1).lower()
        if key == 'match':
            current = {'match': match.group(2)[:200], 'sets': []}
            out.append(current)
        elif current is not None and key in NAMES:
            current['sets'].append('%s %s' % (NAMES[key], match.group(2)[:100]))
    return out


def neutralise(text, managed):
    """Comment out global (pre-Match) lines setting a keyword in `managed` with the SUPERSEDED
    marker, and restore earlier-commented lines for keywords no longer managed."""
    out, in_match = [], False
    for line in text.splitlines(keepends=True):
        if not in_match and line.startswith(SUPERSEDED):
            original = line[len(SUPERSEDED):]
            match = _DIRECTIVE.match(original)
            if match and match.group(1).lower() in managed:
                out.append(line)
            else:
                out.append(original)
            continue
        if line.lstrip().startswith('#'):
            out.append(line)
            continue
        if _is_match(line):
            in_match = True
        match = _DIRECTIVE.match(line)
        if not in_match and match and match.group(1).lower() in managed:
            out.append(SUPERSEDED + line)
        else:
            out.append(line)
    return ''.join(out)


def _insert_at(text):
    """Offset of the first directive line (block goes before it, after the header comments)."""
    offset = 0
    for line in text.splitlines(keepends=True):
        if line.strip() and not line.lstrip().startswith('#'):
            return offset
        offset += len(line)
    return len(text)


def render_main(original, settings, supported=None):
    """sshd_config with the block (re)placed before the first directive. Idempotent."""
    newline = '\r\n' if '\r\n' in original else '\n'
    before, block, after = split_block(original)
    rest = before + after if block is not None else original
    managed = {k for k, _ in directives(settings, supported)}
    rest = neutralise(rest, managed)
    at = _insert_at(rest)
    head, tail = rest[:at], rest[at:]
    if head and not head.endswith('\n'):
        head += newline
    return head + block_text(settings, supported, newline) + tail


def strip_main(original):
    """sshd_config without the block, superseded lines restored."""
    before, block, after = split_block(original)
    rest = before + after if block is not None else original
    return neutralise(rest, set())


def render_dropin(settings, supported=None):
    return ('# Written by the %s panel (SSH Security). It is read first among the drop-ins, so its values win.\n'
            % BRAND) + block_text(settings, supported)


def render_main_for_dropin(original, settings, supported=None):
    """In drop-in mode sshd_config itself only gets conflicting global lines commented out."""
    managed = {k for k, _ in directives(settings, supported)}
    before, block, after = split_block(original)
    return neutralise(before + after if block is not None else original, managed)


def keep_unset(settings, block_values):
    """Fill the optional settings left empty (None = leave as it is) from what the block already
    sets, so leaving a field empty never silently drops a value the block manages."""
    out = dict(settings)
    for key in ('port', 'maxauthtries', 'logingracetime'):
        value = (block_values or {}).get(key)
        if out.get(key) is None and value and re.match(r'^\d{1,5}$', value):
            out[key] = int(value)
    return out


def normalise_root(value):
    return ROOT_ALIASES.get(value, value)


def expected(settings):
    """{sshd -T keyword: expected value} after applying `settings`."""
    out = {'passwordauthentication': settings['password'], 'permitrootlogin': settings['root']}
    if settings['password'] == 'no':
        out['kbdinteractiveauthentication'] = 'no'
    if settings.get('port') is not None:
        out['port'] = str(settings['port'])
    if settings.get('maxauthtries') is not None:
        out['maxauthtries'] = str(settings['maxauthtries'])
    if settings.get('logingracetime') is not None:
        out['logingracetime'] = str(settings['logingracetime'])
    return out


def mismatches(effective, settings):
    """['PasswordAuthentication is yes, wanted no', ...] comparing `sshd -T` output to the request."""
    problems = []
    for key, want in expected(settings).items():
        if key == 'kbdinteractiveauthentication' and key not in effective:
            continue  # an sshd that does not know the keyword
        have = effective.get(key, '')
        if key == 'permitrootlogin':
            have = normalise_root(have)
        if key == 'port':
            if have.split() != [want]:
                problems.append('sshd would listen on port(s) %s, wanted only %s' % (have or '?', want))
            continue
        if have != want:
            problems.append('%s is %s, wanted %s' % (NAMES[key], have or '(unset)', want))
    if 'listenaddress' in effective and settings.get('port') is not None:
        ports = {a.rsplit(':', 1)[-1] for a in effective['listenaddress'].split()}
        if ports and ports != {str(settings['port'])}:
            problems.append('a ListenAddress line names its own port (%s)' % ', '.join(sorted(ports)))
    return problems
