"""authorized_keys parsing, validation and fingerprints (pure functions, no subprocess, no root).

The root side (manage.py) also runs `ssh-keygen -l -f` on every key before adding it and checks
that ssh-keygen reports the same SHA256 fingerprint computed here.

Only the type, size, SHA256 fingerprint, comment and options of a key are ever returned to the
browser, never the key text itself.
"""
import base64
import binascii
import hashlib
import re
import struct

from universalAddons.sshsec.service import SSHSecError

PLAIN_TYPES = ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
               'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com', 'ssh-dss')
CERT_TYPES = tuple(t.replace('@openssh.com', '') + '-cert-v01@openssh.com' for t in PLAIN_TYPES)
KEY_TYPES = PLAIN_TYPES + CERT_TYPES
MIN_RSA_BITS = 2048
MAX_LINE = 16 * 1024
MAX_KEYS = 200
_FP_B64 = re.compile(r'^[A-Za-z0-9+/]{43}$')
_COMMENT_RE = re.compile(r'^[A-Za-z0-9@._+-]{0,64}$')

PRIVATE_MARKERS = ('PRIVATE KEY', 'BEGIN OPENSSH', 'PuTTY-User-Key-File', 'b3BlbnNzaC1rZXktdjE',
                   'SSH2 ENCRYPTED PRIVATE KEY', 'Private-Lines:')


def looks_private(text):
    """True for anything that looks like a private key (OpenSSH, PEM, PKCS#8 or PuTTY)."""
    return any(marker in (text or '') for marker in PRIVATE_MARKERS)


def fingerprint(blob):
    """OpenSSH's SHA256 fingerprint of a decoded key blob: 'SHA256:<base64 without padding>'."""
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')


def _strings(blob, count):
    """The first `count` SSH wire-format strings of a blob."""
    out, offset = [], 0
    for _ in range(count):
        if offset + 4 > len(blob):
            raise ValueError('truncated')
        (length,) = struct.unpack('>I', blob[offset:offset + 4])
        offset += 4
        if offset + length > len(blob):
            raise ValueError('truncated')
        out.append(blob[offset:offset + length])
        offset += length
    return out, offset


def _mpint_bits(value):
    return int.from_bytes(value, 'big').bit_length()


def key_bits(key_type, blob):
    """Key size in bits as ssh-keygen -l prints it; raises ValueError on a malformed blob."""
    base = key_type.replace('-cert-v01@openssh.com', '')
    cert = base != key_type
    skip = 2 if cert else 1            # type name, then the nonce for certificates
    if 'ed25519' in base:
        fields, _ = _strings(blob, skip + 1)
        if len(fields[-1]) != 32:
            raise ValueError('bad ed25519 key')
        return 256
    if 'ecdsa' in base:
        fields, _ = _strings(blob, skip + 2)
        curve = fields[skip].decode('ascii', 'replace')
        return {'nistp256': 256, 'nistp384': 384, 'nistp521': 521}[curve]
    if base == 'ssh-rsa':
        fields, _ = _strings(blob, skip + 2)   # e, n
        return _mpint_bits(fields[skip + 1])
    if base == 'ssh-dss':
        fields, _ = _strings(blob, skip + 1)   # p
        return _mpint_bits(fields[skip])
    raise ValueError('unknown type')


def split_options(line):
    """(options text, rest) of an authorized_keys line. Options come first, are separated by
    commas, and may contain spaces only inside double quotes (with \\" escapes)."""
    line = line.strip()
    first = line.split(None, 1)[0] if line else ''
    if first in KEY_TYPES:
        return '', line
    quoted, index = False, 0
    while index < len(line):
        char = line[index]
        if char == '\\' and quoted and index + 1 < len(line):
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        elif char in ' \t' and not quoted:
            break
        index += 1
    if quoted:
        raise ValueError('unbalanced quotes in options')
    return line[:index], line[index:].strip()


def option_list(options):
    """Split an options string on commas outside quotes."""
    items, current, quoted, index = [], '', False, 0
    while index < len(options):
        char = options[index]
        if char == '\\' and quoted and index + 1 < len(options):
            current += options[index:index + 2]
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        if char == ',' and not quoted:
            items.append(current)
            current = ''
        else:
            current += char
        index += 1
    if current:
        items.append(current)
    if any(not item or not re.match(r'^[A-Za-z0-9-]+(=".*")?$', item, re.S) for item in items):
        raise ValueError('malformed options')
    return items


def parse_line(line):
    """A public-key entry of an authorized_keys line, or None for blank/comment lines.
    Raises ValueError for a line that is neither."""
    text = line.strip()
    if not text or text.startswith('#'):
        return None
    if len(text) > MAX_LINE:
        raise ValueError('line too long')
    options, rest = split_options(text)
    fields = rest.split(None, 2)
    if len(fields) < 2 or fields[0] not in KEY_TYPES:
        raise ValueError('not a public key line')
    key_type, data = fields[0], fields[1]
    comment = fields[2].strip() if len(fields) > 2 else ''
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
        raise ValueError('key data is not base64')
    try:
        blob = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('key data is not base64')
    try:
        (embedded,), _ = _strings(blob, 1)
    except ValueError:
        raise ValueError('key data is truncated')
    if embedded.decode('ascii', 'replace') != key_type:
        raise ValueError('key type does not match the key data')
    bits = key_bits(key_type, blob)
    return {'type': key_type, 'bits': bits, 'fingerprint': fingerprint(blob), 'comment': comment[:200],
            'options': option_list(options) if options else [], 'data': data}


def public(entry):
    """What the browser may see about a key: never the key text."""
    return {k: entry[k] for k in ('type', 'bits', 'fingerprint', 'comment', 'options', 'line')
            if k in entry}


def parse_file(text):
    """(entries, problems) of an authorized_keys file. Entries carry their 1-based line number;
    lines that are neither comments nor valid keys are reported, not dropped."""
    entries, problems = [], []
    for number, line in enumerate((text or '').splitlines(), 1):
        try:
            entry = parse_line(line)
        except (ValueError, KeyError) as exc:
            problems.append({'line': number, 'error': str(exc)})
            continue
        if entry is not None:
            entry['line'] = number
            entries.append(entry)
    return entries, problems


def validate_new(text, allow_options=False):
    """Validate one pasted public key; returns its parsed entry. Raises SSHSecError."""
    text = (text or '').strip()
    if looks_private(text):
        raise SSHSecError('This is a PRIVATE key. Never paste a private key into any website: paste the '
                          'public key instead (the one-line contents of the .pub file, starting with ssh-ed25519 '
                          'or ssh-rsa). Treat the private key you pasted as exposed if it left your computer.')
    if 'BEGIN SSH2 PUBLIC KEY' in text:
        raise SSHSecError('This is an RFC 4716 (PuTTY/SSH.com) public key. Convert it to OpenSSH form first: '
                          'ssh-keygen -i -f key.pub, or in PuTTYgen copy "Public key for pasting into OpenSSH".')
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise SSHSecError('Paste exactly one public key (one line).')
    try:
        entry = parse_line(lines[0])
    except (ValueError, KeyError) as exc:
        raise SSHSecError('Not a valid OpenSSH public key (%s).' % exc)
    if entry is None:
        raise SSHSecError('Not a valid OpenSSH public key.')
    if entry['options'] and not allow_options:
        raise SSHSecError('This key line has options in front of it (%s). Options such as command= or from= '
                          'restrict what the key can do; tick "Allow key options" if you mean them.'
                          % ', '.join(o.split('=', 1)[0] for o in entry['options']))
    if entry['type'].startswith('ssh-dss'):
        raise SSHSecError('DSA keys are obsolete and refused by current OpenSSH. Use an ed25519 key.')
    if entry['type'].startswith('ssh-rsa') and entry['bits'] < MIN_RSA_BITS:
        raise SSHSecError('RSA keys shorter than %d bits are too weak.' % MIN_RSA_BITS)
    return entry


def key_line(entry):
    """The authorized_keys line for a validated entry."""
    line = '%s %s' % (entry['type'], entry['data'])
    if entry.get('comment'):
        line += ' ' + entry['comment']
    if entry.get('options'):
        line = ','.join(entry['options']) + ' ' + line
    return line


def without(text, fingerprints):
    """`text` with every key line whose fingerprint is in `fingerprints` removed; other lines
    (comments, unknown lines) are kept byte for byte."""
    fingerprints = set(fingerprints)
    kept = []
    for line in (text or '').splitlines(keepends=True):
        try:
            entry = parse_line(line)
        except (ValueError, KeyError):
            entry = None
        if entry is not None and entry['fingerprint'] in fingerprints:
            continue
        kept.append(line)
    return ''.join(kept)


def with_key(text, entry):
    """`text` with the entry appended (unless the same key is already there)."""
    existing, _ = parse_file(text)
    if any(e['fingerprint'] == entry['fingerprint'] for e in existing):
        return text
    if len(existing) >= MAX_KEYS:
        raise SSHSecError('authorized_keys already holds %d keys.' % MAX_KEYS)
    if text and not text.endswith('\n'):
        text += '\n'
    return (text or '') + key_line(entry) + '\n'


def decode_fingerprint(value):
    """The page sends fingerprints without the 'SHA256:' prefix (the panel's request filter
    rejects colons). Returns 'SHA256:...'."""
    value = str(value or '')
    if value.startswith('SHA256:'):
        value = value[7:]
    if not _FP_B64.match(value):
        raise SSHSecError('Invalid key fingerprint.')
    return 'SHA256:' + value


def validate_comment(text):
    text = str(text or '').strip()
    if not _COMMENT_RE.match(text):
        raise SSHSecError('Key comment: up to 64 letters, digits and @ . _ + - only.')
    return text
