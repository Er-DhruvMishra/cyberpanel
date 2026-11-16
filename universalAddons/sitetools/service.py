"""Site Tools: pure functions (no I/O) for staging, protected directories, redirects, error pages and
hotlink protection. The root side (actions.py) reads and writes files; everything that decides what
is written lives here so it can be tested.

How each feature reaches OpenLiteSpeed
- Redirects and hotlink protection: managed blocks of mod_rewrite rules at the top of the document
  root's .htaccess, the same file the panel's Rewrite Rules page edits (OpenLiteSpeed reads rewrite
  rules from .htaccess natively).
- Protected directories: OpenLiteSpeed ignores AuthType/AuthUserFile in .htaccess, so (like the
  .htaccess translator add-on) a managed vhost.conf block holds one `realm` (htpasswd user DB) and
  one `context` per directory. OpenLiteSpeed's crypt() accepts bcrypt ($2y$) and apr1 ($apr1$).
- Error pages: HTML files in <docroot>/error-pages/ plus a managed vhost.conf block of `errorpage`
  entries.

Every managed block sits between BEGIN/END marker lines; rendering the same settings twice gives
the same text, and empty settings remove the block.
"""
import hashlib
import os
import re
import secrets
from urllib.parse import quote

from universalAddons.siteinfo import DOMAIN_RE, SiteError, check_rel


class SiteToolsError(ValueError):
    pass


# ----------------------------------------------------------------------------- managed blocks

REDIRECTS = ('# BEGIN IndiansCloud redirects (managed by Site Tools; edit them there)',
             '# END IndiansCloud redirects')
HOTLINK = ('# BEGIN IndiansCloud hotlink protection (managed by Site Tools; edit it there)',
           '# END IndiansCloud hotlink protection')
AUTH = ('# BEGIN IndiansCloud protected directories (managed by Site Tools; do not edit)',
        '# END IndiansCloud protected directories')
ERRORS = ('# BEGIN IndiansCloud error pages (managed by Site Tools; do not edit)',
          '# END IndiansCloud error pages')


def _block_re(markers):
    begin, end = markers
    return re.compile(r'(?m)^' + re.escape(begin) + r'[^\n]*\n.*?^' + re.escape(end) + r'[^\n]*(\n|$)', re.S)


def find_block(text, markers):
    """The managed block (with its markers) or ''. A BEGIN without its END is refused."""
    text = text or ''
    match = _block_re(markers).search(text)
    if match:
        return match.group(0)
    if re.search(r'(?m)^' + re.escape(markers[0]), text):
        raise SiteToolsError('The managed block "%s" has no END line; fix the file by hand first.' % markers[0][2:40])
    return ''


def strip_block(text, markers):
    """Text without the managed block (and without the blank line that separated it)."""
    text = text or ''
    find_block(text, markers)
    out = _block_re(markers).sub('', text, count=1)
    return out


def render_block(markers, lines):
    return '\n'.join([markers[0]] + list(lines) + [markers[1]]) + '\n'


def set_htaccess_block(text, markers, lines):
    """Put the block at the top of a .htaccess (replacing it in place if present); no lines = remove."""
    text = text or ''
    current = find_block(text, markers)
    if not lines:
        return strip_block(text, markers)
    block = render_block(markers, lines)
    if current:
        return text.replace(current, block, 1)
    return block + ('\n' + text if text.strip() else '')


def set_vhost_block(text, markers, body):
    """Put the block into vhost.conf before `vhssl` (the panel keeps SSL last); empty body = remove."""
    text = text or ''
    current = find_block(text, markers)
    if not body:
        out = strip_block(text, markers)
        return re.sub(r'\n{3,}', '\n\n', out)
    block = '\n'.join([markers[0], body.rstrip('\n'), markers[1]]) + '\n'
    if current:
        return text.replace(current, block, 1)
    base = text.rstrip('\n') + '\n'
    match = re.search(r'(?m)^vhssl\s*\{', base)
    if match:
        out = base[:match.start()] + block + '\n' + base[match.start():]
    else:
        out = base + '\n' + block
    return re.sub(r'\n{3,}', '\n\n', out)


def braces_balanced(text):
    depth = 0
    in_heredoc = None
    for line in (text or '').splitlines():
        stripped = line.strip()
        if in_heredoc:
            if stripped == in_heredoc:
                in_heredoc = None
            continue
        heredoc = re.search(r'<<<(\w+)\s*$', stripped)
        if heredoc:
            in_heredoc = heredoc.group(1)
            continue
        if stripped.startswith('#'):
            continue
        depth += stripped.count('{') - stripped.count('}')
        if depth < 0:
            return False
    return depth == 0 and in_heredoc is None


def outside_block(text, markers):
    return strip_block(text or '', markers)


# ----------------------------------------------------------------------------- paths

def safe_dir(docroot, rel, lstat=os.lstat):
    """Absolute path of directory `rel` inside docroot; refuses '..', links and non-directories.

    Every component (the document root included) is checked with lstat, so a symbolic link
    anywhere on the way - to /etc, or to another site - is refused, not followed.
    """
    import stat
    rel = check_rel(rel)
    docroot = os.path.normpath(docroot)
    path = docroot
    for part in [docroot] + (rel.split('/') if rel else []):
        path = part if part == docroot else os.path.join(path, part)
        try:
            info = lstat(path)
        except FileNotFoundError:
            raise SiteToolsError('/%s does not exist.' % rel)
        if stat.S_ISLNK(info.st_mode):
            raise SiteToolsError('/%s goes through a symbolic link; choose the real directory.' % rel)
        if not stat.S_ISDIR(info.st_mode):
            raise SiteToolsError('/%s is not a directory.' % rel)
    if path != docroot and not path.startswith(docroot + '/'):
        raise SiteToolsError('That directory is outside the document root.')
    return path


def norm_rel(value):
    """A directory picked in the form ('/private/', 'private', '') -> validated relative path."""
    value = str(value if value is not None else '').strip().strip('/')
    try:
        return check_rel(value)
    except SiteError as exc:
        raise SiteToolsError(str(exc))


# ----------------------------------------------------------------------------- redirects

URL_CHARS = r"A-Za-z0-9._~%!$&'()*+,;=:@/-"
PATH_RE = re.compile(r'^/[%s]{0,300}$' % URL_CHARS)
TARGET_RE = re.compile(r'^(/[%s?#]{0,500}|https?://[A-Za-z0-9.-]{1,253}(:\d{1,5})?(/[%s?#]{0,500})?)$'
                       % (URL_CHARS, URL_CHARS))
REGEX_FORBIDDEN = re.compile(r'[\s\x00-\x1f\x7f"]')
MAX_REDIRECTS = 200


def validate_regex(pattern):
    """A RewriteRule pattern: no whitespace or quotes (they would split the rule), and it must compile."""
    pattern = str(pattern or '')
    if not pattern or len(pattern) > 300:
        raise SiteToolsError('Enter a regular expression of up to 300 characters.')
    if REGEX_FORBIDDEN.search(pattern):
        raise SiteToolsError('The regular expression may not contain spaces, quotes or control characters '
                             '(use \\s for a space).')
    if '%{' in pattern:
        raise SiteToolsError('Server variables are not allowed in the pattern.')
    try:
        re.compile(pattern)
    except re.error as exc:
        raise SiteToolsError('Invalid regular expression: %s.' % exc)
    if pattern.startswith('^/'):
        pattern = '^' + pattern[2:]   # .htaccess rules see the path without its leading slash
    return pattern


def validate_redirect(rule):
    if not isinstance(rule, dict):
        raise SiteToolsError('Invalid redirect.')
    code = str(rule.get('code', '301'))
    kind = rule.get('kind', 'path')
    source = str(rule.get('source', '')).strip()
    target = str(rule.get('target', '')).strip()
    if code not in ('301', '302'):
        raise SiteToolsError('Choose 301 (permanent) or 302 (temporary).')
    if kind == 'path':
        if not PATH_RE.match(source):
            raise SiteToolsError('The source must be a path that starts with / (no spaces, ? or #): %r.' % source[:80])
    elif kind == 'regex':
        source = validate_regex(source)
    else:
        raise SiteToolsError('Choose a path or a regular expression.')
    if not TARGET_RE.match(target):
        raise SiteToolsError('The target must be a path starting with / or an http(s):// URL, without spaces: %r.'
                             % target[:80])
    if kind == 'path' and target.split('?', 1)[0].split('#', 1)[0] == source:
        raise SiteToolsError('%s would redirect to itself.' % source)
    return {'code': code, 'kind': kind, 'source': source, 'target': target}


def validate_redirects(rules):
    if not isinstance(rules, list) or len(rules) > MAX_REDIRECTS:
        raise SiteToolsError('Send up to %d redirects.' % MAX_REDIRECTS)
    clean, seen = [], set()
    for rule in rules:
        item = validate_redirect(rule)
        key = (item['kind'], item['source'])
        if key in seen:
            raise SiteToolsError('%s is listed twice.' % item['source'])
        seen.add(key)
        clean.append(item)
    return clean


def _rx_escape(path):
    return re.sub(r'([.^$*+?()\[\]{}|\\])', r'\\\1', path)


def redirect_lines(rules):
    if not rules:
        return []
    lines = ['RewriteEngine On']
    for rule in rules:
        if rule['kind'] == 'path':
            pattern = '^' + _rx_escape(rule['source'][1:]) + '$'
        else:
            pattern = rule['source']
        target = rule['target'].replace(' ', '%20')
        lines.append('RewriteRule %s %s [R=%s,L]' % (pattern, target, rule['code']))
    return lines


# ----------------------------------------------------------------------------- hotlink protection

EXT_RE = re.compile(r'^[a-z0-9]{1,10}$')
DEFAULT_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'mp4', 'webm', 'mp3']


def validate_hotlink(config, site_domain):
    if not isinstance(config, dict):
        raise SiteToolsError('Invalid hotlink settings.')
    enabled = config.get('enabled') is True
    domains = []
    for value in config.get('domains') or []:
        value = str(value).strip().lower()
        if value.startswith('www.'):
            value = value[4:]
        if not value:
            continue
        if not DOMAIN_RE.match(value):
            raise SiteToolsError('Invalid referrer domain %r.' % value[:80])
        if value not in domains and value != site_domain:
            domains.append(value)
    if len(domains) > 50:
        raise SiteToolsError('List up to 50 allowed domains.')
    extensions = []
    for value in config.get('extensions') or []:
        value = str(value).strip().lower().lstrip('.')
        if not value:
            continue
        if not EXT_RE.match(value):
            raise SiteToolsError('Invalid file extension %r.' % value[:20])
        if value not in extensions:
            extensions.append(value)
    if enabled and not extensions:
        raise SiteToolsError('List at least one protected file extension.')
    redirect = str(config.get('redirect') or '').strip()
    if redirect and not TARGET_RE.match(redirect):
        raise SiteToolsError('The replacement image must be a path starting with / or an http(s):// URL.')
    return {'enabled': enabled, 'domains': domains, 'extensions': extensions[:40],
            'allow_empty': config.get('allow_empty', True) is not False, 'redirect': redirect}


def _referer_cond(domain):
    return 'RewriteCond %%{HTTP_REFERER} !^https?://([^/]+\\.)?%s(:[0-9]+)?(/|$) [NC]' % _rx_escape(domain)


def hotlink_lines(config, site_domain):
    if not config or not config.get('enabled'):
        return []
    base = site_domain[4:] if site_domain.startswith('www.') else site_domain
    lines = ['RewriteEngine On']
    if config.get('allow_empty', True):
        lines.append('RewriteCond %{HTTP_REFERER} !^$')
    for domain in [base] + [d for d in config.get('domains', []) if d != base]:
        lines.append(_referer_cond(domain))
    redirect = config.get('redirect') or ''
    if redirect.startswith('/'):
        lines.append('RewriteCond %%{REQUEST_URI} !^%s$' % _rx_escape(redirect.split('?', 1)[0]))
    pattern = '\\.(%s)$' % '|'.join(config['extensions'])
    if redirect:
        lines.append('RewriteRule %s %s [NC,R=302,L]' % (pattern, redirect))
    else:
        lines.append('RewriteRule %s - [NC,F,L]' % pattern)
    return lines


# ----------------------------------------------------------------------------- error pages

ERROR_CODES = ('403', '404', '500', '502', '503')
ERROR_DIR = 'error-pages'
MAX_PAGE_BYTES = 256 * 1024
TITLES = {'403': 'Access denied', '404': 'Page not found', '500': 'Something went wrong',
          '502': 'Bad gateway', '503': 'Temporarily unavailable'}


def validate_code(code):
    code = str(code)
    if code not in ERROR_CODES:
        raise SiteToolsError('Choose one of %s.' % ', '.join(ERROR_CODES))
    return code


def validate_page(html):
    if not isinstance(html, str) or not html.strip():
        raise SiteToolsError('The page is empty.')
    if '\x00' in html or len(html.encode('utf-8')) > MAX_PAGE_BYTES:
        raise SiteToolsError('The page must be text of at most %d KB.' % (MAX_PAGE_BYTES // 1024))
    return html


def default_page(code):
    title = TITLES[validate_code(code)]
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>%s %s</title>\n'
            '<style>body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;margin:0;align-items:center;'
            'justify-content:center;background:#f8fafc;color:#1e293b}main{text-align:center;padding:24px}'
            'h1{font-size:64px;margin:0}p{color:#64748b}</style>\n</head>\n<body>\n<main>\n<h1>%s</h1>\n'
            '<p>%s</p>\n<p><a href="/">Back to the home page</a></p>\n</main>\n</body>\n</html>\n'
            % (code, title, code, title))


def page_url(code):
    return '/%s/%s.html' % (ERROR_DIR, validate_code(code))


def errorpage_body(codes):
    parts = []
    for code in sorted(set(codes)):
        parts.append('errorpage %s {\n  url                     %s\n}' % (validate_code(code), page_url(code)))
    return '\n\n'.join(parts)


def errorpage_conflicts(vhost_text, codes):
    """Codes that vhost.conf already defines outside our block (by hand or by the .htaccess add-on)."""
    text = outside_block(vhost_text, ERRORS)
    return [c for c in codes if re.search(r'(?m)^\s*errorpage\s+%s\b' % c, text)]


# ----------------------------------------------------------------------------- protected directories

HT_USER_RE = re.compile(r'^[A-Za-z0-9._@-]{1,64}$')
AUTH_NAME_RE = re.compile(r'^[A-Za-z0-9 ._,()-]{1,60}$')
SCHEMES = ('bcrypt', 'apr1')
_APR_ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def validate_ht_user(user):
    user = str(user or '').strip()
    if not HT_USER_RE.match(user):
        raise SiteToolsError('User names: 1-64 letters, digits, . _ @ - (no spaces or colons).')
    return user


def validate_password(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 128 or re.search(r'[\x00-\x1f\x7f]', password):
        raise SiteToolsError('Passwords need 8-128 characters (no control characters).')
    return password


def validate_auth_name(name):
    name = str(name or 'Restricted area').strip()
    if not AUTH_NAME_RE.match(name):
        raise SiteToolsError('The prompt text may use letters, digits, spaces and . _ , ( ) - (up to 60).')
    return name


def _to64(value, length):
    out = ''
    for _ in range(length):
        out += _APR_ALPHABET[value & 0x3f]
        value >>= 6
    return out


def apr1_crypt(password, salt=None):
    """Apache's MD5-based $apr1$ hash (the htpasswd -m format)."""
    if salt is None:
        salt = ''.join(secrets.choice(_APR_ALPHABET) for _ in range(8))
    salt = salt[:8]
    pw = password.encode('utf-8')
    magic = b'$apr1$'
    sb = salt.encode('ascii')
    ctx = hashlib.md5(pw + magic + sb)
    final = hashlib.md5(pw + sb + pw).digest()
    length = len(pw)
    while length > 0:
        ctx.update(final[:min(16, length)])
        length -= 16
    i = len(pw)
    while i:
        ctx.update(b'\x00' if i & 1 else pw[:1])
        i >>= 1
    final = ctx.digest()
    for i in range(1000):
        step = hashlib.md5()
        step.update(pw if i & 1 else final)
        if i % 3:
            step.update(sb)
        if i % 7:
            step.update(pw)
        step.update(final if i & 1 else pw)
        final = step.digest()
    out = ''
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        out += _to64((final[a] << 16) | (final[b] << 8) | final[c], 4)
    out += _to64(final[11], 2)
    return '$apr1$%s$%s' % (salt, out)


def hash_password(password, scheme='bcrypt'):
    validate_password(password)
    if scheme == 'apr1':
        return apr1_crypt(password)
    if scheme != 'bcrypt':
        raise SiteToolsError('Choose bcrypt or apr1.')
    import bcrypt
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=10)).decode('ascii')
    # Same algorithm; $2y$ is the prefix every crypt_blowfish build (and htpasswd -B) understands.
    return '$2y$' + hashed[4:]


def verify_password(password, hashed):
    if hashed.startswith('$apr1$'):
        return secrets.compare_digest(apr1_crypt(password, hashed.split('$')[2]), hashed)
    if hashed.startswith(('$2y$', '$2a$', '$2b$')):
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), ('$2b$' + hashed[4:]).encode('ascii'))
    return False


def parse_htpasswd(text):
    entries = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or ':' not in line:
            continue
        user, hashed = line.split(':', 1)
        if HT_USER_RE.match(user):
            entries.append((user, hashed.split(':', 1)[0]))
    return entries


def render_htpasswd(entries):
    return ''.join('%s:%s\n' % (user, hashed) for user, hashed in entries)


def set_ht_user(entries, user, hashed):
    user = validate_ht_user(user)
    if not re.match(r'^\$(apr1|2[aby])\$[./0-9A-Za-z$]{20,80}$', hashed):
        raise SiteToolsError('Unexpected password hash.')
    out = [(u, h) for u, h in entries if u != user]
    position = next((i for i, (u, _) in enumerate(entries) if u == user), len(out))
    out.insert(position, (user, hashed))
    return out


def remove_ht_user(entries, user):
    return [(u, h) for u, h in entries if u != user]


def realm_name(domain, rel):
    return 'ic_auth_' + hashlib.sha1(('%s\0%s' % (domain, rel)).encode()).hexdigest()[:12]


def htpasswd_path(home, realm):
    """Outside the document root (never served), in the site's home like the panel's own password files."""
    return os.path.join(home, '.ic-htpasswd-' + realm)


def auth_body(entries, docroot):
    """realm + context blocks for each protected directory. entries: [{path, realm, userfile, name}]."""
    parts = []
    for entry in sorted(entries, key=lambda e: e['path']):
        parts.append('realm %s {\n  userDB  {\n    location              %s\n  }\n}' % (entry['realm'], entry['userfile']))
    for entry in sorted(entries, key=lambda e: e['path']):
        uri = '/' + entry['path'] + '/' if entry['path'] else '/'
        location = os.path.join(docroot, entry['path']).rstrip('/') + '/'
        parts.append('\n'.join([
            'context %s {' % uri,
            '  location                %s' % location,
            '  allowBrowse             1',
            '  realm                   %s' % entry['realm'],
            '  authName                %s' % validate_auth_name(entry.get('name')),
            '  required                valid-user',
            '  rewrite  {',
            '    enable                  1',
            '    autoLoadHtaccess        1',
            '  }',
            '}']))
    return '\n\n'.join(parts)


def auth_conflicts(vhost_text, rel):
    """A `context <uri>` for this directory that vhost.conf defines outside our block."""
    uri = '/' + rel + '/' if rel else '/'
    text = outside_block(vhost_text, AUTH)
    pattern = r'(?m)^\s*context\s+%s\s*\{' % re.escape(uri)
    if rel:
        pattern = r'(?m)^\s*context\s+%s/?\s*\{' % re.escape('/' + rel)
    return bool(re.search(pattern, text))


# ----------------------------------------------------------------------------- serialized-aware replace

class _Unparsable(Exception):
    pass


def _parse(data, pos, depth):
    if depth > 256:
        raise _Unparsable()
    kind = data[pos:pos + 1]
    if kind == b'N':
        if data[pos + 1:pos + 2] != b';':
            raise _Unparsable()
        return ('N', b'N;'), pos + 2
    if kind in (b'b', b'i', b'd', b'r', b'R'):
        if data[pos + 1:pos + 2] != b':':
            raise _Unparsable()
        end = data.find(b';', pos + 2)
        if end < 0:
            raise _Unparsable()
        raw = data[pos:end + 1]
        if not re.match(rb'^[bidrR]:[-+0-9.eEINFAN]+;$', raw):
            raise _Unparsable()
        return ('raw', raw), end + 1
    if kind == b's':
        match = re.compile(rb's:(\d+):"').match(data, pos)
        if not match:
            raise _Unparsable()
        length = int(match.group(1))
        start = match.end()
        if data[start + length:start + length + 2] != b'";':
            raise _Unparsable()
        return ('s', data[start:start + length]), start + length + 2
    if kind == b'a':
        match = re.compile(rb'a:(\d+):\{').match(data, pos)
        if not match:
            raise _Unparsable()
        items, pos = _parse_items(data, match.end(), int(match.group(1)), depth)
        return ('a', items), pos
    if kind == b'O':
        match = re.compile(rb'O:(\d+):"').match(data, pos)
        if not match:
            raise _Unparsable()
        start = match.end()
        name = data[start:start + int(match.group(1))]
        rest = re.compile(rb'":(\d+):\{').match(data, start + len(name))
        if not rest:
            raise _Unparsable()
        items, pos = _parse_items(data, rest.end(), int(rest.group(1)), depth)
        return ('O', name, items), pos
    if kind in (b'C', b'E'):
        # Custom-serialized objects and enums: their payload is opaque, so it is kept as it is.
        if kind == b'E':
            match = re.compile(rb'E:(\d+):"').match(data, pos)
            if not match:
                raise _Unparsable()
            end = match.end() + int(match.group(1))
            if data[end:end + 2] != b'";':
                raise _Unparsable()
            return ('raw', data[pos:end + 2]), end + 2
        match = re.compile(rb'C:(\d+):"').match(data, pos)
        if not match:
            raise _Unparsable()
        start = match.end() + int(match.group(1))
        rest = re.compile(rb'":(\d+):\{').match(data, start)
        if not rest:
            raise _Unparsable()
        end = rest.end() + int(rest.group(1))
        if data[end:end + 1] != b'}':
            raise _Unparsable()
        return ('raw', data[pos:end + 1]), end + 1
    raise _Unparsable()


def _parse_items(data, pos, count, depth):
    items = []
    for _ in range(count):
        key, pos = _parse(data, pos, depth + 1)
        if key[0] not in ('s', 'raw') or (key[0] == 'raw' and not key[1].startswith(b'i:')):
            raise _Unparsable()
        value, pos = _parse(data, pos, depth + 1)
        items.append((key, value))
    if data[pos:pos + 1] != b'}':
        raise _Unparsable()
    return items, pos + 1


def unserialize_tree(data):
    """Parse PHP serialize() output into a tree, or None if `data` is not exactly one serialized value."""
    if not isinstance(data, bytes) or not re.match(rb'^(N;|[bidsaOCE]:)', data):
        return None
    try:
        tree, end = _parse(data, 0, 0)
    except (_Unparsable, ValueError, IndexError):
        return None
    return tree if end == len(data) else None


def serialize_tree(node):
    kind = node[0]
    if kind in ('N', 'raw'):
        return node[1]
    if kind == 's':
        return b's:%d:"%s";' % (len(node[1]), node[1])
    if kind == 'a':
        return b'a:%d:{%s}' % (len(node[1]), b''.join(serialize_tree(k) + serialize_tree(v) for k, v in node[1]))
    if kind == 'O':
        return b'O:%d:"%s":%d:{%s}' % (len(node[1]), node[1], len(node[2]),
                                       b''.join(serialize_tree(k) + serialize_tree(v) for k, v in node[2]))
    raise ValueError(kind)


def _replace_tree(node, pairs, depth):
    kind = node[0]
    if kind == 's':
        return ('s', replace_value(node[1], pairs, depth + 1))
    if kind == 'a':
        return ('a', [(k, _replace_tree(v, pairs, depth)) for k, v in node[1]])
    if kind == 'O':
        return ('O', node[1], [(k, _replace_tree(v, pairs, depth)) for k, v in node[2]])
    return node


def replace_value(value, pairs, depth=0):
    """Replace each (old, new) bytes pair in a value. PHP-serialized values are parsed, replaced
    inside their strings (serialized data nested in strings included) and re-serialized with
    correct byte lengths; anything else gets a plain replace (what WP-CLI search-replace does)."""
    if not any(old in value for old, _ in pairs):
        return value
    tree = unserialize_tree(value) if depth < 8 else None
    if tree is not None:
        return serialize_tree(_replace_tree(tree, pairs, depth))
    for old, new in pairs:
        value = value.replace(old, new)
    return value


def url_pairs(old_domain, new_domain):
    """Byte pairs that move URLs of old_domain to new_domain, keeping the scheme (no https downgrade).

    Covers http(s)://, protocol-relative //, www., and JSON-escaped https:\\/\\/ forms.
    """
    pairs = []
    for prefix in (b'://www.', b'://', b':\\/\\/www.', b':\\/\\/'):
        pairs.append((prefix + old_domain.encode(), prefix.replace(b'www.', b'') + new_domain.encode()))
    return pairs


# ----------------------------------------------------------------------------- SQL dumps

_SQL_LITERAL = re.compile(rb"'((?:[^'\\]|\\.|'')*)'", re.S)
_UNESCAPE = {b'0': b'\x00', b'n': b'\n', b'r': b'\r', b'Z': b'\x1a', b't': b'\t', b'b': b'\x08'}


def sql_unescape(raw):
    out, i = bytearray(), 0
    while i < len(raw):
        char = raw[i:i + 1]
        if char == b'\\' and i + 1 < len(raw):
            nxt = raw[i + 1:i + 2]
            out += _UNESCAPE.get(nxt, nxt)
            i += 2
        elif char == b"'" and raw[i + 1:i + 2] == b"'":
            out += b"'"
            i += 2
        else:
            out += char
            i += 1
    return bytes(out)


def sql_escape(value):
    """mysql_real_escape_string, as mysqldump writes string literals."""
    return (value.replace(b'\\', b'\\\\').replace(b'\x00', b'\\0').replace(b'\n', b'\\n').replace(b'\r', b'\\r')
            .replace(b"'", b"\\'").replace(b'"', b'\\"').replace(b'\x1a', b'\\Z'))


def transform_dump_line(line, pairs):
    """Search-replace inside the string literals of one mysqldump INSERT line (serialized-aware).

    mysqldump writes each extended INSERT on one line (newlines in values are escaped), so a dump
    can be streamed line by line; other lines pass through unchanged.
    """
    if not line.startswith(b'INSERT INTO ') or not any(old.replace(b'\\', b'\\\\') in line or old in line
                                                       for old, _ in pairs):
        return line

    def one(match):
        raw = match.group(1)
        value = sql_unescape(raw)
        new = replace_value(value, pairs)
        return match.group(0) if new == value else b"'" + sql_escape(new) + b"'"
    return _SQL_LITERAL.sub(one, line)


# ----------------------------------------------------------------------------- config rewrite

ENV_LINE = re.compile(r'^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*?)(\s*)$')


def _env_value(raw):
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in '"\'':
        return raw[1:-1]
    return raw.split(' #', 1)[0].strip()


def _env_quote(value):
    if re.match(r'^[A-Za-z0-9_./:@+-]*$', value):
        return value
    return '"%s"' % value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')


def _replace_text(text, pairs):
    data = text.encode('utf-8', 'surrogateescape')
    for old, new in pairs:
        data = data.replace(old, new)
    return data.decode('utf-8', 'surrogateescape')


def rewrite_env(text, db_map, old_domain, new_domain):
    """Point a .env (Laravel, Symfony, generic DB_*) at the copied databases and the new URL.

    db_map: {old_db_name: {'name', 'user', 'password'}}. Only a .env whose database is one of the
    copied ones gets new credentials; *_URL values move to the new domain.
    Returns (new text, [changed keys]).
    """
    lines = (text or '').split('\n')
    values = {}
    for line in lines:
        match = ENV_LINE.match(line)
        if match and not match.group(1).lstrip().startswith('#'):
            values[match.group(2)] = _env_value(match.group(4))
    target = None
    for key in ('DB_DATABASE', 'DB_NAME', 'DATABASE_NAME', 'MYSQL_DATABASE'):
        if values.get(key) in db_map:
            target = db_map[values[key]]
            break
    url_match = re.match(r'^(mysql|mariadb|mysqli|pdo-mysql)://([^:@/]*)(:[^@/]*)?@([^/]+)/([^?]+)(\?.*)?$',
                         values.get('DATABASE_URL', ''))
    if target is None and url_match and url_match.group(5) in db_map:
        target = db_map[url_match.group(5)]
    pairs = url_pairs(old_domain, new_domain)
    changed, out = [], []
    for line in lines:
        match = ENV_LINE.match(line)
        if not match:
            out.append(line)
            continue
        lead, key, eq, raw, tail = match.groups()
        new = None
        if target:
            if key in ('DB_DATABASE', 'DB_NAME', 'DATABASE_NAME', 'MYSQL_DATABASE'):
                new = target['name']
            elif key in ('DB_USERNAME', 'DB_USER', 'DATABASE_USER', 'MYSQL_USER'):
                new = target['user']
            elif key in ('DB_PASSWORD', 'DB_PASS', 'DATABASE_PASSWORD', 'MYSQL_PASSWORD'):
                new = target['password']
            elif key == 'DATABASE_URL' and url_match:
                new = '%s://%s:%s@%s/%s%s' % (url_match.group(1), quote(target['user'], safe=''),
                                              quote(target['password'], safe=''), url_match.group(4), target['name'],
                                              url_match.group(6) or '')
        if new is None and (key.endswith('_URL') or key in ('APP_DOMAIN', 'SESSION_DOMAIN', 'SANCTUM_STATEFUL_DOMAINS')):
            value = _env_value(raw)
            moved = _replace_text(value, pairs)
            if key in ('APP_DOMAIN', 'SESSION_DOMAIN', 'SANCTUM_STATEFUL_DOMAINS'):
                hold = '\x00new\x00'   # leave values that already name the new domain as they are
                moved = re.sub(r'(^|[,.\s])%s(?=$|[,:\s])' % re.escape(old_domain),
                               lambda m: m.group(1) + new_domain, value.replace(new_domain, hold))
                moved = moved.replace(hold, new_domain)
            if moved != value:
                new = moved
        if new is None or new == _env_value(raw):
            out.append(line)
            continue
        changed.append(key)
        out.append('%s%s%s%s%s' % (lead, key, eq, _env_quote(new), tail))
    return '\n'.join(out), changed


_DEFINE = r"""(define\(\s*['"]%s['"]\s*,\s*)(['"])((?:\\.|(?!\2).)*)\2"""


def _php_quote(value):
    return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"


def _define_value(text, name):
    match = re.search(_DEFINE % re.escape(name), text)
    if not match:
        return None
    return re.sub(r'\\(.)', r'\1', match.group(3))


def rewrite_wp_config(text, db_map, old_domain, new_domain):
    """Point a wp-config.php at the copied database and move WP_HOME / WP_SITEURL. Returns (text, keys)."""
    changed = []
    current = _define_value(text, 'DB_NAME')
    target = db_map.get(current) if current is not None else None

    def put(text, name, value):
        pattern = re.compile(_DEFINE % re.escape(name))
        if not pattern.search(text):
            return text
        new_text = pattern.sub(lambda m: m.group(1) + _php_quote(value), text, count=1)
        if new_text != text:
            changed.append(name)
        return new_text
    if target:
        text = put(text, 'DB_NAME', target['name'])
        text = put(text, 'DB_USER', target['user'])
        text = put(text, 'DB_PASSWORD', target['password'])
    pairs = url_pairs(old_domain, new_domain)
    for name in ('WP_HOME', 'WP_SITEURL', 'WP_CONTENT_URL', 'WP_PLUGIN_URL', 'DOMAIN_CURRENT_SITE'):
        value = _define_value(text, name)
        if value is None:
            continue
        moved = new_domain if name == 'DOMAIN_CURRENT_SITE' and value == old_domain else _replace_text(value, pairs)
        if moved != value:
            text = put(text, name, moved)
    return text, changed


def config_db_names(files):
    """Database names a site's config files use. files: {relpath: text}."""
    names = []
    for rel, text in files.items():
        name = None
        if rel.endswith('wp-config.php'):
            name = _define_value(text, 'DB_NAME')
        else:
            for line in text.split('\n'):
                match = ENV_LINE.match(line)
                if match and match.group(2) in ('DB_DATABASE', 'DB_NAME', 'DATABASE_NAME', 'MYSQL_DATABASE'):
                    name = _env_value(match.group(4))
                    break
            if not name:
                url = re.search(r'(?m)^DATABASE_URL\s*=\s*["\']?\w+://[^@\s]*@[^/\s]+/([A-Za-z0-9_]+)', text)
                name = url.group(1) if url else None
        if name and name not in names:
            names.append(name)
    return names


CONFIG_NAMES = ('.env', 'wp-config.php')
SKIP_DIRS = {'vendor', 'node_modules', '.git', 'cache', 'storage', 'wp-content', 'wp-includes', 'wp-admin',
             '.cp-wp-snapshots', 'error-pages'}


def find_config_files(docroot, max_depth=3, walk=os.walk):
    """Relative paths of .env / wp-config.php files in the document root (bounded, links not followed)."""
    found = []
    base = docroot.rstrip('/').count('/')
    for current, dirs, names in walk(docroot):
        depth = current.rstrip('/').count('/') - base
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(current, d)))
        if depth >= max_depth:
            dirs[:] = []
        for name in CONFIG_NAMES:
            if name in names and not os.path.islink(os.path.join(current, name)):
                rel = os.path.relpath(os.path.join(current, name), docroot)
                found.append(rel)
        if len(found) >= 40:
            break
    return sorted(found)


def rewrite_config(rel, text, db_map, old_domain, new_domain):
    if os.path.basename(rel) == 'wp-config.php':
        return rewrite_wp_config(text, db_map, old_domain, new_domain)
    return rewrite_env(text, db_map, old_domain, new_domain)


# ----------------------------------------------------------------------------- staging copies

LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$')
# rsync patterns: a leading / anchors a pattern at the document root; without it, it matches anywhere.
CACHE_EXCLUDES = ['/wp-content/cache/', '/wp-content/litespeed/', '/storage/framework/cache/',
                  '/storage/framework/views/', '/var/cache/', '/cache/', '/tmp/cache/', '/.cache/']
UPLOAD_EXCLUDES = ['/wp-content/uploads/', '/storage/app/public/', '/public/uploads/', '/uploads/', '/media/']
# Never pushed over the live site: its own credentials and server files stay as they are.
ALWAYS_PUSH_EXCLUDES = ['.env', 'wp-config.php', '.user.ini', '/.well-known/']
EXCLUDE_RE = re.compile(r'^/?[A-Za-z0-9._*-][A-Za-z0-9._*/-]{0,119}$')


def staging_domain(source_domain, label='staging'):
    label = str(label or 'staging').strip().lower()
    if not LABEL_RE.match(label):
        raise SiteToolsError('The subdomain may use lower-case letters, digits and hyphens.')
    domain = '%s.%s' % (label, source_domain)
    if not DOMAIN_RE.match(domain):
        raise SiteToolsError('%s is not a valid domain name.' % domain)
    return domain


def excludes(exclude_cache=True, exclude_uploads=False, extra=None, push=False):
    items = []
    if push:
        items += ALWAYS_PUSH_EXCLUDES
    if exclude_cache:
        items += CACHE_EXCLUDES
    if exclude_uploads:
        items += UPLOAD_EXCLUDES
    for value in extra or []:
        value = str(value).strip()
        if not value:
            continue
        if not EXCLUDE_RE.match(value) or '..' in value.split('/'):
            raise SiteToolsError('Invalid exclude pattern %r (letters, digits, . _ * / - only).' % value[:60])
        items.append(value)
    out = []
    for item in items:
        if item not in out:
            out.append(item)
    return out[:60]


def nested(a, b):
    a, b = os.path.normpath(a), os.path.normpath(b)
    return a == b or a.startswith(b + '/') or b.startswith(a + '/')


EMPTY_OK = {'index.html', '.htaccess', '.well-known', 'cgi-bin', 'error-pages', '.user.ini'}


def looks_empty(names):
    return not [n for n in names if n not in EMPTY_OK]


def tar_excludes(patterns):
    """The same excludes for tar (-C <docroot> ... .): anchored ones become ./path."""
    out = []
    for item in patterns:
        item = item.rstrip('/')
        out.append('--exclude=' + ('./' + item.lstrip('/') if item.startswith('/') else item))
    return out
