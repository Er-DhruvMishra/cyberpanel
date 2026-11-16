#!/usr/bin/env python3
"""IndiansCloud AI Scanner - local pre-filter and secret redaction.

This module is standard-library only on purpose: the panel runs it as the
site's own Linux user (``sudo -u <site user> python -I prefilter.py --root
<docroot>``) so a scan can only ever read what the site owner can read.

It walks the docroot without following symlinks, applies cheap signature and
heuristic checks with no network access, and prints JSON describing the
suspicious files.  Snippets in that JSON are already redacted (DB passwords,
API keys, tokens, private keys, e-mail addresses), and configuration files
such as wp-config.php are reduced to their structure (every string literal
blanked) before anything leaves this process.
"""
import argparse
import json
import os
import re
import stat
import sys
import time

VERSION = 1

# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------
MAX_FILES = 60000            # files examined per scan
MAX_FILE_BYTES = 2 * 1024 * 1024
IMAGE_HEAD_BYTES = 64 * 1024
MAX_CANDIDATES = 300
MAX_HITS_PER_FILE = 12
SNIPPET_CONTEXT = 6          # lines either side of a hit
SNIPPET_MAX_LINES = 120
SNIPPET_MAX_CHARS = 6000
LINE_MAX_CHARS = 400
LONG_LITERAL_KEEP = 120      # long string literals are cut to this many chars
RECENT_SECONDS = 7 * 86400

SKIP_DIRS = {'.git', '.svn', '.hg', 'node_modules'}
PHP_EXT = {'.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.php8', '.pht', '.phar', '.inc'}
JS_EXT = {'.js', '.mjs'}
HTML_EXT = {'.html', '.htm'}
IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.ico', '.bmp', '.webp', '.svg'}
SPECIAL_NAMES = {'.htaccess', '.user.ini', 'php.ini'}

# Files whose content is configuration: never sent as-is, only their structure.
CONFIG_NAMES = {
    'wp-config.php', 'wp-config-sample.php', 'configuration.php', 'settings.php', 'local.xml',
    'env.php', 'config.php', 'config.inc.php', 'database.php', 'db.php', 'parameters.yml',
    'parameters.yaml', 'secrets.php', 'credentials.php', 'local.php', 'app.php', '.env',
}

SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')
SEV_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

_I = re.I

# (rule id, severity, applies-to, compiled regex, reason, suggested action)
# applies-to: 'php', 'js', 'html', 'htaccess', 'any'
_RAW_SIGNATURES = [
    ('php_eval_decode', 'critical', 'php',
     r'\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|hex2bin|convert_uudecode)\s*\(',
     'eval/assert of decoded data (classic obfuscated backdoor)', 'Quarantine the file and compare it with a clean copy.'),
    ('php_eval_input', 'critical', 'php',
     r'\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b',
     'eval/assert of request input (remote code execution)', 'Remove the file or the injected code immediately.'),
    ('php_exec_input', 'critical', 'php',
     r'\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b',
     'shell command built from request input', 'Remove the file or the injected code immediately.'),
    ('php_dynamic_call_input', 'critical', 'php',
     r'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(',
     'function name taken from request input', 'Remove the file or the injected code immediately.'),
    ('php_decode_chain', 'high', 'php',
     r'\b(?:gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*(?:@\s*)?(?:base64_decode|str_rot13|gzinflate)\s*\(',
     'nested decode chain (payload obfuscation)', 'Review the decoded payload; quarantine if it is not part of a known plugin.'),
    ('php_preg_e', 'high', 'php',
     r'preg_replace\s*\(\s*([\'"])(.).{0,200}?\2[imsxuADSUXJ]*e[imsxuADSUXJ]*\1',
     'preg_replace with the /e modifier (code execution)', 'Replace or remove the code.'),
    ('php_write_input', 'high', 'php',
     r'\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,200}\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b',
     'writes request input to a file (uploader/dropper)', 'Check whether this is legitimate upload code; quarantine if not.'),
    ('php_create_function', 'medium', 'php', r'\bcreate_function\s*\(',
     'create_function (deprecated, common in obfuscated code)', 'Review the code.'),
    ('php_long_base64', 'medium', 'php', r'[A-Za-z0-9+/]{400,}={0,2}',
     'very long base64-like blob', 'Review the decoded content.'),
    ('php_hex_escapes', 'medium', 'php', r'(?:\\x[0-9a-fA-F]{2}){24,}',
     'long hex-escaped string (obfuscation)', 'Review the decoded content.'),
    ('php_chr_chain', 'medium', 'php', r'(?:chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){8,}',
     'long chr() concatenation (obfuscation)', 'Review the decoded content.'),
    ('php_globals_call', 'medium', 'php', r'\$GLOBALS\s*\[\s*[\'"][^\'"]{1,40}[\'"]\s*\]\s*\[\s*\d+\s*\]\s*\(',
     'call through obfuscated $GLOBALS table', 'Review the code.'),
    ('webshell_marker', 'critical', 'any',
     r'(?:FilesMan|c99shell|r57shell|b374k|IndoXploit|WSO\s+[0-9.]+|AnonymousFox|Alfa[\s_-]?Shell|Mini\s+Shell|uname\s*-a.{0,40}passthru|wso_version)',
     'known web shell marker', 'Remove the file and rotate site passwords.'),
    ('js_eval_decode', 'high', 'js',
     r'\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(',
     'JavaScript eval of decoded data', 'Compare with the original library; remove injected code.'),
    ('js_function_atob', 'high', 'js', r'\bnew\s+Function\s*\(\s*atob\s*\(',
     'new Function(atob(...)) loader', 'Compare with the original library; remove injected code.'),
    ('js_document_write_unescape', 'high', 'js', r'document\.write\s*\(\s*unescape\s*\(',
     'document.write(unescape(...)) injection', 'Remove injected code.'),
    ('js_fromcharcode_chain', 'medium', 'js', r'String\.fromCharCode\s*\(\s*(?:\d{1,3}\s*,\s*){40,}',
     'long String.fromCharCode payload', 'Review the decoded content.'),
    ('js_atob_blob', 'medium', 'js', r'\batob\s*\(\s*[\'"][A-Za-z0-9+/=]{300,}',
     'large atob() payload', 'Review the decoded content.'),
    ('html_hidden_script_php', 'high', 'html', r'<\?php',
     'PHP code inside an HTML file', 'Check why an HTML file contains PHP.'),
    ('htaccess_prepend', 'high', 'htaccess', r'\b(?:auto_prepend_file|auto_append_file)\b',
     'auto_prepend/append_file directive (loads code into every request)', 'Remove the directive unless you added it.'),
    ('htaccess_image_handler', 'high', 'htaccess',
     r'(?:AddHandler|AddType|SetHandler)[^\n]{0,80}(?:php|x-httpd)[^\n]{0,80}\.(?:jpe?g|png|gif|ico|txt)\b',
     'image or text extension handled as PHP', 'Remove the directive.'),
    ('htaccess_seo_redirect', 'medium', 'htaccess',
     r'RewriteCond\s+%\{HTTP_(?:REFERER|USER_AGENT)\}[^\n]{0,120}(?:google|bing|yahoo|baidu|yandex)',
     'search-engine conditional redirect (SEO spam pattern)', 'Review the rewrite rules.'),
]

SIGNATURES = [(rid, sev, kind, re.compile(rx, _I), reason, action)
              for rid, sev, kind, rx, reason, action in _RAW_SIGNATURES]

SHELL_NAME = re.compile(r'^(?:r57|c99|c100|wso\d*|b374k|alfa\w*|marijuana|indoxploit|shell\d*|cmd|up|uploader|bypass)\.php\d?$', _I)

# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------
REDACTED = '[REDACTED]'
_SECRET_WORD = r'(?:PASS|PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|AUTH|SALT|PRIVATE|CREDENTIAL|DSN|DATABASE_URL|DB_USER|DB_NAME|DB_HOST|NONCE|KEY)'

_REDACTIONS = [
    # -----BEGIN ... PRIVATE KEY----- blocks
    (re.compile(r'-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END[A-Z0-9 ]*PRIVATE KEY-----|\Z)', re.S), '[REDACTED PRIVATE KEY]'),
    # define('DB_PASSWORD', '...') and friends (WordPress keys and salts too)
    (re.compile(r'(define\s*\(\s*([\'"])[A-Z0-9_]*' + _SECRET_WORD + r'[A-Z0-9_]*\2\s*,\s*)([\'"])(?:\\.|(?!\3).)*\3', re.I | re.S),
     r'\1"' + REDACTED + '"'),
    # $db_password = '...';  $apiKey = "...";
    (re.compile(r'(\$(?:[A-Za-z_][A-Za-z0-9_]*)?(?:pass|pwd|secret|token|api_?key|apikey|auth|salt|private|credential)[A-Za-z0-9_]*\s*=\s*)([\'"])(?:\\.|(?!\2).)*\2', re.I | re.S),
     r'\1"' + REDACTED + '"'),
    # 'password' => '...',  "api_key": "..."
    (re.compile(r'(([\'"])[A-Za-z0-9_.-]*(?:pass|pwd|secret|token|api_?key|apikey|auth|salt|private|credential|username|user)[A-Za-z0-9_.-]*\2\s*(?:=>|:)\s*)([\'"])(?:\\.|(?!\3).)*\3', re.I | re.S),
     r'\1"' + REDACTED + '"'),
    # .env style lines: DB_PASSWORD=..., export API_KEY=...
    (re.compile(r'^(\s*(?:export\s+)?[A-Za-z][A-Za-z0-9_]*' + _SECRET_WORD + r'[A-Za-z0-9_]*\s*=\s*).+$', re.I | re.M),
     r'\1' + REDACTED),
    # connection calls: mysqli_connect('h','u','p'), new PDO('dsn','u','p')
    (re.compile(r'((?:mysqli?_connect|mysqli_real_connect|new\s+mysqli|new\s+PDO|pg_connect)\s*\()([^;]{0,400}?)(\))', re.I),
     lambda m: m.group(1) + _blank_literals(m.group(2)) + m.group(3)),
    # URLs with credentials: scheme://user:pass@host
    (re.compile(r'\b([a-z][a-z0-9+.-]{1,15}://)[^\s/@\'"]{1,200}:[^\s/@\'"]{1,200}@', re.I), r'\1' + REDACTED + '@'),
    # Well-known token formats
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), REDACTED),
    (re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), REDACTED),
    (re.compile(r'\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b'), REDACTED),
    (re.compile(r'\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b'), REDACTED),
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b'), REDACTED),
    (re.compile(r'\bgsk_[A-Za-z0-9]{20,}\b'), REDACTED),
    (re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,}\b'), REDACTED),
    (re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+'), REDACTED),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'), REDACTED),
    (re.compile(r'(\bBearer\s+)[A-Za-z0-9._~+/=-]{20,}', re.I), r'\1' + REDACTED),
    # e-mail addresses (personal data)
    (re.compile(r'\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b'), '[EMAIL]'),
]

_LITERAL = re.compile(r'([\'"])(?:\\.|(?!\1).){0,2000}?\1', re.S)
_LONG_LITERAL = re.compile(r'([\'"])((?:\\.|(?!\1).){%d,})\1' % (LONG_LITERAL_KEEP + 80), re.S)


def _keep_lines(original, replacement):
    """Pad a replacement with newlines so later line numbers stay correct."""
    missing = original.count('\n') - replacement.count('\n')
    return replacement + '\n' * missing if missing > 0 else replacement


def _blank_literals(text, placeholder='"' + REDACTED + '"'):
    return _LITERAL.sub(lambda m: _keep_lines(m.group(0), placeholder), text)


def redact(text):
    """Return (redacted text, number of redactions).  Line count is preserved."""
    if not text:
        return text or '', 0
    total = 0
    for pattern, repl in _REDACTIONS:
        if callable(repl):
            func = lambda m, f=repl: _keep_lines(m.group(0), f(m))
        else:
            func = lambda m, r=repl: _keep_lines(m.group(0), m.expand(r))
        text, count = pattern.subn(func, text)
        total += count
    return text, total


def shorten_long_literals(text):
    def _cut(match):
        quote, body = match.group(1), match.group(2)
        cut = '%s%s...[+%d chars]%s' % (quote, body[:LONG_LITERAL_KEEP], len(body) - LONG_LITERAL_KEEP, quote)
        return _keep_lines(match.group(0), cut.replace('\n', ' '))
    return _LONG_LITERAL.sub(_cut, text)


def config_structure(text, max_lines=200):
    """Structure of a configuration file: code kept, every string literal blanked."""
    lines = text.splitlines()[:max_lines]
    blanked = _blank_literals('\n'.join(lines), '"..."')
    blanked, _ = redact(blanked)
    return blanked


def is_config_file(name):
    lower = name.lower()
    return lower in CONFIG_NAMES or lower.startswith('.env') or lower.startswith('wp-config')


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def file_kind(name):
    lower = name.lower()
    if lower in SPECIAL_NAMES:
        return 'htaccess'
    ext = os.path.splitext(lower)[1]
    if ext in PHP_EXT or lower.endswith('.php.suspected'):
        return 'php'
    if ext in JS_EXT:
        return 'js'
    if ext in HTML_EXT:
        return 'html'
    if ext in IMAGE_EXT:
        return 'image'
    return None


def _line_of(text, index):
    return text.count('\n', 0, index) + 1


def scan_content(rel_path, text, kind, mtime=None, now=None):
    """Signature + heuristic hits for one file's text.  Pure function."""
    hits = []
    now = time.time() if now is None else now
    name = os.path.basename(rel_path)
    lower_path = '/' + rel_path.lower()

    if kind == 'image':
        if re.search(r'<\?php|<\?=|\beval\s*\(', text[:IMAGE_HEAD_BYTES], _I):
            hits.append(('php_in_image', 'high', 1, 'PHP code hidden in an image file', 'Delete the file; images never contain PHP.'))
        return hits

    for rid, sev, applies, rx, reason, action in SIGNATURES:
        if applies not in ('any', kind):
            continue
        match = rx.search(text)
        if match:
            hits.append((rid, sev, _line_of(text, match.start()), reason, action))
            if len(hits) >= MAX_HITS_PER_FILE:
                break

    if kind == 'php':
        recent = mtime is not None and (now - mtime) < RECENT_SECONDS
        if '/uploads/' in lower_path or '/wp-content/upgrade/' in lower_path:
            reason = 'PHP file inside an uploads directory'
            if recent:
                reason += ' (modified in the last 7 days)'
            hits.append(('php_in_uploads', 'high', 1, reason, 'Uploads should hold media only; delete or quarantine.'))
        if SHELL_NAME.match(name):
            hits.append(('shell_filename', 'high', 1, 'file name commonly used by web shells', 'Inspect and delete if unknown.'))
        if name.startswith('.') and name.lower().endswith('.php'):
            hits.append(('hidden_php', 'medium', 1, 'hidden PHP file', 'Inspect and delete if unknown.'))
        longest = max((len(line) for line in text.splitlines()), default=0)
        if longest > 5000 and not name.lower().endswith('.min.php'):
            hits.append(('php_long_line', 'medium', 1, 'extremely long line (%d chars), typical of packed code' % longest, 'Review the code.'))
    return hits


def max_severity(hits):
    best = 'info'
    for hit in hits:
        if SEV_RANK.get(hit[1], 0) > SEV_RANK[best]:
            best = hit[1]
    return best


def build_snippet(text, hits, config=False):
    """Redacted excerpt around the hits, with 'NNN| ' line prefixes."""
    if config:
        body = config_structure(text)
        lines = body.splitlines()
        out = ['%d| %s' % (i + 1, line[:LINE_MAX_CHARS]) for i, line in enumerate(lines)]
        return '\n'.join(out)[:SNIPPET_MAX_CHARS], 0

    redacted, count = redact(text)
    redacted = shorten_long_literals(redacted)
    lines = redacted.splitlines()
    wanted = set()
    for hit in hits:
        line = max(1, int(hit[2]))
        for n in range(max(1, line - SNIPPET_CONTEXT), min(len(lines), line + SNIPPET_CONTEXT) + 1):
            wanted.add(n)
    if not wanted:
        wanted = set(range(1, min(len(lines), 20) + 1))
    out, previous, chars = [], None, 0
    for n in sorted(wanted)[:SNIPPET_MAX_LINES]:
        if previous is not None and n != previous + 1:
            out.append('...')
        line = lines[n - 1]
        if len(line) > LINE_MAX_CHARS:
            line = line[:LINE_MAX_CHARS] + '...[+%d chars]' % (len(line) - LINE_MAX_CHARS)
        entry = '%d| %s' % (n, line)
        if chars + len(entry) > SNIPPET_MAX_CHARS:
            out.append('...[snippet truncated]')
            break
        out.append(entry)
        chars += len(entry) + 1
        previous = n
    return '\n'.join(out), count


def _read_regular_file(path, limit):
    """Read a regular file without following a symlink; returns (bytes, stat) or (None, reason)."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return None, 'unreadable (%s)' % (exc.strerror or 'error')
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, 'not a regular file'
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = handle.read(limit)
        return data, info
    finally:
        os.close(fd)


def scan_tree(root, max_files=MAX_FILES, max_candidates=MAX_CANDIDATES, now=None):
    """Walk ``root`` (a docroot) and return the pre-filter report as a dict."""
    now = time.time() if now is None else now
    report = {'version': VERSION, 'root': root, 'files_scanned': 0, 'files_seen': 0,
              'candidates': [], 'skipped': {'symlinks': 0, 'too_large': 0, 'unreadable': 0, 'outside_root': 0,
                                            'limit': 0, 'hardlinked': 0}, 'truncated': False}
    real_root = os.path.realpath(root)
    if not os.path.isdir(real_root) or os.path.islink(root):
        report['error'] = 'Document root is not a directory.'
        return report
    prefix = real_root.rstrip(os.sep) + os.sep
    candidates = []

    for dirpath, dirnames, filenames in os.walk(real_root, followlinks=False):
        # never descend into symlinked or skipped directories
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if d in SKIP_DIRS:
                continue
            if os.path.islink(full):
                report['skipped']['symlinks'] += 1
                continue
            keep.append(d)
        dirnames[:] = sorted(keep)

        for name in sorted(filenames):
            kind = file_kind(name)
            if kind is None:
                continue
            report['files_seen'] += 1
            if report['files_scanned'] >= max_files:
                report['skipped']['limit'] += 1
                report['truncated'] = True
                continue
            full = os.path.join(dirpath, name)
            try:
                info = os.lstat(full)
            except OSError:
                report['skipped']['unreadable'] += 1
                continue
            if stat.S_ISLNK(info.st_mode):
                report['skipped']['symlinks'] += 1
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            real = os.path.realpath(full)
            if not real.startswith(prefix):
                report['skipped']['outside_root'] += 1
                continue
            if kind != 'image' and info.st_size > MAX_FILE_BYTES:
                report['skipped']['too_large'] += 1
                continue
            data, meta = _read_regular_file(full, IMAGE_HEAD_BYTES if kind == 'image' else MAX_FILE_BYTES)
            if data is None:
                report['skipped']['unreadable'] += 1
                continue
            report['files_scanned'] += 1
            text = data.decode('utf-8', errors='replace')
            rel = os.path.relpath(real, real_root).replace(os.sep, '/')
            hits = scan_content(rel, text, kind, mtime=meta.st_mtime, now=now)
            if not hits:
                continue
            config = is_config_file(name)
            send_ai = meta.st_nlink <= 1 and kind != 'image'
            if meta.st_nlink > 1:
                report['skipped']['hardlinked'] += 1
            snippet, redactions = ('', 0)
            if send_ai:
                snippet, redactions = build_snippet(text, hits, config=config)
            candidates.append({
                'path': rel,
                'kind': kind,
                'size': meta.st_size,
                'mtime': int(meta.st_mtime),
                'severity': max_severity(hits),
                'config': config,
                'send_ai': send_ai,
                'redactions': redactions,
                'hits': [{'rule': h[0], 'severity': h[1], 'line': h[2], 'reason': h[3], 'action': h[4]} for h in hits],
                'snippet': snippet,
            })

    candidates.sort(key=lambda c: (-SEV_RANK.get(c['severity'], 0), c['path']))
    if len(candidates) > max_candidates:
        report['truncated'] = True
        candidates = candidates[:max_candidates]
    report['candidates'] = candidates
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='IndiansCloud AI Scanner local pre-filter')
    parser.add_argument('--root', required=True)
    parser.add_argument('--max-files', type=int, default=MAX_FILES)
    parser.add_argument('--max-candidates', type=int, default=MAX_CANDIDATES)
    args = parser.parse_args(argv)
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass
    report = scan_tree(args.root, max_files=max(1, min(args.max_files, 500000)),
                       max_candidates=max(1, min(args.max_candidates, 2000)))
    sys.stdout.write('AISCANNER-JSON:' + json.dumps(report, separators=(',', ':')) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
