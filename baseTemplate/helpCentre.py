"""Local help centre: Markdown articles in baseTemplate/help/<slug>.md, rendered on the server.

The renderer supports only the subset the articles use (headings, paragraphs, lists, fenced code,
inline code, links and bold) and escapes every character of the source, so an article can never
inject HTML or script into the panel.
"""
import html
import re
import subprocess
import time
from pathlib import Path

HELP_DIR = Path(__file__).resolve().parent / 'help'
SLUG_RE = re.compile(r'^[a-z0-9-]{1,80}$')
CHANGELOG_REPO = '/usr/local/CyberCP'
CHANGELOG_FALLBACK = 'https://github.com/Er-DhruvMishra/cyberpanel/commits/main'

# Index order. Every .md file in HELP_DIR must appear here exactly once (see test_help.py).
CATEGORIES = (
    ('Getting started', ('onboarding', 'universal-addons', 'upgrading', 'change-logs')),
    ('Websites', ('creating-websites', 'sub-addon-domains', 'child-domains', 'wordpress-deploy',
                  'file-manager', 'rewrite-rules', 'cron-jobs', 'git-manager', 'apache-manager',
                  'web-terminal', 'ssh-manager', 'ftp')),
    ('DNS', ('dns-management', 'powerdns-service')),
    ('Email', ('email-server', 'email-accounts', 'email-forwarding', 'email-limits', 'dkim',
               'mail-server-ssl', 'spamassassin', 'email-queue', 'email-debugger',
               'cybermail-setup', 'cybermail-guide')),
    ('SSL', ('ssl-manager', 'hostname-ssl')),
    ('Backups', ('backup-restore', 'backup-schedule', 'backup-destinations', 'remote-transfer',
                 'google-drive-backup', 'incremental-backups', 'incremental-backup-destinations',
                 'incremental-backup-restore', 'backup-v2')),
    ('Security and server', ('imunify', 'modsecurity', 'cloudlinux', 'litespeed-enterprise')),
)

_SAFE_HREF = re.compile(r'^(/(?!/)|#|https://|http://)')
_INLINE_CODE = re.compile(r'`([^`]+)`')
_LINK = re.compile(r'\[([^\]]+)\]\(([^)\s]+)\)')
_BOLD = re.compile(r'\*\*(.+?)\*\*')
_ORDERED = re.compile(r'^\d+\.\s+(.*)$')
_UNORDERED = re.compile(r'^[-*]\s+(.*)$')
_HEADING = re.compile(r'^(#{1,4})\s+(.*)$')


def valid_slug(slug):
    return isinstance(slug, str) and bool(SLUG_RE.match(slug))


def _link(match):
    text, href = match.group(1), match.group(2)
    # Both parts are already escaped. Unknown schemes (javascript:, data:...) become plain text.
    if not _SAFE_HREF.match(href):
        return text
    external = href.startswith('http')
    extra = ' target="_blank" rel="noopener noreferrer"' if external else ''
    return '<a href="%s"%s>%s</a>' % (href, extra, text)


def render_inline(text):
    out = []
    pos = 0
    for match in _INLINE_CODE.finditer(text):
        out.append(_format(text[pos:match.start()]))
        out.append('<code>%s</code>' % html.escape(match.group(1)))
        pos = match.end()
    out.append(_format(text[pos:]))
    return ''.join(out)


def _format(text):
    text = html.escape(text)
    text = _LINK.sub(_link, text)
    return _BOLD.sub(r'<strong>\1</strong>', text)


def render_markdown(source):
    """Return HTML for the supported Markdown subset. Every input character is escaped."""
    lines = source.replace('\r\n', '\n').split('\n')
    out, para, items, list_tag = [], [], [], None

    def flush():
        nonlocal list_tag
        if para:
            out.append('<p>%s</p>' % render_inline(' '.join(para)))
            para.clear()
        if items:
            out.append('<%s>%s</%s>' % (list_tag, ''.join('<li>%s</li>' % render_inline(i) for i in items), list_tag))
            items.clear()
            list_tag = None

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()
        if stripped.startswith('```'):
            flush()
            code = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code.append(lines[i].rstrip())
                i += 1
            out.append('<pre><code>%s</code></pre>' % html.escape('\n'.join(code)))
            i += 1
            continue
        if not stripped:
            flush()
        elif _HEADING.match(stripped):
            flush()
            level, text = _HEADING.match(stripped).groups()
            # The article title is the page's only h1, so body headings start at h2.
            tag = 'h%d' % max(2, len(level))
            out.append('<%s>%s</%s>' % (tag, render_inline(text), tag))
        elif _UNORDERED.match(stripped) or _ORDERED.match(stripped):
            tag = 'ul' if _UNORDERED.match(stripped) else 'ol'
            if para or (items and list_tag != tag):
                flush()
            list_tag = tag
            items.append((_UNORDERED.match(stripped) or _ORDERED.match(stripped)).group(1))
        elif items and line.startswith('  '):
            items[-1] += ' ' + stripped  # continuation of a list item
        else:
            if items:
                flush()
            para.append(stripped)
        i += 1
    flush()
    return '\n'.join(out)


def _split(source):
    """Return (title, summary, body) from an article: '# Title', first paragraph = summary."""
    lines = source.lstrip('﻿').split('\n')
    title = ''
    if lines and lines[0].startswith('# '):
        title = lines[0][2:].strip()
        lines = lines[1:]
    body = '\n'.join(lines).strip('\n')
    summary = ''
    for block in body.split('\n\n'):
        block = block.strip()
        if block and not block.startswith(('#', '-', '*', '```')) and not _ORDERED.match(block):
            summary = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', ' '.join(block.split()))
            summary = summary.replace('**', '').replace('`', '')
            break
    return title, summary, body


def article_path(slug):
    if not valid_slug(slug):
        return None
    path = (HELP_DIR / (slug + '.md')).resolve()
    if path.parent != HELP_DIR or not path.is_file():
        return None
    return path


def load_article(slug):
    """Return {'slug', 'title', 'summary', 'html'} or None for an unknown or invalid slug."""
    path = article_path(slug)
    if path is None:
        return None
    title, summary, body = _split(path.read_text(encoding='utf-8'))
    return {'slug': slug, 'title': title or slug, 'summary': summary, 'html': render_markdown(body)}


def index():
    """[{'name': category, 'articles': [{'slug', 'title', 'summary'}]}] for the topics that exist."""
    result = []
    for name, slugs in CATEGORIES:
        articles = []
        for slug in slugs:
            path = article_path(slug)
            if path is None:
                continue
            title, summary, _ = _split(path.read_text(encoding='utf-8'))
            articles.append({'slug': slug, 'title': title or slug, 'summary': summary})
        if articles:
            result.append({'name': name, 'articles': articles})
    return result


_commit_cache = {'at': 0.0, 'value': None}


def recent_commits(repo=CHANGELOG_REPO, limit=30, ttl=600, run=subprocess.run, now=time.time):
    """Recent commit subjects of the panel checkout, or None when git or the checkout is unavailable."""
    if _commit_cache['value'] is not None and now() - _commit_cache['at'] < ttl and repo == CHANGELOG_REPO:
        return _commit_cache['value']
    if not Path(repo, '.git').exists():
        return None
    try:
        result = run(['git', '-c', 'safe.directory=' + repo, '-C', repo, 'log', '-n', str(int(limit)),
                      '--no-merges', '--date=short', '--format=%h%x1f%ad%x1f%s'],
                     capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    commits = []
    for line in result.stdout.splitlines():
        parts = line.split('\x1f')
        if len(parts) == 3:
            commits.append({'hash': parts[0], 'date': parts[1], 'subject': parts[2]})
    if repo == CHANGELOG_REPO:
        _commit_cache.update(at=now(), value=commits)
    return commits
