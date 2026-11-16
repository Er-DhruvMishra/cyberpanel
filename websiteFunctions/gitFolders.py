"""Folders a website owner can track with Manage GIT.

/home/<domain> is mode 711, so the panel cannot list it itself; the listing
runs as the site's own user through ProcessUtilities.
"""
import re
import shlex

# Folder names that hold panel/server data rather than site code.
EXCLUDED_NAMES = {'logs'}
_NAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9._-]*$')


def parse_site_folders(vh_root, output):
    """Return direct child directories of vh_root found in `find` output.

    public_html comes first, the rest alphabetically. Error lines, nested
    paths, hidden or excluded names and anything unusual are ignored.
    """
    prefix = vh_root.rstrip('/') + '/'
    names = set()
    for line in (output or '').splitlines():
        line = line.strip()
        if not line.startswith(prefix):
            continue
        name = line[len(prefix):]
        if '/' in name or not _NAME_RE.match(name) or name in EXCLUDED_NAMES:
            continue
        names.add(name)
    ordered = sorted(names, key=lambda n: (n != 'public_html', n.lower()))
    return [prefix + name for name in ordered]


def list_site_folders(domain, external_app, executor):
    """Folders under /home/<domain> to offer in the Manage GIT dropdown.

    `executor` is ProcessUtilities.outputExecutioner (command, user) -> str.
    Always includes public_html, even if the listing fails.
    """
    vh_root = '/home/%s' % domain
    command = 'find %s -mindepth 1 -maxdepth 1 -type d' % shlex.quote(vh_root)
    try:
        output = executor(command, external_app)
    except Exception:
        output = ''
    folders = parse_site_folders(vh_root, output if isinstance(output, str) else '')
    public_html = vh_root + '/public_html'
    if public_html not in folders:
        folders.insert(0, public_html)
    return folders
