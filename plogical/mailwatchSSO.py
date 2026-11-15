"""Sign panel administrators into MailWatch without a second password.

The panel (running as the panel user) writes a single-use ticket into a directory shared with
lscpd's PHP (owner cyberpanel, group lscpd, setgid, mode 2770). MailWatch's cp-sso.php claims it
once (atomic rename), checks the expiry and signs the browser in as the mapped MailWatch user.
Only the SHA-256 of the token is used as the file name; the token travels in a POST body.
"""
import hashlib
import json
import os
import re
import secrets
import time

SSO_DIR = '/var/lib/cp-mailwatch-sso'
TTL = 60
MAILWATCH_USER = 'admin'
_NAME = re.compile(r'^[0-9a-f]{64}\.json$')


class SSOError(RuntimeError):
    pass


def prune(directory=SSO_DIR, now=None):
    now = time.time() if now is None else now
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names[:500]:
        path = os.path.join(directory, name)
        try:
            if not _NAME.match(name) or now - os.lstat(path).st_mtime > TTL:
                os.unlink(path)
        except OSError:
            pass


def issue(panel_user, directory=SSO_DIR, now=None, user=MAILWATCH_USER):
    """Create a ticket for the given panel administrator; return the token."""
    now = time.time() if now is None else now
    if not os.path.isdir(directory):
        raise SSOError('MailWatch sign-on is not set up on this server (missing %s).' % directory)
    prune(directory, now)
    token = secrets.token_urlsafe(32)
    path = os.path.join(directory, hashlib.sha256(token.encode('ascii')).hexdigest() + '.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'w') as handle:
        json.dump({'user': user, 'panel_user': panel_user, 'expires': now + TTL}, handle)
    return token


def handoff_page(token, action='/mailwatch/mailscanner/cp-sso.php'):
    """An auto-submitting POST form, so the token never appears in a URL or access log."""
    return ('<!doctype html><html><head><meta charset="utf-8"><title>Opening MailWatch…</title></head>'
            '<body><form id="f" method="post" action="%s"><input type="hidden" name="cp_sso" value="%s">'
            '<noscript><button type="submit">Continue to MailWatch</button></noscript></form>'
            '<script>document.getElementById("f").submit();</script></body></html>' % (action, token))
