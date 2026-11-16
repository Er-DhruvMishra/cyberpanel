"""Optional status receivers. Nothing is sent anywhere unless the admin sets a URL.

Upstream CyberPanel posted install, upgrade and High Availability status to the
vendor (platform.cyberpersons.com). IndiansCloud keeps that information local
(log files) and only forwards it when the admin configures an https receiver in
/home/cyberpanel/status-receivers.json, for example:

    {"upgrade_status_url": "", "ha_status_url": "", "ha_uptime_url": ""}

Every key is empty by default, so no request is made.
"""
import json
import os
import stat
from urllib.parse import urlsplit

CONFIG_PATH = '/home/cyberpanel/status-receivers.json'
KEYS = ('upgrade_status_url', 'ha_status_url', 'ha_uptime_url')


def receiver_url(key, path=None):
    """Return the configured https URL for ``key`` or '' (the default)."""
    if key not in KEYS:
        return ''
    try:
        descriptor = os.open(path or CONFIG_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ''
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > 65536:
            return ''
        with os.fdopen(descriptor, 'rb', closefd=False) as handle:
            data = json.loads(handle.read(65537).decode('utf-8'))
    except Exception:
        return ''
    finally:
        os.close(descriptor)
    value = data.get(key, '') if isinstance(data, dict) else ''
    if not isinstance(value, str) or not value:
        return ''
    url = urlsplit(value)
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        return ''
    return value


def send(key, payload, timeout=10):
    """POST ``payload`` as JSON to the configured receiver. No URL means no request."""
    url = receiver_url(key)
    if not url:
        return False
    try:
        import requests
        requests.post(url, json=payload, timeout=timeout, allow_redirects=False)
        return True
    except Exception:
        return False
