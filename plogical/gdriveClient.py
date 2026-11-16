"""The admin's own Google OAuth client for Google Drive backups.

Stored in /home/cyberpanel/gdrive-oauth.json, mode 0600, readable only by the
panel user (and root). The client secret is never returned to a browser: callers
get ``public_status()``, which says only whether a secret is set.
"""
import json
import os
import re
import stat
import tempfile

CONFIG_PATH = '/home/cyberpanel/gdrive-oauth.json'
CLIENT_ID = re.compile(r'^[A-Za-z0-9_.-]{1,256}\.apps\.googleusercontent\.com$')
CLIENT_SECRET = re.compile(r'^[A-Za-z0-9._~-]{8,512}$')
MAX_SIZE = 16384


class ClientConfigError(ValueError):
    pass


def _path(path):
    return path or CONFIG_PATH


def valid_client_id(value):
    return isinstance(value, str) and bool(CLIENT_ID.fullmatch(value))


def valid_client_secret(value):
    return isinstance(value, str) and bool(CLIENT_SECRET.fullmatch(value))


def load_client(path=None):
    """Return {'client_id', 'client_secret'} or None when not configured.

    Raises ClientConfigError for an unsafe or malformed file (symlink, group or
    world readable, owned by another unprivileged user, bad values).
    """
    try:
        descriptor = os.open(_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise ClientConfigError('Google OAuth client file is not readable safely') from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_SIZE or
                (info.st_uid != os.geteuid() and os.geteuid() != 0)):
            raise ClientConfigError('Google OAuth client file is not private')
        with os.fdopen(descriptor, 'rb', closefd=False) as handle:
            raw = handle.read(MAX_SIZE + 1)
        data = json.loads(raw.decode('utf-8'))
    except ClientConfigError:
        raise
    except Exception:
        raise ClientConfigError('Google OAuth client file is malformed') from None
    finally:
        os.close(descriptor)
    if (not isinstance(data, dict) or not valid_client_id(data.get('client_id')) or
            not valid_client_secret(data.get('client_secret'))):
        raise ClientConfigError('Google OAuth client file is malformed')
    return {'client_id': data['client_id'], 'client_secret': data['client_secret']}


def save_client(client_id, client_secret='', path=None):
    """Save the client. A blank secret keeps the stored one for the same client ID."""
    client_id = client_id.strip() if isinstance(client_id, str) else client_id
    client_secret = client_secret.strip() if isinstance(client_secret, str) else client_secret
    if not valid_client_id(client_id):
        raise ClientConfigError('Enter a client ID ending in .apps.googleusercontent.com')
    if not client_secret:
        current = load_client(path)
        if not current or current['client_id'] != client_id:
            raise ClientConfigError('Enter the client secret for this client ID')
        client_secret = current['client_secret']
    if not valid_client_secret(client_secret):
        raise ClientConfigError('The client secret has an unexpected format')
    target = _path(path)
    directory = os.path.dirname(target) or '.'
    if os.path.islink(target):
        raise ClientConfigError('Refusing to replace a symlink')
    body = json.dumps({'client_id': client_id, 'client_secret': client_secret}, sort_keys=True).encode()
    descriptor, temporary = tempfile.mkstemp(prefix='.gdrive-oauth-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary:
            os.unlink(temporary)


def clear_client(path=None):
    try:
        os.unlink(_path(path))
    except FileNotFoundError:
        pass


def public_status(path=None):
    """Safe for the browser: the client ID and whether a secret is set, never the secret."""
    try:
        client = load_client(path)
    except ClientConfigError as error:
        return {'configured': False, 'client_id': '', 'client_secret': 'not set', 'error': str(error)}
    if not client:
        return {'configured': False, 'client_id': '', 'client_secret': 'not set', 'error': ''}
    return {'configured': True, 'client_id': client['client_id'], 'client_secret': 'set', 'error': ''}
