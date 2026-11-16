"""The administrator's own OAuth app registration for each OAuth provider.

Stored as the panel user, mode 0600, one file per provider in /home/cyberpanel/backup-oauth/.
Google Drive shares the client of the Google Drive Backups page (plogical/gdriveClient.py,
/home/cyberpanel/gdrive-oauth.json), so the administrator registers Google only once.
The client secret is never returned to a browser: callers get public_status().
"""
import json
import os
import re
import stat
import tempfile

CLIENT_DIR = '/home/cyberpanel/backup-oauth'
MAX_SIZE = 16384
_ID = re.compile(r'^[A-Za-z0-9._-]{4,256}$')
_SECRET = re.compile(r'^[A-Za-z0-9._~+/=-]{4,512}$')


class ClientError(ValueError):
    pass


def _google():
    from plogical import gdriveClient
    return gdriveClient


def _file(provider, client_dir=None):
    from universalAddons.destinations.providers import OAUTH_PROVIDERS
    if provider not in OAUTH_PROVIDERS or provider == 'gdrive':
        raise ClientError('Unknown OAuth provider.')
    return os.path.join(client_dir or CLIENT_DIR, provider + '.json')


def load(provider, client_dir=None, google_path=None, allowed_uid=None):
    """{'client_id', 'client_secret'} or None when not configured.

    Refuses symlinks, files readable by group/others and files owned by anyone other than the
    current user, root or `allowed_uid` (the root side passes the panel user's uid).
    """
    if provider == 'gdrive':
        try:
            return _google().load_client(google_path)
        except _google().ClientConfigError as exc:
            raise ClientError(str(exc)) from None
    try:
        fd = os.open(_file(provider, client_dir), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise ClientError('The OAuth client file is not readable safely.') from None
    try:
        info = os.fstat(fd)
        owners = {os.geteuid(), 0} | ({allowed_uid} if allowed_uid is not None else set())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_SIZE or \
                info.st_uid not in owners:
            raise ClientError('The OAuth client file is not private.')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = json.loads(handle.read(MAX_SIZE + 1).decode('utf-8'))
    except ClientError:
        raise
    except Exception:
        raise ClientError('The OAuth client file is malformed.') from None
    finally:
        os.close(fd)
    if not isinstance(data, dict) or not _ID.match(str(data.get('client_id', ''))) or \
            not _SECRET.match(str(data.get('client_secret', ''))):
        raise ClientError('The OAuth client file is malformed.')
    return {'client_id': data['client_id'], 'client_secret': data['client_secret']}


def save(provider, client_id, client_secret='', client_dir=None, google_path=None):
    """Save a client. A blank secret keeps the stored secret of the same client ID."""
    client_id = str(client_id or '').strip()
    client_secret = str(client_secret or '').strip()
    if provider == 'gdrive':
        try:
            return _google().save_client(client_id, client_secret, google_path)
        except _google().ClientConfigError as exc:
            raise ClientError(str(exc)) from None
    target = _file(provider, client_dir)
    if not _ID.match(client_id):
        raise ClientError('Enter the client (application) ID.')
    if not client_secret:
        current = load(provider, client_dir)
        if not current or current['client_id'] != client_id:
            raise ClientError('Enter the client secret for this client ID.')
        client_secret = current['client_secret']
    if not _SECRET.match(client_secret):
        raise ClientError('The client secret has an unexpected format.')
    directory = os.path.dirname(target)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.islink(directory) or os.path.islink(target):
        raise ClientError('Refusing to write through a symlink.')
    os.chmod(directory, 0o700)
    fd, temporary = tempfile.mkstemp(prefix='.client-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(json.dumps({'client_id': client_id, 'client_secret': client_secret}).encode())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary:
            os.unlink(temporary)


def clear(provider, client_dir=None, google_path=None):
    if provider == 'gdrive':
        return _google().clear_client(google_path)
    try:
        os.unlink(_file(provider, client_dir))
    except FileNotFoundError:
        pass


def public_status(provider, client_dir=None, google_path=None):
    """Safe for the browser: the client ID and whether a secret is set, never the secret."""
    try:
        client = load(provider, client_dir, google_path)
    except ClientError as exc:
        return {'configured': False, 'client_id': '', 'client_secret': 'not set', 'error': str(exc)}
    if not client:
        return {'configured': False, 'client_id': '', 'client_secret': 'not set', 'error': ''}
    return {'configured': True, 'client_id': client['client_id'], 'client_secret': 'set', 'error': ''}
