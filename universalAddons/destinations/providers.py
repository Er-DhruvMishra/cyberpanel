"""Backup destination providers: their fields, validation and rclone configuration.

Every destination is reached through rclone (restic uses it as its ``rclone:`` backend), so a
destination is fully described by one rclone remote section. The section is rendered only on the
root side, per run, into a private temporary file (see actions.py); it is never written anywhere
a browser or another local user can read.

Fields are split into ``public`` (stored in the panel database, shown to the destination's owner
only) and ``secret`` (stored in the root-only store, never returned to anyone).
"""
import base64
import json
import re

DEFAULT_FOLDER = 'IndiansCloud Backups'
REPO_SUBDIR = 'restic'

_HOST = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$')
_USER = re.compile(r'^[A-Za-z0-9._@+-]{1,128}$')
_PATH = re.compile(r'^/?[A-Za-z0-9._ ~+@-]+(/[A-Za-z0-9._ ~+@-]+)*/?$')
_BUCKET = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.-]{1,62}$')
_PREFIX = re.compile(r'^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$')
_REGION = re.compile(r'^[a-z0-9-]{1,32}$')
_ACCOUNT_ID = re.compile(r'^[a-f0-9]{32}$')
_KEY_ID = re.compile(r'^[A-Za-z0-9+/=._-]{4,256}$')
_PRINTABLE = re.compile(r'^[\x20-\x7e]{1,1024}$')
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')


class ProviderError(ValueError):
    pass


class _Kept:
    """Stands for a stored secret the web side cannot see (blank field on update)."""
    def __bool__(self):
        return True


KEPT = _Kept()


def F(key, label, kind='text', required=True, secret=False, default='', choices=None, help='', show=None):
    """A form field. show: {'other_field': [values]} - shown only when the condition holds."""
    return {'key': key, 'label': label, 'kind': kind, 'required': required, 'secret': secret,
            'default': default, 'choices': choices or [], 'help': help, 'show': show or {}}


FOLDER = F('folder', 'Folder', default=DEFAULT_FOLDER, required=False,
           help='Folder in your storage for the backups (created if missing).')

S3_PRESETS = {
    'aws': {'title': 'Amazon S3', 'provider': 'AWS', 'endpoint': '', 'region': 'us-east-1'},
    'b2s3': {'title': 'Backblaze B2 (S3 API)', 'provider': 'Other', 'endpoint': 's3.{region}.backblazeb2.com',
             'region': 'us-west-004'},
    'wasabi': {'title': 'Wasabi', 'provider': 'Wasabi', 'endpoint': 's3.{region}.wasabisys.com', 'region': 'us-east-1'},
    'r2': {'title': 'Cloudflare R2', 'provider': 'Cloudflare', 'endpoint': '{account_id}.r2.cloudflarestorage.com',
           'region': 'auto'},
    'idrive': {'title': 'iDrive e2', 'provider': 'IDrive', 'endpoint': None, 'region': ''},
    'minio': {'title': 'MinIO / other S3-compatible', 'provider': 'Minio', 'endpoint': None, 'region': ''},
}

# OAuth providers: what the administrator registers once, and where.
OAUTH_SETUP = {
    'gdrive': {
        'console': 'https://console.cloud.google.com/apis/credentials',
        'steps': [
            'Open Google Cloud Console and create or pick a project.',
            'APIs & Services > Library: enable the Google Drive API.',
            'OAuth consent screen: External (or Internal for Workspace); add the scope '
            'https://www.googleapis.com/auth/drive.file; publish the app (test-mode tokens expire after 7 days).',
            'Credentials > Create credentials > OAuth client ID > Web application.',
            'Add the redirect URI below under "Authorized redirect URIs".',
            'Copy the client ID and client secret here.',
        ],
    },
    'onedrive': {
        'console': 'https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade',
        'steps': [
            'Microsoft Entra admin center (or Azure portal) > App registrations > New registration.',
            'Supported account types: "Accounts in any organizational directory and personal Microsoft '
            'accounts" (covers OneDrive personal and OneDrive for Business).',
            'Redirect URI: platform "Web", the redirect URI below.',
            'Certificates & secrets > New client secret; copy its Value (not the Secret ID).',
            'API permissions > Microsoft Graph > Delegated: Files.ReadWrite and offline_access.',
            'Copy the Application (client) ID and the secret value here.',
        ],
    },
    'dropbox': {
        'console': 'https://www.dropbox.com/developers/apps',
        'steps': [
            'Dropbox App Console > Create app > Scoped access > App folder (or Full Dropbox).',
            'Permissions tab: enable files.metadata.read, files.metadata.write, files.content.read, '
            'files.content.write, then Submit.',
            'Settings tab: add the redirect URI below under OAuth 2 > Redirect URIs.',
            'Copy the App key (client ID) and App secret here.',
        ],
    },
    'box': {
        'console': 'https://app.box.com/developers/console',
        'steps': [
            'Box Developer Console > Create New App > Custom App > User Authentication (OAuth 2.0).',
            'Configuration: add the redirect URI below; Application Scopes: Read and write all files and folders.',
            'Copy the Client ID and Client Secret here.',
        ],
    },
    'pcloud': {
        'console': 'https://docs.pcloud.com/my_apps/',
        'steps': [
            'pCloud > My applications > New app.',
            'Add the redirect URI below; permissions: Upload, Modify, Delete files.',
            'Copy the Client ID and Client secret here.',
        ],
    },
}

PROVIDERS = {
    'gdrive': {'title': 'Google Drive', 'kind': 'oauth', 'rclone': 'drive', 'fields': [FOLDER], 'about': True},
    'onedrive': {'title': 'Microsoft OneDrive (personal or business)', 'kind': 'oauth', 'rclone': 'onedrive',
                 'fields': [FOLDER], 'about': True},
    'dropbox': {'title': 'Dropbox', 'kind': 'oauth', 'rclone': 'dropbox', 'fields': [FOLDER], 'about': True},
    'box': {'title': 'Box', 'kind': 'oauth', 'rclone': 'box', 'fields': [FOLDER], 'about': True},
    'pcloud': {'title': 'pCloud', 'kind': 'oauth', 'rclone': 'pcloud', 'fields': [FOLDER], 'about': True},
    's3': {'title': 'S3-compatible (AWS, Backblaze B2, Wasabi, Cloudflare R2, iDrive e2, MinIO)', 'kind': 'key',
           'rclone': 's3', 'about': False, 'fields': [
               F('preset', 'Service', kind='select', default='aws',
                 choices=[[k, v['title']] for k, v in S3_PRESETS.items()]),
               F('region', 'Region', required=False, help='For example us-east-1, us-west-004 (B2), eu-central-1.',
                 show={'preset': ['aws', 'b2s3', 'wasabi', 'idrive', 'minio']}),
               F('account_id', 'Cloudflare account ID', required=False, show={'preset': ['r2']}),
               F('endpoint', 'Endpoint host', required=False, help='Host name, optionally with :port.',
                 show={'preset': ['idrive', 'minio']}),
               F('use_http', 'Use plain http (local MinIO only)', kind='checkbox', required=False,
                 show={'preset': ['minio']}),
               F('bucket', 'Bucket', help='The bucket must already exist.'),
               F('prefix', 'Folder inside the bucket', required=False, default='indianscloud'),
               F('access_key_id', 'Access key ID', secret=True),
               F('secret_access_key', 'Secret access key', kind='password', secret=True),
           ]},
    'sftp': {'title': 'SFTP', 'kind': 'key', 'rclone': 'sftp', 'about': True, 'fields': [
        F('host', 'Host'), F('port', 'Port', kind='number', default='22'), F('user', 'User'),
        F('path', 'Directory', default='indianscloud-backups', help='Absolute, or relative to the login directory.'),
        F('auth', 'Sign in with', kind='select', default='password', choices=[['password', 'Password'],
                                                                                ['key', 'Private key']]),
        F('password', 'Password', kind='password', secret=True, required=False, show={'auth': ['password']}),
        F('private_key', 'Private key (PEM / OpenSSH)', kind='textarea', secret=True, required=False,
          show={'auth': ['key']}),
        F('key_passphrase', 'Key passphrase', kind='password', secret=True, required=False, show={'auth': ['key']}),
    ]},
    'ftp': {'title': 'FTP / FTPS', 'kind': 'key', 'rclone': 'ftp', 'about': False, 'fields': [
        F('host', 'Host'), F('port', 'Port', kind='number', default='21'), F('user', 'User'),
        F('path', 'Directory', default='indianscloud-backups'),
        F('tls', 'Encryption', kind='select', default='explicit',
          choices=[['explicit', 'FTPS, explicit TLS (port 21)'], ['implicit', 'FTPS, implicit TLS (port 990)'],
                   ['none', 'None (plain FTP, not recommended)']]),
        F('password', 'Password', kind='password', secret=True),
    ]},
    'webdav': {'title': 'WebDAV (Nextcloud, ownCloud)', 'kind': 'key', 'rclone': 'webdav', 'about': True, 'fields': [
        F('vendor', 'Server', kind='select', default='nextcloud',
          choices=[['nextcloud', 'Nextcloud'], ['owncloud', 'ownCloud'], ['other', 'Other WebDAV']]),
        F('host', 'Host', help='Host name, optionally with :port.'),
        F('dav_path', 'WebDAV path', required=False,
          help='Nextcloud: remote.php/dav/files/USERNAME. ownCloud: remote.php/webdav.'),
        F('user', 'User'), F('password', 'Password or app password', kind='password', secret=True),
        F('path', 'Folder', default='indianscloud-backups'),
    ]},
    'b2': {'title': 'Backblaze B2 (native API)', 'kind': 'key', 'rclone': 'b2', 'about': False, 'fields': [
        F('bucket', 'Bucket'), F('prefix', 'Folder inside the bucket', required=False, default='indianscloud'),
        F('account', 'Application key ID', secret=True),
        F('key', 'Application key', kind='password', secret=True),
    ]},
}

OAUTH_PROVIDERS = tuple(k for k, v in PROVIDERS.items() if v['kind'] == 'oauth')
# Secret keys an OAuth sign-in stores (never typed by users).
OAUTH_SECRET_KEYS = {'token', 'drive_id', 'drive_type', 'hostname'}


def get(provider):
    spec = PROVIDERS.get(provider)
    if not spec:
        raise ProviderError('Unknown provider.')
    return spec


def describe():
    """Provider metadata for the browser (field definitions only, no values)."""
    return [{'key': key, 'title': spec['title'], 'kind': spec['kind'], 'fields': spec['fields']}
            for key, spec in PROVIDERS.items()]


def valid_name(name):
    name = str(name or '').strip()
    if not _NAME.match(name):
        raise ProviderError('Name: 1-64 letters, digits, spaces, ".", "_" or "-", starting with a letter or digit.')
    return name


def _visible(field, values):
    return all(values.get(other) in allowed for other, allowed in field['show'].items())


def _clean_path(value, label, allow_absolute=True):
    value = str(value or '').strip()
    if not value:
        return ''
    if not _PATH.match(value) or any(part in ('.', '..') for part in value.strip('/').split('/')) or \
            (value.startswith('/') and not allow_absolute):
        raise ProviderError('%s: letters, digits, spaces and . _ - ~ + @, separated by "/".' % label)
    return value.rstrip('/') if value != '/' else value


def _host_port(value, label):
    value = str(value or '').strip().lower()
    host, _, port = value.partition(':')
    if not _HOST.match(host) or (port and (not port.isdigit() or not 0 < int(port) < 65536)):
        raise ProviderError('%s: a host name, optionally with :port.' % label)
    return value


def validate_public(provider, data):
    """Return the clean public config for provider from untrusted data (secrets are ignored)."""
    spec = get(provider)
    data = data if isinstance(data, dict) else {}
    values = {}
    for field in spec['fields']:
        if field['secret']:
            continue
        raw = data.get(field['key'], field['default'])
        if field['kind'] == 'checkbox':
            values[field['key']] = raw is True
        elif field['kind'] == 'select':
            raw = str(raw or field['default'])
            if raw not in [c[0] for c in field['choices']]:
                raise ProviderError('%s: choose one of the listed options.' % field['label'])
            values[field['key']] = raw
        else:
            values[field['key']] = str(raw if raw is not None else '').strip()
    clean = {}
    if spec['kind'] == 'oauth':
        clean['folder'] = _clean_path(values.get('folder') or DEFAULT_FOLDER, 'Folder', allow_absolute=False)
        return clean
    if provider == 's3':
        preset = S3_PRESETS[values['preset']]
        clean['preset'] = values['preset']
        region = values.get('region', '') or preset['region']
        if values['preset'] == 'r2':
            region = 'auto'
            if not _ACCOUNT_ID.match(values.get('account_id', '').lower()):
                raise ProviderError('Cloudflare account ID: 32 hexadecimal characters (R2 > Overview).')
            clean['account_id'] = values['account_id'].lower()
        if region and not _REGION.match(region):
            raise ProviderError('Region: lowercase letters, digits and dashes.')
        clean['region'] = region
        if preset['endpoint'] is None:
            clean['endpoint'] = _host_port(values.get('endpoint'), 'Endpoint host')
        if values['preset'] == 'minio':
            clean['use_http'] = values.get('use_http') is True
        if values['preset'] == 'aws' and not region:
            raise ProviderError('Enter the bucket region.')
        if not _BUCKET.match(values.get('bucket', '')):
            raise ProviderError('Bucket: 2-63 letters, digits, dots or dashes.')
        clean['bucket'] = values['bucket']
        prefix = values.get('prefix', '').strip('/')
        if prefix and not _PREFIX.match(prefix):
            raise ProviderError('Folder inside the bucket: letters, digits, . _ - separated by "/".')
        clean['prefix'] = prefix
    elif provider in ('sftp', 'ftp'):
        if not _HOST.match(values.get('host', '').lower()):
            raise ProviderError('Enter the server host name or IP address.')
        clean['host'] = values['host'].lower()
        try:
            port = int(values.get('port') or field_default(provider, 'port'))
        except ValueError:
            raise ProviderError('Port must be a number.')
        if not 0 < port < 65536:
            raise ProviderError('Port must be 1-65535.')
        clean['port'] = port
        if not _USER.match(values.get('user', '')):
            raise ProviderError('User: letters, digits and . _ @ + -')
        clean['user'] = values['user']
        clean['path'] = _clean_path(values.get('path'), 'Directory') or field_default(provider, 'path')
        if provider == 'sftp':
            clean['auth'] = values['auth']
        else:
            clean['tls'] = values['tls']
    elif provider == 'webdav':
        clean['vendor'] = values['vendor']
        clean['host'] = _host_port(values.get('host'), 'Host')
        dav_path = _clean_path(values.get('dav_path'), 'WebDAV path')
        clean['dav_path'] = dav_path.strip('/')
        if not _USER.match(values.get('user', '')):
            raise ProviderError('User: letters, digits and . _ @ + -')
        clean['user'] = values['user']
        clean['path'] = _clean_path(values.get('path'), 'Folder', allow_absolute=False) or 'indianscloud-backups'
    elif provider == 'b2':
        if not re.match(r'^[A-Za-z0-9-]{6,50}$', values.get('bucket', '')):
            raise ProviderError('B2 bucket: 6-50 letters, digits or dashes.')
        clean['bucket'] = values['bucket']
        prefix = values.get('prefix', '').strip('/')
        if prefix and not _PREFIX.match(prefix):
            raise ProviderError('Folder inside the bucket: letters, digits, . _ - separated by "/".')
        clean['prefix'] = prefix
    return clean


def field_default(provider, key):
    for field in get(provider)['fields']:
        if field['key'] == key:
            return field['default']
    return ''


def decode_secrets(blob):
    """Secrets travel from the browser as base64 of a JSON object, so passwords may contain any
    character (the panel's request filter rejects many punctuation characters in plain values)."""
    if blob in (None, ''):
        return {}
    if not isinstance(blob, str) or not re.match(r'^[A-Za-z0-9+/=]{0,65536}$', blob):
        raise ProviderError('Invalid credentials encoding.')
    try:
        data = json.loads(base64.b64decode(blob.encode('ascii'), validate=True).decode('utf-8'))
    except Exception:
        raise ProviderError('Invalid credentials encoding.')
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise ProviderError('Invalid credentials.')
    return data


def validate_secrets(provider, public, secrets, existing=None):
    """Clean secrets for a key-based provider. Blank values keep the existing ones (updates)."""
    spec = get(provider)
    existing = existing or {}
    if spec['kind'] == 'oauth':
        raise ProviderError('Sign in with the provider instead of entering credentials.')
    clean = {}
    for field in spec['fields']:
        if not field['secret']:
            continue
        value = secrets.get(field['key'], '')
        if not isinstance(value, str):
            raise ProviderError('Invalid %s.' % field['label'])
        if field['kind'] != 'textarea':
            value = value.strip()
        if not value and field['key'] in existing:
            value = existing[field['key']]
            if value is not KEPT and not isinstance(value, str):
                raise ProviderError('Invalid stored %s.' % field['label'])
        if not _visible(field, public):
            continue
        if value is KEPT:
            clean[field['key']] = KEPT
            continue
        if not value:
            if field['required']:
                raise ProviderError('Enter the %s.' % field['label'].lower())
            continue
        if field['kind'] == 'textarea':
            value = value.replace('\r\n', '\n').strip() + '\n'
            if len(value) > 16384 or not re.match(r'^-----BEGIN [A-Z0-9 ]+-----\n[A-Za-z0-9+/=\n:,\- ]+-----END [A-Z0-9 ]+-----\n$', value):
                raise ProviderError('The private key must be a PEM or OpenSSH private key.')
        elif field['key'] in ('access_key_id', 'account'):
            if not _KEY_ID.match(value):
                raise ProviderError('Invalid %s.' % field['label'])
        elif not _PRINTABLE.match(value):
            raise ProviderError('%s: printable characters only (no line breaks).' % field['label'])
        clean[field['key']] = value
    if provider == 'sftp' and public.get('auth') == 'password' and not clean.get('password'):
        raise ProviderError('Enter the password.')
    if provider == 'sftp' and public.get('auth') == 'key' and not clean.get('private_key'):
        raise ProviderError('Paste the private key.')
    return clean


def validate_oauth_secrets(provider, secrets):
    if provider not in OAUTH_PROVIDERS or not isinstance(secrets, dict) or set(secrets) - OAUTH_SECRET_KEYS:
        raise ProviderError('Invalid sign-in data.')
    token = secrets.get('token')
    try:
        parsed = json.loads(token)
    except (TypeError, ValueError):
        raise ProviderError('Invalid sign-in data.')
    if not isinstance(parsed, dict) or not isinstance(parsed.get('access_token'), str) or \
            not re.match(r'^[\x21-\x7e]{1,8192}$', parsed['access_token']):
        raise ProviderError('Invalid sign-in data.')
    if provider == 'onedrive':
        if not re.match(r'^[A-Za-z0-9!._-]{1,256}$', secrets.get('drive_id', '')) or \
                secrets.get('drive_type') not in ('personal', 'business', 'documentLibrary'):
            raise ProviderError('Invalid OneDrive drive.')
    if provider == 'pcloud' and secrets.get('hostname') not in ('api.pcloud.com', 'eapi.pcloud.com'):
        raise ProviderError('Invalid pCloud region.')
    return dict(secrets)


def base_path(provider, public):
    """Folder of the destination inside its remote (without the remote name)."""
    if PROVIDERS[provider]['kind'] == 'oauth':
        return public.get('folder') or DEFAULT_FOLDER
    if provider in ('s3', 'b2'):
        return public['bucket'] + ('/' + public['prefix'] if public.get('prefix') else '')
    return public.get('path') or 'indianscloud-backups'


def repo_path(provider, public):
    return base_path(provider, public).rstrip('/') + '/' + REPO_SUBDIR


def _value(value):
    value = str(value)
    if any(ch in value for ch in '\r\n\x00') or value != value.strip():
        raise ProviderError('Invalid configuration value.')
    return value


def render(remote, provider, public, secrets, client=None, obscure=None):
    """The rclone config section text for one destination.

    client: {'client_id', 'client_secret'} of the administrator's OAuth app (OAuth providers).
    obscure: callable(str) -> rclone-obscured str (passwords; rclone requires that form).
    """
    if not re.match(r'^[a-z][a-z0-9]{0,31}$', remote):
        raise ProviderError('Invalid remote name.')
    spec = get(provider)
    pairs = [('type', spec['rclone'])]
    if spec['kind'] == 'oauth':
        if not client:
            raise ProviderError('The administrator has not set up %s sign-in.' % spec['title'])
        pairs += [('client_id', client['client_id']), ('client_secret', client['client_secret']),
                  ('token', secrets['token'])]
        if provider == 'gdrive':
            pairs += [('scope', 'drive.file')]
        elif provider == 'onedrive':
            pairs += [('drive_id', secrets['drive_id']), ('drive_type', secrets['drive_type']), ('region', 'global')]
        elif provider == 'pcloud':
            pairs += [('hostname', secrets['hostname'])]
    elif provider == 's3':
        preset = S3_PRESETS[public['preset']]
        endpoint = preset['endpoint']
        if endpoint is None:
            endpoint = public['endpoint']
        else:
            endpoint = endpoint.format(region=public.get('region', ''), account_id=public.get('account_id', ''))
        pairs += [('provider', preset['provider']), ('env_auth', 'false'),
                  ('access_key_id', secrets['access_key_id']), ('secret_access_key', secrets['secret_access_key'])]
        if public.get('region'):
            pairs.append(('region', public['region']))
        if endpoint:
            pairs.append(('endpoint', ('http://' if public.get('use_http') else 'https://') + endpoint))
        pairs += [('acl', 'private'), ('no_check_bucket', 'true')]
    elif provider == 'sftp':
        pairs += [('host', public['host']), ('user', public['user']), ('port', str(public['port']))]
        if public.get('auth') == 'key':
            pairs.append(('key_pem', secrets['private_key'].strip().replace('\n', '\\n')))
            if secrets.get('key_passphrase'):
                pairs.append(('key_file_pass', obscure(secrets['key_passphrase'])))
        else:
            pairs.append(('pass', obscure(secrets['password'])))
        # Never run commands on the remote shell (checksums are not needed by restic).
        pairs += [('shell_type', 'none'), ('md5sum_command', 'none'), ('sha1sum_command', 'none')]
    elif provider == 'ftp':
        pairs += [('host', public['host']), ('user', public['user']), ('port', str(public['port'])),
                  ('pass', obscure(secrets['password']))]
        if public.get('tls') == 'implicit':
            pairs.append(('tls', 'true'))
        elif public.get('tls') == 'explicit':
            pairs.append(('explicit_tls', 'true'))
    elif provider == 'webdav':
        url = 'https://%s/%s' % (public['host'], public.get('dav_path', ''))
        pairs += [('url', url.rstrip('/')), ('vendor', public['vendor']), ('user', public['user']),
                  ('pass', obscure(secrets['password']))]
    elif provider == 'b2':
        pairs += [('account', secrets['account']), ('key', secrets['key']), ('hard_delete', 'false')]
    lines = ['[%s]' % remote] + ['%s = %s' % (key, _value(value)) for key, value in pairs]
    return '\n'.join(lines) + '\n'


def rclone_token(access_token, refresh_token=None, expires_in=None, now=None):
    """Token JSON in the form rclone stores (Go oauth2.Token), so rclone can refresh it."""
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    if expires_in:
        expiry = (now + timedelta(seconds=int(expires_in))).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    else:
        expiry = '0001-01-01T00:00:00Z'  # never expires (pCloud)
    token = {'access_token': access_token, 'token_type': 'Bearer', 'expiry': expiry}
    if refresh_token:
        token['refresh_token'] = refresh_token
    return json.dumps(token, separators=(',', ':'), sort_keys=True)
